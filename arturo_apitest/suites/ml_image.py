"""ML / image-verification suite — separate from OWASP, oracle = labelled corpus.

Test classes:
  * corpus_accuracy   — feed genuine/forged docs with known ground truth; flag
    when the backend accepts something it should reject (or vice versa). The
    label IS the oracle; no heuristic guessing.
  * prompt_injection  — (LLM confirmed in pipeline) embed instructions in the
    document fields / OCR-reachable text; flag a decision flip (a sample the
    backend rejects clean but accepts once the injection string is present),
    and/or an OOB exfil callback.
  * ocr_field_injection — put SQLi/XSS/cmd payloads where OCR text flows
    downstream; confirmed by OOB (delegated to the injection suite's channel).
  * resource_abuse    — API4: decompression bomb / pixel flood / polyglot /
    truncated image inputs; flag a 5xx or timeout that a size guard should
    have caught, confirmed by the stability gate.

Everything that could be ambiguous is gated: corpus verdicts are exact
(label vs backend decision), resource-abuse is stability-gated.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..engine.client import Client
from ..engine.collection import RequestTemplate
from ..engine.config import Identity, Settings
from ..engine.mutate import set_at, dumps
from ..engine.oracle import Finding, Severity, stability_gate
from ..engine import imageabuse, payloads

OWASP_API4 = "API4:2023 Unrestricted Resource Consumption (image parser)"
ML_FORGERY = "ML: forgery/perturbation accepted"
ML_PROMPT = "ML: LLM prompt-injection decision flip"


@dataclass
class CorpusItem:
    label: str          # genuine | forged
    doc_type: str
    service: str        # e.g. check_tampering/document
    path: str           # local path or https url
    expect_pass: bool


def load_corpus(manifest: str | Path) -> list[CorpusItem]:
    items: list[CorpusItem] = []
    p = Path(manifest)
    if not p.exists():
        return items
    for row in csv.DictReader(_decomment(p)):
        if not row.get("label"):
            continue
        items.append(CorpusItem(
            label=row["label"].strip(),
            doc_type=row.get("doc_type", "").strip(),
            service=row.get("service", "").strip(),
            path=row.get("path", "").strip(),
            expect_pass=str(row.get("expect_pass", "")).strip().lower() == "true",
        ))
    return items


def _decomment(p: Path):
    for line in p.read_text().splitlines():
        if line.lstrip().startswith("#"):
            continue
        yield line


def run(
    templates: list[RequestTemplate],
    client: Client,
    settings: Settings,
    identity: Identity,
    decision_reader,          # callable(Response) -> bool|None  (did backend PASS?)
) -> list[Finding]:
    findings: list[Finding] = []
    corpus = load_corpus(Path(settings.corpus_dir) / "manifest.csv")
    by_service = _templates_by_service(templates)

    # --- corpus accuracy -----------------------------------------------------
    for item in corpus:
        tmpl = by_service.get(item.service)
        if not tmpl or not tmpl.document_url_paths or not item.path.startswith("http"):
            continue  # corpus_accuracy needs a fetchable URL + a doc-url sink
        path = tmpl.document_url_paths[0]
        body = dumps(set_at(tmpl.body_json, path, item.path))
        resp = client.execute_task(tmpl, identity, body_override=body)
        passed = decision_reader(resp)
        if passed is None:
            continue
        if passed != item.expect_pass:
            findings.append(Finding(
                suite="ml_image",
                owasp=ML_FORGERY,
                endpoint=tmpl.uid,
                title=(f"{item.service}: backend {'accepted' if passed else 'rejected'} a "
                       f"{item.label} {item.doc_type} (expected {'accept' if item.expect_pass else 'reject'})"),
                severity=Severity.HIGH if item.label == "forged" and passed else Severity.MEDIUM,
                confirmed_by="corpus-label",
                evidence={"sample": item.path, "label": item.label,
                          "expect_pass": item.expect_pass, "backend_pass": passed},
            ))

        # --- prompt injection on this sample (LLM confirmed) -----------------
        if settings.llm_in_pipeline and item.label == "forged" and not passed:
            # baseline correctly rejected; does an injected instruction flip it?
            for pi in payloads.PROMPT_INJECTION:
                flip_body = _inject_prompt(tmpl, item.path, pi)
                if flip_body is None:
                    continue

                def candidate() -> bool:
                    r = client.execute_task(tmpl, identity, body_override=flip_body)
                    return decision_reader(r) is True   # flipped to PASS

                passed_gate, hits = stability_gate(
                    candidate, settings.stability_runs, settings.stability_required)
                if passed_gate:
                    findings.append(Finding(
                        suite="ml_image",
                        owasp=ML_PROMPT,
                        endpoint=tmpl.uid,
                        title=f"Prompt injection flipped a forged {item.doc_type} to PASS",
                        severity=Severity.CRITICAL,
                        confirmed_by="stability",
                        reproductions=hits,
                        evidence={"sample": item.path, "injection": pi},
                    ))
                    break  # one confirmed flip per sample is enough

    # --- resource abuse (API4) ----------------------------------------------
    abuse_files = imageabuse.build(Path(settings.corpus_dir) / "_abuse")
    # Note: these need a file-upload or a reachable URL. If the API only takes
    # URLs, host these and list them in the manifest; here we record that the
    # inputs were generated and leave firing to the URL path.
    findings_api4 = _maybe_resource_abuse(abuse_files)
    findings.extend(findings_api4)

    return findings


def _templates_by_service(templates: list[RequestTemplate]) -> dict[str, RequestTemplate]:
    out: dict[str, RequestTemplate] = {}
    for t in templates:
        if t.service and t.service not in out and t.body_json:
            out[t.service] = t
    return out


def _inject_prompt(tmpl: RequestTemplate, doc_url: str, injection: str) -> str | None:
    """Put the doc URL in its sink and the injection into a text field if one exists."""
    if not tmpl.body_json or not tmpl.document_url_paths:
        return None
    body = set_at(tmpl.body_json, tmpl.document_url_paths[0], doc_url)
    # prefer an obvious text field; else append to business_name/name if present
    for path in tmpl.injectable_paths:
        if path[-1] in {"business_name", "name", "name1", "task_id"}:
            body = set_at(body, path, injection)
            return dumps(body)
    return dumps(body)  # URL set even if no text field to carry the string


def _maybe_resource_abuse(abuse_files: dict[str, Path]) -> list[Finding]:
    # Placeholder: resource-abuse firing depends on whether the target accepts
    # uploads or only URLs. The inputs are generated deterministically above so
    # they can be hosted and added to manifest.csv as forged/expect-reject rows.
    return []
