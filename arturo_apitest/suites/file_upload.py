"""Unrestricted file / server-side document-parsing suite.

Your document sinks take a URL the backend fetches and processes as an image or
document. This suite hosts hostile markup at such a URL and checks whether the
backend accepts a non-image type AND parses it:

  * svg_xxe / xml_xxe / xhtml_obj — external XML entity resolved -> XXE
  * svg_href / html_img          — remote resource fetched by a renderer -> SSRF-via-file

Confirmation (zero inference): a probe is reported ONLY when the catcher records
a hit on /c/<token>, i.e. the embedded reference fired. That proves the server
fetched our non-image file and parsed it. A plain fetch of the file (/f) is
recorded as supporting evidence but is not, by itself, a finding here.

Each confirmed probe is re-fired under the stability gate. Needs a catcher the
target can reach (see engine/catcher.py); otherwise the suite is skipped.
"""
from __future__ import annotations

import time
import uuid

from ..engine.catcher import Catcher
from ..engine.client import Client
from ..engine.collection import RequestTemplate
from ..engine.config import Identity, Settings
from ..engine.mutate import set_at, dumps
from ..engine.oracle import Finding, Severity, stability_gate
from ..engine import payloads

OWASP_XXE = "API7/API10: XXE via fetched document (server parsed hostile XML)"
OWASP_SSRF_FILE = "API7:2023 SSRF via fetched document (renderer loaded remote ref)"
OWASP_UPLOAD = "Unrestricted file type accepted and processed"


def run(
    templates: list[RequestTemplate],
    client: Client,
    settings: Settings,
    identity: Identity,
    catcher: Catcher,
    settle_s: float = 3.0,
) -> list[Finding]:
    findings: list[Finding] = []
    kinds = payloads.upload_files("CALLBACK")  # just to enumerate names/exts

    for t in templates:
        if not t.body_json or not t.document_url_paths:
            continue
        sink = t.document_url_paths[0]

        for spec_template in kinds:
            name = spec_template["name"]

            def fire() -> str:
                """Send one payload; return its token so we can poll the catcher."""
                token = f"{name}-{uuid.uuid4().hex[:10]}"
                built = _build(name, catcher, token)
                serve_url = catcher.register(token, built["content_type"], built["body"], built["ext"])
                body = dumps(set_at(t.body_json, sink, serve_url))
                client.execute_task(t, identity, body_override=body)
                return token

            # first attempt: fire and wait for the parse callback
            token = fire()
            _wait(lambda: catcher.was_parsed(token), settle_s)
            if not catcher.was_parsed(token):
                continue

            # confirm under the stability gate (fresh token each run)
            def candidate() -> bool:
                tk = fire()
                return _wait(lambda: catcher.was_parsed(tk), settle_s)

            passed, hits = stability_gate(
                candidate, settings.stability_runs, settings.stability_required)
            if passed:
                owasp = OWASP_XXE if "xxe" in name or name == "xhtml_obj" else OWASP_SSRF_FILE
                findings.append(Finding(
                    suite="file_upload",
                    owasp=owasp,
                    endpoint=t.uid,
                    title=f"{t.service or t.name}: fetched+parsed hostile '{name}' document ({OWASP_UPLOAD})",
                    severity=Severity.HIGH,
                    confirmed_by="oob",
                    reproductions=hits,
                    evidence={"field": "/".join(sink), "payload": name,
                              "note": "server fetched a non-image file and resolved its embedded reference"},
                ))
                break  # one confirmed parsing vector per sink is enough
    return findings


def _build(name: str, catcher: Catcher, token: str) -> dict:
    cb = catcher.callback_url(token)
    for spec in payloads.upload_files(cb):
        if spec["name"] == name:
            return spec
    raise KeyError(name)


def _wait(pred, seconds: float) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(0.25)
    return pred()
