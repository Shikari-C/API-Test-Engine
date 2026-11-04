"""Injection / SSRF suite (API7-ish + classic injection), OOB-confirmed only.

For each injectable field (and each document-url field for SSRF), embed a
unique Collaborator token, fire the request, and flag ONLY if the token later
shows a real callback. No error-string matching, no status-code guessing ->
essentially zero false positives. If no OOB domain is configured, the suite
no-ops (it refuses to guess).
"""
from __future__ import annotations

from ..engine.client import Client
from ..engine.collection import RequestTemplate
from ..engine.config import Identity, Settings
from ..engine.mutate import set_at, dumps
from ..engine.oracle import Finding, Severity, OOBProbe, oob_confirmed
from ..engine import payloads

OWASP_SSRF = "API7:2023 SSRF (document fetch)"
OWASP_INJ = "Injection (OOB-confirmed)"


def run(
    templates: list[RequestTemplate],
    client: Client,
    settings: Settings,
    identity: Identity,
    probe: OOBProbe | None,
) -> list[Finding]:
    findings: list[Finding] = []
    if probe is None or not settings.oob_domain:
        return findings  # no OOB channel -> we don't infer, so we don't run

    pending: list[tuple[str, RequestTemplate, str, tuple]] = []  # (token, tmpl, kind, path)

    for t in templates:
        if not t.body_json:
            continue
        # SSRF via document URL sinks
        for path in t.document_url_paths:
            for pl in payloads.ssrf_payloads(_tok(probe, "ssrf", t, pending, path)):
                _fire(client, t, identity, path, pl)
        # injection via scalar fields
        for path in t.injectable_paths:
            for pl in payloads.injection_payloads(_tok(probe, "inj", t, pending, path)):
                _fire(client, t, identity, path, pl)

    # Give callbacks time to arrive, then confirm.
    for token, t, kind, path in pending:
        if oob_confirmed(probe, token):
            findings.append(Finding(
                suite="injection",
                owasp=OWASP_SSRF if kind == "ssrf" else OWASP_INJ,
                endpoint=t.uid,
                title=f"OOB callback from field {'/'.join(path)} ({kind})",
                severity=Severity.HIGH if kind == "ssrf" else Severity.CRITICAL,
                confirmed_by="oob",
                evidence={"token": token, "field": "/".join(path)},
            ))
    return findings


def _tok(probe, kind, t, pending, path):
    token = probe.token(f"{kind}-{abs(hash(t.uid+str(path)))%100000}")
    pending.append((token, t, kind, path))
    return token


def _fire(client, t, identity, path, payload):
    try:
        mutated = dumps(set_at(t.body_json, path, payload))
    except Exception:
        return
    client.send(t, identity, body_override=mutated)
