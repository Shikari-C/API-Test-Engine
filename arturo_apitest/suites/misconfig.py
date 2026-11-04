"""Security Misconfiguration suite (API8:2023), deterministic + gated.

Checks that confirm themselves from the response alone (no inference):

  * CORS reflection — send a cross-origin `Origin`; flag only if the server
    reflects that exact origin into Access-Control-Allow-Origin (or returns
    `*`) together with Access-Control-Allow-Credentials: true. That pairing is
    an exploitable misconfiguration, not a guess.
  * TRACE / XST — if TRACE is enabled and echoes a request header back in the
    body, cross-site tracing is possible. Confirmed by seeing our own marker
    reflected.

Each probe is run under the stability gate so a one-off fluke is discarded.
One probe per distinct URL, read-only, no body mutation.
"""
from __future__ import annotations

from ..engine.client import Client
from ..engine.collection import RequestTemplate
from ..engine.config import Identity, Settings
from ..engine.oracle import Finding, Severity, stability_gate
from ..engine import payloads

OWASP_CORS = "API8:2023 Security Misconfiguration (CORS)"
OWASP_XST = "API8:2023 Security Misconfiguration (TRACE/XST enabled)"

_XST_MARKER = "apisec-xst-marker-7c1f"


def run(
    templates: list[RequestTemplate],
    client: Client,
    settings: Settings,
    identity: Identity,
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    origin = payloads.CORS_PROBE_ORIGIN

    for t in templates:
        if t.raw_url in seen:
            continue
        seen.add(t.raw_url)

        # --- CORS reflection -------------------------------------------------
        def cors_result():
            r = client.send(t, identity, extra_headers={"Origin": origin})
            acao = (r.headers.get("access-control-allow-origin") or "").strip()
            acac = (r.headers.get("access-control-allow-credentials") or "").strip().lower()
            return acao, acac

        acao, acac = cors_result()
        reflected = (acao == origin)
        wildcard_creds = (acao == "*" and acac == "true")
        if reflected or wildcard_creds:
            passed, hits = stability_gate(
                lambda: (lambda a, c: a == origin or (a == "*" and c == "true"))(*cors_result()),
                settings.stability_runs, settings.stability_required)
            if passed:
                creds = (acac == "true")
                findings.append(Finding(
                    suite="misconfig",
                    owasp=OWASP_CORS,
                    endpoint=t.uid,
                    title=f"{t.name}: CORS reflects arbitrary origin"
                          + (" with credentials" if creds else ""),
                    severity=Severity.HIGH if creds else Severity.MEDIUM,
                    confirmed_by="stability",
                    reproductions=hits,
                    evidence={"sent_origin": origin,
                              "access-control-allow-origin": acao,
                              "access-control-allow-credentials": acac or "(absent)"},
                ))

        # --- TRACE / XST -----------------------------------------------------
        def xst_ok() -> bool:
            r = client.send(t, identity, method_override="TRACE",
                            extra_headers={"X-Apisec-Xst": _XST_MARKER})
            return r.status == 200 and _XST_MARKER in (r.text or "")

        if xst_ok():
            passed, hits = stability_gate(
                xst_ok, settings.stability_runs, settings.stability_required)
            if passed:
                findings.append(Finding(
                    suite="misconfig",
                    owasp=OWASP_XST,
                    endpoint=t.uid,
                    title=f"{t.name}: TRACE enabled and echoes request headers (XST)",
                    severity=Severity.MEDIUM,
                    confirmed_by="stability",
                    reproductions=hits,
                    evidence={"method": "TRACE", "reflected_marker": _XST_MARKER},
                ))
    return findings
