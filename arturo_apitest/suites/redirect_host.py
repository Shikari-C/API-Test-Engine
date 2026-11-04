"""Open-redirect and Host-header-injection suite, reflection-confirmed.

Both checks confirm from the response alone, no inference:

  * open redirect — set a redirect-type body field (redirect_url, next,
    return_url, ...) to an attacker host; flag only if the server answers with a
    3xx whose Location actually points at that host. A 200, or a Location that
    stays on the target, is a clean pass.
  * host-header injection — send a spoofed Host / X-Forwarded-Host; flag only if
    that attacker host is reflected back into a Location or an absolute URL in
    the body (the classic password-reset / cache-poisoning primitive).

Each confirmed probe is re-run through the stability gate. Needs identity A.
"""
from __future__ import annotations

from typing import Iterator
from urllib.parse import urlparse

from ..engine.client import Client
from ..engine.collection import RequestTemplate
from ..engine.config import Identity, Settings
from ..engine.mutate import set_at, dumps
from ..engine.oracle import Finding, Severity, stability_gate

OWASP_REDIRECT = "Open Redirect (unvalidated redirect target)"
OWASP_HOSTHDR = "API8:2023 Host header injection (reflected attacker host)"

REDIRECT_HOST = "apisec-redirect.attacker.example"
HOSTHDR_MARKER = "apisec-hosthdr.attacker.example"

REDIRECT_FIELDS = {
    "redirect_url", "redirect", "redir", "url", "next", "return_url",
    "returnurl", "return_to", "returnto", "continue", "dest", "destination",
    "callback", "success_url", "failure_url", "goto",
}


def run(
    templates: list[RequestTemplate],
    client: Client,
    settings: Settings,
    identity: Identity,
) -> list[Finding]:
    findings: list[Finding] = []

    # --- open redirect ------------------------------------------------------
    for t in templates:
        if not t.body_json:
            continue
        for path in _redirect_paths(t.body_json):
            payload = f"https://{REDIRECT_HOST}/x"

            def probe() -> bool:
                body = dumps(set_at(t.body_json, path, payload))
                r = client.send(t, identity, body_override=body)
                return _location_points_to(r.headers.get("location", ""), REDIRECT_HOST)

            if not probe():
                continue
            passed, hits = stability_gate(
                probe, settings.stability_runs, settings.stability_required)
            if passed:
                findings.append(Finding(
                    suite="redirect_host",
                    owasp=OWASP_REDIRECT,
                    endpoint=t.uid,
                    title=f"{t.name}: field '{'/'.join(path)}' allows redirect to an external host",
                    severity=Severity.MEDIUM,
                    confirmed_by="stability",
                    reproductions=hits,
                    evidence={"field": "/".join(path), "payload": payload,
                              "note": "response Location pointed at the attacker host"},
                ))

    # --- host header injection ----------------------------------------------
    seen: set[str] = set()
    for t in templates:
        if t.raw_url in seen:
            continue
        seen.add(t.raw_url)

        def probe_host() -> bool:
            r = client.send(t, identity, extra_headers={
                "Host": HOSTHDR_MARKER,
                "X-Forwarded-Host": HOSTHDR_MARKER,
                "X-Host": HOSTHDR_MARKER,
            })
            loc = r.headers.get("location", "")
            return HOSTHDR_MARKER in loc or HOSTHDR_MARKER in (r.text or "")

        if not probe_host():
            continue
        passed, hits = stability_gate(
            probe_host, settings.stability_runs, settings.stability_required)
        if passed:
            findings.append(Finding(
                suite="redirect_host",
                owasp=OWASP_HOSTHDR,
                endpoint=t.uid,
                title=f"{t.name}: spoofed Host header reflected in the response",
                severity=Severity.MEDIUM,
                confirmed_by="stability",
                reproductions=hits,
                evidence={"sent_host": HOSTHDR_MARKER,
                          "note": "attacker-controlled Host/X-Forwarded-Host echoed into Location or body"},
            ))
    return findings


def _redirect_paths(body: dict, prefix: tuple = ()) -> Iterator[tuple]:
    """Yield paths to string leaves whose key is a redirect-type field."""
    if isinstance(body, dict):
        for k, v in body.items():
            if isinstance(v, str) and k.lower() in REDIRECT_FIELDS:
                yield prefix + (k,)
            else:
                yield from _redirect_paths(v, prefix + (k,))
    elif isinstance(body, list):
        for i, v in enumerate(body):
            yield from _redirect_paths(v, prefix + (str(i),))


def _location_points_to(location: str, host: str) -> bool:
    """True iff a Location header actually redirects to `host` (not just mentions it)."""
    if not location:
        return False
    loc = location.strip()
    # protocol-relative //host/... or scheme://host/...
    if loc.startswith("//"):
        loc = "http:" + loc
    try:
        netloc = urlparse(loc).netloc.lower()
    except ValueError:
        return False
    # strip creds/port
    netloc = netloc.split("@")[-1].split(":")[0]
    return netloc == host.lower()
