"""Broken Authentication suite (API2:2023), content-differential confirmed.

Two checks, each wrapped in the stability gate and confirmed only by a content
match against an authenticated baseline — never by a status code alone:

  * no-auth access   — the same request with NO credentials returns 2xx AND the
    exact content the authenticated identity received. Proof the endpoint does
    not actually enforce auth (an empty/generic 200 is not a finding).
  * credential confusion — identity A's account-id paired with identity B's
    api-key is accepted and returns A's content. Proof the api-key is not bound
    to the account it is sent with.

Both are read-only probes against endpoints the identity can already reach; we
never fabricate state. Needs identity A; credential-confusion also needs B.
"""
from __future__ import annotations

from dataclasses import replace

from ..engine.client import Client
from ..engine.collection import RequestTemplate
from ..engine.config import Identity, Settings
from ..engine.oracle import Finding, Severity, same_content, stability_gate

OWASP_NOAUTH = "API2:2023 Broken Authentication (no credentials accepted)"
OWASP_CONF = "API2:2023 Broken Authentication (api-key not bound to account)"


def run(
    templates: list[RequestTemplate],
    client: Client,
    settings: Settings,
    id_a: Identity,
    id_b: Identity | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    for t in templates:
        if t.mode not in {"sync", "async"} or not t.body_raw:
            continue  # need a request that returns real content to compare

        baseline = client.execute_task(t, id_a)
        if not (200 <= baseline.status < 300) or baseline.json is None:
            continue  # no trustworthy authenticated baseline -> skip

        # --- no-auth access --------------------------------------------------
        def probe_noauth() -> bool:
            r = client.execute_task(t, None)
            return 200 <= r.status < 300 and same_content(baseline, r)

        passed, hits = stability_gate(
            probe_noauth, settings.stability_runs, settings.stability_required)
        if passed:
            findings.append(Finding(
                suite="broken_auth",
                owasp=OWASP_NOAUTH,
                endpoint=t.uid,
                title=f"{t.service or t.name}: returns authenticated content with no credentials",
                severity=Severity.CRITICAL,
                confirmed_by="differential",
                reproductions=hits,
                evidence={"baseline_status": baseline.status,
                          "note": "unauthenticated request returned the same body as identity A"},
            ))

        # --- credential confusion (A account-id + B api-key) -----------------
        if id_b and id_b.api_key and not id_b.api_key.startswith("REPLACE"):
            mixed = replace(id_a, key="mixed", label=f"{id_a.label}-id+{id_b.label}-key",
                            api_key=id_b.api_key)

            def probe_conf() -> bool:
                r = client.execute_task(t, mixed)
                return 200 <= r.status < 300 and same_content(baseline, r)

            passed2, hits2 = stability_gate(
                probe_conf, settings.stability_runs, settings.stability_required)
            if passed2:
                findings.append(Finding(
                    suite="broken_auth",
                    owasp=OWASP_CONF,
                    endpoint=t.uid,
                    title=f"{t.service or t.name}: accepts {id_a.label}'s account-id with {id_b.label}'s api-key",
                    severity=Severity.HIGH,
                    confirmed_by="differential",
                    reproductions=hits2,
                    evidence={"note": "api-key is not validated against the account-id it is paired with"},
                ))
    return findings
