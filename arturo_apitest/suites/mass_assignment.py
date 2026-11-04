"""Mass Assignment / BOPLA suite (API3:2023), reflection-confirmed.

For each endpoint with a JSON body, inject privileged properties the client
should not control (role, is_admin, verified, balance, verification_status...)
using distinctive sentinel values. A finding is raised ONLY when:

  * the server accepts the request (2xx), AND
  * the sentinel value is echoed back in the response, AND
  * that sentinel was NOT present in the clean baseline response.

The echo is the proof the extra property was bound into the object. A property
that is silently ignored (not reflected) is not reported. Each confirmed hit is
re-run through the stability gate.

Read/write note: these requests submit the SAME task the identity already
submits, with extra fields added — they do not create unrelated state.
"""
from __future__ import annotations

from ..engine.client import Client
from ..engine.collection import RequestTemplate
from ..engine.config import Identity, Settings
from ..engine.mutate import dumps
from ..engine.oracle import Finding, Severity, reflects_value, stability_gate
from ..engine import payloads

OWASP = "API3:2023 BOPLA / Mass Assignment"


def _inject_props(body_json: dict, prop: str, value) -> str:
    """Add the privileged property at top level and inside a 'data' object if present."""
    import copy
    mutated = copy.deepcopy(body_json)
    mutated[prop] = value
    if isinstance(mutated.get("data"), dict):
        mutated["data"][prop] = value
    return dumps(mutated)


def run(
    templates: list[RequestTemplate],
    client: Client,
    settings: Settings,
    identity: Identity,
) -> list[Finding]:
    findings: list[Finding] = []

    for t in templates:
        if not t.body_json or t.mode not in {"sync", "async"}:
            continue

        baseline = client.execute_task(t, identity)
        if not (200 <= baseline.status < 300) or baseline.json is None:
            continue

        for prop, value in payloads.MASS_ASSIGN.items():
            needle = str(value)
            if reflects_value(baseline, needle):
                continue  # sentinel already present naturally -> not attributable

            body = _inject_props(t.body_json, prop, value)

            def probe() -> bool:
                r = client.execute_task(t, identity, body_override=body)
                return (200 <= r.status < 300
                        and reflects_value(r, needle)
                        and not reflects_value(baseline, needle))

            if not probe():
                continue  # cheap pre-check before spending the stability budget
            passed, hits = stability_gate(
                probe, settings.stability_runs, settings.stability_required)
            if passed:
                findings.append(Finding(
                    suite="mass_assignment",
                    owasp=OWASP,
                    endpoint=t.uid,
                    title=f"{t.service or t.name}: client-supplied '{prop}' was bound and reflected",
                    severity=Severity.HIGH,
                    confirmed_by="stability",
                    reproductions=hits,
                    evidence={"property": prop, "sentinel_value": value,
                              "note": "server accepted and echoed a property the client should not control"},
                ))
    return findings
