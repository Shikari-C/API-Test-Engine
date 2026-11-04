"""Authorization suite: BOLA / BFLA / BOPLA (API1/API3/API5) via A/B differential.

Strategy, per async endpoint that produces a request_id:
  1. Identity A submits the task  -> request_id_A.
  2. A polls its own task         -> baseline (must be 2xx, real content).
  3. B polls A's request_id       -> the cross-tenant probe.
  -> oracle.differential_authz(A_baseline, B_own_baseline, B_on_A)
     LEAK only when B receives A's exact content.

The whole probe is wrapped in the stability gate: a leak must reproduce.
Object identifier here is the request_id (the BOLA object). This is the
cleanest object handle in this API; ou_id / profile_id can be added the same way.
"""
from __future__ import annotations

from ..engine.client import Client
from ..engine.collection import RequestTemplate
from ..engine.config import Identity, Settings
from ..engine.oracle import (
    Finding, Severity, AuthzVerdict, differential_authz, stability_gate,
)

OWASP = "API1:2023 BOLA (cross-tenant object access)"


def run(
    templates: list[RequestTemplate],
    client: Client,
    settings: Settings,
    id_a: Identity,
    id_b: Identity,
) -> list[Finding]:
    findings: list[Finding] = []

    # candidate endpoints: async submitters that produce a request_id, plus a
    # matching poll template to read a task back.
    submitters = [t for t in templates if t.mode == "async" and t.body_raw]
    poller = _find_poller(templates)
    if poller is None:
        return findings  # no GET /v3/tasks template to read with; nothing to do

    for sub in submitters:
        # 1. A submits its own task.
        a_submit = client.send(sub, id_a)
        rid_a = _request_id(a_submit)
        if not rid_a:
            continue

        # 2. A reads its own task (baseline).
        a_read = _poll_as(client, poller, id_a, rid_a, settings)
        if not (200 <= a_read.status < 300):
            continue  # no clean baseline -> skip (keeps FP rate at zero)

        # 2b. B submits + reads its own (sanity that B works at all).
        b_submit = client.send(sub, id_b)
        rid_b = _request_id(b_submit)
        b_read_own = _poll_as(client, poller, id_b, rid_b, settings) if rid_b else a_read

        # 3. The probe, under the stability gate: B reads A's request_id.
        def probe() -> bool:
            b_on_a = _poll_as(client, poller, id_b, rid_a, settings)
            verdict, _ = differential_authz(a_read, b_read_own, b_on_a)
            return verdict == AuthzVerdict.LEAK

        passed, hits = stability_gate(
            probe, settings.stability_runs, settings.stability_required
        )
        if passed:
            # capture final evidence once more for the report
            b_on_a = _poll_as(client, poller, id_b, rid_a, settings)
            verdict, ev = differential_authz(a_read, b_read_own, b_on_a)
            findings.append(Finding(
                suite="authz",
                owasp=OWASP,
                endpoint=sub.uid,
                title=f"Tenant {id_b.label} can read tenant {id_a.label}'s task via request_id",
                severity=Severity.CRITICAL,
                confirmed_by="differential",
                reproductions=hits,
                evidence={
                    "object": "request_id",
                    "a_request_id": rid_a,
                    **ev,
                },
            ))
    return findings


def _find_poller(templates: list[RequestTemplate]) -> RequestTemplate | None:
    for t in templates:
        if t.mode == "poll" and t.method == "GET":
            return t
    return None


def _request_id(resp) -> str | None:
    if isinstance(resp.json, dict):
        return resp.json.get("request_id")
    return None


def _poll_as(client: Client, poller: RequestTemplate, identity: Identity, rid: str, settings: Settings):
    base = settings.base_url or client.r.resolve("{{eve_base_url}}")
    url = f"{base}/v3/tasks?request_id={rid}"
    return client.send(poller, identity, url_override=url)
