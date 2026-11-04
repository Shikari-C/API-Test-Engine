"""The oracle: decides when something is a REAL finding vs expected behaviour.

Nothing is reported on a single response or a status-code heuristic. Three
independent confirmation strategies, each near-zero false positive:

  1. differential_authz  — three-state A/B check. Flag ONLY when identity B
     receives identity A's resource content. Returns ALLOW/DENY/LEAK.
  2. oob_confirmed        — blind classes (SSRF/injection) flagged ONLY on a
     real out-of-band callback hit, never by inference.
  3. stability_gate       — wraps any candidate probe, requires it to reproduce
     N times before it counts. Flaky-once is discarded.

A Finding is only emitted when one of these says so.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from .client import Response


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    suite: str
    owasp: str                 # e.g. "API1:2023 BOLA"
    endpoint: str              # template uid
    title: str
    severity: Severity
    confirmed_by: str          # "differential" | "oob" | "stability"
    evidence: dict[str, Any] = field(default_factory=dict)
    reproductions: int = 0

    def key(self) -> str:
        return f"{self.suite}|{self.owasp}|{self.endpoint}|{self.title}"


# --------------------------------------------------------------------------- #
# 1. Authz differential
# --------------------------------------------------------------------------- #
class AuthzVerdict(str, Enum):
    ALLOW = "allow"      # B denied A's resource — correct
    DENY = "deny"        # B denied — correct (alias)
    LEAK = "leak"        # B received A's content — BOLA/BFLA
    INCONCLUSIVE = "inconclusive"


def _fingerprint(resp: Response) -> str:
    """Content fingerprint that ignores volatile fields (timestamps, request_id)."""
    payload = resp.json if resp.json is not None else resp.text
    norm = _strip_volatile(payload)
    blob = _canonical(norm)
    return hashlib.sha256(blob.encode()).hexdigest()


_VOLATILE_KEYS = {"request_id", "created_at", "completed_at", "x-request-id", "date"}


def _strip_volatile(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _strip_volatile(v) for k, v in obj.items() if k not in _VOLATILE_KEYS}
    if isinstance(obj, list):
        return [_strip_volatile(v) for v in obj]
    return obj


def _canonical(obj: Any) -> str:
    import json
    try:
        return json.dumps(obj, sort_keys=True, ensure_ascii=False)
    except TypeError:
        return str(obj)


def differential_authz(
    a_on_own: Response,     # A requesting A's resource  (baseline, should succeed)
    b_on_own: Response,     # B requesting B's resource  (sanity, should succeed)
    b_on_a: Response,       # B requesting A's resource  (the probe)
) -> tuple[AuthzVerdict, dict[str, Any]]:
    """Three-state BOLA/BFLA oracle.

    LEAK iff:
      - A's own call succeeded (we have a real baseline), AND
      - B's cross-tenant call returned 2xx, AND
      - B's cross-tenant content fingerprint == A's baseline fingerprint.
    Matching content is the proof: a 200 alone is not enough (could be an empty
    or generic 'not found' body), and a 403 is a clean pass.
    """
    ev: dict[str, Any] = {
        "a_status": a_on_own.status,
        "b_status": b_on_own.status,
        "b_on_a_status": b_on_a.status,
    }
    if not (200 <= a_on_own.status < 300):
        return AuthzVerdict.INCONCLUSIVE, {**ev, "why": "no valid A baseline"}
    if b_on_a.status in (401, 403):
        return AuthzVerdict.DENY, {**ev, "why": "cross-tenant denied (good)"}
    if not (200 <= b_on_a.status < 300):
        return AuthzVerdict.DENY, {**ev, "why": f"cross-tenant non-2xx ({b_on_a.status})"}

    a_fp = _fingerprint(a_on_own)
    probe_fp = _fingerprint(b_on_a)
    ev["content_match"] = (a_fp == probe_fp)
    if a_fp == probe_fp:
        return AuthzVerdict.LEAK, {**ev, "why": "B received A's exact resource content"}
    return AuthzVerdict.DENY, {**ev, "why": "2xx but content differs from A's resource"}


# --------------------------------------------------------------------------- #
# 2. Out-of-band confirmation
# --------------------------------------------------------------------------- #
class OOBProbe:
    """Interface the runner feeds in. Implement against Collaborator/interactsh.

    `token()` returns a unique subdomain/path to embed in a payload;
    `was_hit(token)` returns True only if the collaborator server actually
    recorded a DNS/HTTP interaction for that token.
    """

    def __init__(self, domain: str) -> None:
        self.domain = domain

    def token(self, label: str) -> str:
        import uuid
        return f"{label}-{uuid.uuid4().hex[:12]}.{self.domain}"

    def was_hit(self, token: str) -> bool:  # pragma: no cover - needs live server
        raise NotImplementedError(
            "Wire was_hit() to the Collaborator/interactsh polling API. "
            "Return True only on a real recorded interaction."
        )


class FileOOBProbe(OOBProbe):
    """Concrete OOB probe that confirms a callback from a local hits file.

    Point it at a file your collaborator client appends observed interactions
    to (e.g. `interactsh-client -o hits.txt`, or Burp Collaborator interactions
    exported/tailed to a file). A token is confirmed when its unique label
    appears anywhere in that file. Confirmation is still a REAL recorded
    interaction — we only read what the collaborator server actually saw.
    """

    def __init__(self, domain: str, hits_file: str) -> None:
        super().__init__(domain)
        self.hits_file = hits_file

    def was_hit(self, token: str) -> bool:
        from pathlib import Path
        p = Path(self.hits_file)
        if not p.exists():
            return False
        label = token.split(".", 1)[0]  # the unique "<kind>-<hex>" part
        try:
            data = p.read_text(errors="ignore")
        except OSError:
            return False
        return token in data or (bool(label) and label in data)


def oob_confirmed(probe: "OOBProbe | None", token: str) -> bool:
    if probe is None:
        return False
    try:
        return probe.was_hit(token)
    except NotImplementedError:
        return False


# --------------------------------------------------------------------------- #
# content-match and reflection confirmers (used by the advanced suites)
# --------------------------------------------------------------------------- #
def content_fingerprint(resp: Response) -> str:
    """Volatile-stripped content fingerprint, exposed for cross-check suites."""
    return _fingerprint(resp)


def same_content(a: Response, b: Response) -> bool:
    """True iff two responses carry the same (volatile-stripped) body."""
    return _fingerprint(a) == _fingerprint(b)


def reflects_value(resp: Response, needle: str) -> bool:
    """True iff an injected sentinel is echoed back in the response body.

    Used by mass-assignment (API3/BOPLA): a privileged property the server
    accepted and returned is proof it was bound, not a guess.
    """
    if not needle:
        return False
    if resp.text and needle in resp.text:
        return True
    try:
        return needle in _canonical(resp.json)
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# 3. Stability gate
# --------------------------------------------------------------------------- #
def stability_gate(
    candidate: Callable[[], bool],
    runs: int,
    required: int,
) -> tuple[bool, int]:
    """Run `candidate` up to `runs` times; True iff it holds >= `required` times.

    Short-circuits: stops early once it can no longer reach `required`.
    Returns (passed, reproductions).
    """
    hits = 0
    for i in range(runs):
        if candidate():
            hits += 1
        remaining = runs - (i + 1)
        if hits >= required:
            return True, hits
        if hits + remaining < required:
            break
    return hits >= required, hits
