"""HTTP client: per-identity auth, optional Burp upstream proxy, task polling.

Design points that matter for the oracle:
  * Auth is injected here, per Identity, overriding whatever account-id/api-key
    the template carried. The collection's own (leaked) creds are never used.
  * Every request can be mirrored through Burp by flipping one proxy flag —
    Collaborator, logging and manual inspection then work with zero engine
    changes. TLS verify is off while proxying (Burp presents its own CA).
  * send() returns a normalised Response the oracle can diff deterministically.
  * async tasks: POST returns {"request_id": ...}; poll GET /v3/tasks?request_id=
    until status == completed (or timeout). Sync tasks return the result inline.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

import httpx

from .collection import RequestTemplate, HeaderSpec
from .config import Identity, Settings
from .envresolve import EnvResolver


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    text: str
    elapsed_ms: float
    json: Any = None
    error: str | None = None             # transport-level error, if any

    @property
    def ok_transport(self) -> bool:
        return self.error is None


# Realistic User-Agent pool. The engine rotates through these per request so
# traffic does not go out as python-httpx / curl. Add/trim freely.
USER_AGENTS = [
    # Chrome (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Firefox (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Safari (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    # Chrome (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Edge (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # Firefox (Linux)
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Postman
    "PostmanRuntime/7.37.3",
    # Chrome (Android)
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    # Safari (iPhone)
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]


def _apply_identity(headers: list[HeaderSpec], identity: Identity | None) -> dict[str, str]:
    """Build the final header dict: enabled template headers, with auth overridden."""
    out: dict[str, str] = {}
    for h in headers:
        if h.disabled:
            continue
        if h.key.lower() in {"account-id", "api-key"}:
            continue  # drop template auth; we inject our own below
        out[h.key] = h.value
    if identity:
        out.update(identity.auth_headers())
    out.setdefault("Content-Type", "application/json")
    return out


class Client:
    def __init__(self, settings: Settings, resolver: EnvResolver) -> None:
        self.s = settings
        self.r = resolver
        proxy = settings.proxy_url if settings.proxy_enabled else None
        verify = settings.proxy_verify_tls if settings.proxy_enabled else True
        # httpx: `proxy=` routes all traffic through Burp when enabled.
        self._client = httpx.Client(
            timeout=settings.request_timeout_s,
            proxy=proxy,
            verify=verify,
            follow_redirects=False,  # redirects matter for some checks; don't hide them
        )
        self._ua_i = 0

    def _next_ua(self) -> str:
        """Round-robin a realistic User-Agent so no two consecutive requests
        share one and nothing goes out as python-httpx/curl."""
        ua = USER_AGENTS[self._ua_i % len(USER_AGENTS)]
        self._ua_i += 1
        return ua

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ---- low-level single send --------------------------------------------
    def send(
        self,
        tmpl: RequestTemplate,
        identity: Identity | None,
        *,
        body_override: str | None = None,
        url_override: str | None = None,
        extra_headers: dict[str, str] | None = None,
        method_override: str | None = None,
    ) -> Response:
        url = self.r.resolve(url_override if url_override is not None else tmpl.raw_url)
        headers = _apply_identity(tmpl.headers, identity)
        if extra_headers:
            headers.update(extra_headers)
        # rotate a realistic UA unless the template or caller already set one
        if not any(k.lower() == "user-agent" for k in headers):
            headers["User-Agent"] = self._next_ua()

        body = body_override if body_override is not None else tmpl.body_raw
        body = self.r.resolve(body) if body else None

        if self.s.per_request_delay_ms:
            time.sleep(self.s.per_request_delay_ms / 1000.0)

        t0 = time.perf_counter()
        try:
            resp = self._client.request(
                method_override or tmpl.method, url,
                headers=headers,
                content=body.encode() if body else None,
            )
        except httpx.HTTPError as e:
            return Response(status=0, headers={}, text="", elapsed_ms=0.0, error=str(e))
        elapsed = (time.perf_counter() - t0) * 1000.0

        parsed: Any = None
        try:
            parsed = resp.json()
        except Exception:
            parsed = None
        return Response(
            status=resp.status_code,
            headers=dict(resp.headers),
            text=resp.text,
            elapsed_ms=elapsed,
            json=parsed,
        )

    # ---- task-aware send (handles sync vs async+poll) ---------------------
    def execute_task(
        self,
        tmpl: RequestTemplate,
        identity: Identity | None,
        *,
        body_override: str | None = None,
    ) -> Response:
        """Send and, for async tasks, poll until the task completes.

        Returns the *result* response (the completed task document for async,
        or the inline response for sync). The poll uses the SAME identity.
        """
        resp = self.send(tmpl, identity, body_override=body_override)
        if tmpl.mode != "async" or not resp.ok_transport:
            return resp
        request_id = None
        if isinstance(resp.json, dict):
            request_id = resp.json.get("request_id")
        if not request_id:
            return resp  # nothing to poll; hand back what we got
        return self._poll(request_id, identity)

    def _poll(self, request_id: str, identity: Identity | None) -> Response:
        base = self.r.resolve("{{base_url}}") if "{{" not in self.s.base_url else self.s.base_url
        base = base or self.s.base_url
        url = f"{base}/v3/tasks?request_id={request_id}"
        headers = {"Content-Type": "application/json", "User-Agent": self._next_ua()}
        if identity:
            headers.update(identity.auth_headers())
        deadline = time.time() + self.s.poll_max_s
        last: Response | None = None
        while time.time() < deadline:
            t0 = time.perf_counter()
            headers["User-Agent"] = self._next_ua()  # rotate on every poll too
            try:
                resp = self._client.get(url, headers=headers)
            except httpx.HTTPError as e:
                return Response(status=0, headers={}, text="", elapsed_ms=0.0, error=str(e))
            elapsed = (time.perf_counter() - t0) * 1000.0
            parsed = None
            try:
                parsed = resp.json()
            except Exception:
                parsed = None
            last = Response(resp.status_code, dict(resp.headers), resp.text, elapsed, parsed)
            status = _task_status(parsed)
            if status in {"completed", "failed", "error"}:
                return last
            time.sleep(self.s.poll_interval_s)
        return last or Response(0, {}, "", 0.0, error="poll timeout")


def _task_status(parsed: Any) -> str | None:
    """Pull status from a task document (object or single-element list)."""
    if isinstance(parsed, list) and parsed:
        parsed = parsed[0]
    if isinstance(parsed, dict):
        return parsed.get("status")
    return None
