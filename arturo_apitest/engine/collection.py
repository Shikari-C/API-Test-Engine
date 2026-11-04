"""Postman v2.1 collection parser -> flat list of RequestTemplate objects.

Handles the quirks seen in the real target collections:
  * duplicate `account-id` / `api-key` headers (enabled + several disabled);
    we keep enabled ones and let the client override auth per-identity.
  * `//` line comments and trailing commas inside raw JSON bodies.
  * nested item folders (recurses).
  * `{{var}}` placeholders anywhere in url / headers / body (left for the resolver).
  * the sync/async task pattern (path segment 2 == 'sync' | 'async').

Injectable fields are tagged by walking the parsed JSON body so suites know
exactly which leaves to fuzz, and which chained `request_id` vars a GET depends on.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

# data.* leaves worth fuzzing for injection / OOB; extend freely.
INJECTABLE_LEAF_KEYS = {
    "id_number", "business_name", "address", "name", "name1", "name2",
    "last_name", "first_name", "gstin", "pan_number", "aadhaar_number",
    "search_term", "company_name", "firm_name", "rc_number", "email",
    "email_id", "phone_number", "mobile_number", "workflow_name", "ou_id",
    "task_id", "group_id", "document_type", "doc_type", "country_code",
    "reference_id", "callback_url", "redirect_url",
}
# leaves that carry a URL the ML/OCR backend will fetch -> SSRF / image-swap surface
DOCUMENT_URL_KEYS = {
    "document1", "document2", "document", "document_url", "input_file",
    "file1", "itr_url", "bank_statement",
}


@dataclass
class HeaderSpec:
    key: str
    value: str
    disabled: bool = False


@dataclass
class RequestTemplate:
    collection: str
    name: str
    method: str
    raw_url: str                      # may contain {{vars}}
    path: list[str]                   # path segments as authored
    headers: list[HeaderSpec]
    body_raw: str | None              # raw body text (may contain {{vars}}, // comments)
    body_json: dict[str, Any] | None  # parsed body if it was JSON-ish, else None
    # derived:
    mode: str = "unknown"             # 'sync' | 'async' | 'poll' | 'unknown'
    service: str = ""                 # e.g. 'verify_with_source/ind_pan'
    produces_var: str | None = None   # var this request's test-script sets (chaining)
    depends_on_vars: list[str] = field(default_factory=list)
    injectable_paths: list[tuple[str, ...]] = field(default_factory=list)
    document_url_paths: list[tuple[str, ...]] = field(default_factory=list)

    @property
    def uid(self) -> str:
        return f"{self.collection}::{self.name}"

    def enabled_headers(self) -> list[HeaderSpec]:
        return [h for h in self.headers if not h.disabled]

    def hardcoded_auth_headers(self) -> list[HeaderSpec]:
        """account-id / api-key headers with a literal (non-{{var}}) value.

        These are the leaked credentials in the collection; the engine reports
        their presence but never uses them as the test identity.
        """
        out = []
        for h in self.headers:
            if h.key.lower() in {"account-id", "api-key"} and "{{" not in h.value and h.value:
                out.append(h)
        return out


# --------------------------------------------------------------------------- #
# JSON-with-comments tolerance (Postman bodies frequently contain // and ,})
# --------------------------------------------------------------------------- #
_LINE_COMMENT = re.compile(r"//[^\n\r]*")
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def loads_lenient(raw: str) -> Any | None:
    """Best-effort JSON parse tolerating // comments and trailing commas."""
    if not raw or not raw.strip():
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    cleaned = _LINE_COMMENT.sub("", raw)
    cleaned = _TRAILING_COMMA.sub(r"\1", cleaned)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return None


# --------------------------------------------------------------------------- #
# body walking
# --------------------------------------------------------------------------- #
def _walk(obj: Any, prefix: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], Any]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, prefix + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, prefix + (str(i),))
    else:
        yield prefix, obj


def _match_key(path_tuple: tuple[str, ...]) -> str:
    """Nearest non-index segment. For data.document[0] this is 'document', so a
    list of URLs under a document key is still recognised as that key."""
    for seg in reversed(path_tuple):
        if not seg.isdigit():
            return seg
    return ""


def _tag_fields(body_json: dict[str, Any] | None) -> tuple[list[tuple[str, ...]], list[tuple[str, ...]]]:
    injectable: list[tuple[str, ...]] = []
    doc_urls: list[tuple[str, ...]] = []
    if not body_json:
        return injectable, doc_urls
    for path_tuple, value in _walk(body_json):
        key = _match_key(path_tuple)
        if key in DOCUMENT_URL_KEYS and isinstance(value, str) and value.startswith("http"):
            doc_urls.append(path_tuple)
        elif key in INJECTABLE_LEAF_KEYS and isinstance(value, (str, int)):
            injectable.append(path_tuple)
    return injectable, doc_urls


# --------------------------------------------------------------------------- #
# parsing
# --------------------------------------------------------------------------- #
def _extract_produces_var(item: dict[str, Any]) -> str | None:
    """Find pm.globals.set("x", jsondata.request_id) in a test event script."""
    for ev in item.get("event", []) or []:
        if ev.get("listen") != "test":
            continue
        exec_lines = ev.get("script", {}).get("exec", []) or []
        joined = "\n".join(exec_lines)
        m = re.search(r"pm\.globals\.set\(\s*['\"]([^'\"]+)['\"]", joined)
        if m:
            return m.group(1)
    return None


def _classify(path: list[str]) -> tuple[str, str]:
    """Return (mode, service) from the url path segments.

    .../v3/tasks/sync/<service...>     -> ('sync',  'service...')
    .../v3/tasks/async/<service...>    -> ('async', 'service...')
    .../v3/tasks (with ?request_id=..) -> ('poll',  'tasks')
    """
    if "tasks" not in path:
        return "unknown", "/".join(path)
    i = path.index("tasks")
    tail = path[i + 1:]
    if not tail:
        return "poll", "tasks"
    if tail[0] in {"sync", "async"}:
        return tail[0], "/".join(tail[1:])
    return "unknown", "/".join(tail)


def _parse_item(item: dict[str, Any], collection_name: str) -> RequestTemplate | None:
    req = item.get("request")
    if not isinstance(req, dict):
        return None

    method = (req.get("method") or "GET").upper()

    url = req.get("url", {})
    if isinstance(url, str):
        raw_url, path, query = url, [], []
    else:
        raw_url = url.get("raw", "")
        path = list(url.get("path", []) or [])
        query = url.get("query", []) or []

    headers = [
        HeaderSpec(key=h.get("key", ""), value=h.get("value", ""),
                   disabled=bool(h.get("disabled", False)))
        for h in (req.get("header") or [])
    ]

    body = req.get("body") or {}
    body_raw = body.get("raw") if body.get("mode") == "raw" else None
    body_json = loads_lenient(body_raw) if body_raw else None

    mode, service = _classify(path)
    injectable, doc_urls = _tag_fields(body_json if isinstance(body_json, dict) else None)

    # polling GETs depend on a {{request_id}} var in the query string
    depends: list[str] = []
    for q in query:
        val = q.get("value", "")
        depends += re.findall(r"\{\{\s*([A-Za-z0-9_\-\.]+)\s*\}\}", val)

    return RequestTemplate(
        collection=collection_name,
        name=item.get("name", "<unnamed>"),
        method=method,
        raw_url=raw_url,
        path=path,
        headers=headers,
        body_raw=body_raw,
        body_json=body_json if isinstance(body_json, dict) else None,
        mode=mode,
        service=service,
        produces_var=_extract_produces_var(item),
        depends_on_vars=depends,
        injectable_paths=injectable,
        document_url_paths=doc_urls,
    )


def _iter_items(items: list[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    """Recurse into Postman folders (items that contain their own `item` list)."""
    for it in items:
        if "item" in it and isinstance(it["item"], list):
            yield from _iter_items(it["item"])
        else:
            yield it


def parse_collection(path: str | Path) -> list[RequestTemplate]:
    data = json.loads(Path(path).read_text())
    name = data.get("info", {}).get("name", Path(path).stem)
    out: list[RequestTemplate] = []
    for item in _iter_items(data.get("item", []) or []):
        tmpl = _parse_item(item, name)
        if tmpl:
            out.append(tmpl)
    return out


def parse_many(paths: list[str | Path]) -> list[RequestTemplate]:
    out: list[RequestTemplate] = []
    for p in paths:
        out.extend(parse_collection(p))
    return out
