"""Body mutation helpers: set/get a value at a tuple path in a parsed body,
and re-serialise. Used by suites to inject payloads into tagged fields.
"""
from __future__ import annotations

import copy
import json
from typing import Any


def get_at(body: dict[str, Any], path: tuple[str, ...]) -> Any:
    cur: Any = body
    for seg in path:
        if isinstance(cur, list):
            cur = cur[int(seg)]
        else:
            cur = cur[seg]
    return cur


def set_at(body: dict[str, Any], path: tuple[str, ...], value: Any) -> dict[str, Any]:
    """Return a deep copy of body with path set to value."""
    out = copy.deepcopy(body)
    cur: Any = out
    for seg in path[:-1]:
        cur = cur[int(seg)] if isinstance(cur, list) else cur[seg]
    last = path[-1]
    if isinstance(cur, list):
        cur[int(last)] = value
    else:
        cur[last] = value
    return out


def dumps(body: dict[str, Any]) -> str:
    return json.dumps(body)
