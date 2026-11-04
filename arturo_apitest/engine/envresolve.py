"""Environment-variable resolution for Postman `{{var}}` placeholders.

Two sources, merged in priority order (later wins):
  1. A Postman *environment export* JSON  (File > Export in Postman).
  2. A manual override file (flat JSON or YAML)  — set any value by hand.

The engine never reads credentials out of the collection itself. Auth
(`account-id` / `api-key`) is injected per-identity by the client, so the
resolver deliberately does NOT need those two to render a template; it only
needs non-secret vars like `eve_base_url` and any chained `request_id`s.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_VAR_RE = re.compile(r"\{\{\s*([A-Za-z0-9_\-\.]+)\s*\}\}")


class EnvResolver:
    """Resolves `{{var}}` placeholders from merged env sources."""

    def __init__(self, values: dict[str, str] | None = None) -> None:
        self.values: dict[str, str] = dict(values or {})
        # vars referenced by templates but absent from every source
        self.unresolved: set[str] = set()

    # ---- loaders -----------------------------------------------------------
    @classmethod
    def from_sources(
        cls,
        postman_env: str | Path | None = None,
        overrides: str | Path | None = None,
        extra: dict[str, str] | None = None,
    ) -> "EnvResolver":
        values: dict[str, str] = {}
        if postman_env:
            values.update(_load_postman_env(Path(postman_env)))
        if overrides:
            values.update(_load_flat(Path(overrides)))
        if extra:
            values.update({k: str(v) for k, v in extra.items()})
        return cls(values)

    # ---- resolution --------------------------------------------------------
    def resolve(self, text: str) -> str:
        """Substitute every `{{var}}` we know; leave unknowns in place and log them."""
        if not text:
            return text

        def _sub(m: re.Match[str]) -> str:
            name = m.group(1)
            if name in self.values:
                return self.values[name]
            self.unresolved.add(name)
            return m.group(0)  # leave {{name}} so it's visible downstream

        return _VAR_RE.sub(_sub, text)

    def referenced_vars(self, text: str) -> set[str]:
        return {m.group(1) for m in _VAR_RE.finditer(text or "")}

    def set(self, key: str, value: str) -> None:
        """Set a var at runtime (used to feed chained request_ids back in)."""
        self.values[key] = value
        self.unresolved.discard(key)


def _load_postman_env(path: Path) -> dict[str, str]:
    """Parse a Postman environment export: {"values":[{key,value,enabled}]}."""
    data = json.loads(path.read_text())
    out: dict[str, str] = {}
    for entry in data.get("values", []):
        if entry.get("enabled", True) is False:
            continue
        key = entry.get("key")
        if key:
            out[key] = entry.get("value", "")
    return out


def _load_flat(path: Path) -> dict[str, str]:
    """Load a flat override file. JSON always; YAML if PyYAML is present."""
    raw = path.read_text()
    if path.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
        except ImportError as e:  # pragma: no cover
            raise RuntimeError(
                f"{path} is YAML but PyYAML isn't installed (pip install pyyaml)"
            ) from e
        data = yaml.safe_load(raw) or {}
    else:
        data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a flat object of key->value")
    return {k: str(v) for k, v in data.items()}
