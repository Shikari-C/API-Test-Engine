"""Load settings + identities. Thin, dependency-light, with sane defaults."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _load(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    raw = p.read_text()
    if p.suffix.lower() in {".yaml", ".yml"}:
        import yaml  # type: ignore
        return yaml.safe_load(raw) or {}
    return json.loads(raw)


@dataclass
class Identity:
    key: str                # "A" / "B"
    label: str
    account_id: str
    api_key: str

    def auth_headers(self) -> dict[str, str]:
        return {"account-id": self.account_id, "api-key": self.api_key}


@dataclass
class Settings:
    base_url: str = ""
    postman_env: str | None = None
    overrides: str | None = None
    identities_file: str | None = None
    proxy_enabled: bool = False
    proxy_url: str = "http://127.0.0.1:8080"
    proxy_verify_tls: bool = False
    stability_runs: int = 3
    stability_required: int = 3
    request_timeout_s: int = 30
    poll_interval_s: int = 2
    poll_max_s: int = 120
    oob_domain: str = ""
    oob_hits_file: str = ""
    upload_bind_host: str = "0.0.0.0"
    upload_bind_port: int = 0
    upload_public_base: str = ""
    max_concurrency: int = 4
    per_request_delay_ms: int = 0
    corpus_dir: str = "corpus"
    llm_in_pipeline: bool = True
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> "Settings":
        d = _load(path)
        proxy = d.get("proxy", {}) or {}
        oracle = d.get("oracle", {}) or {}
        oob = d.get("oob", {}) or {}
        tp = d.get("throughput", {}) or {}
        ml = d.get("ml", {}) or {}
        up = d.get("upload", {}) or {}
        return cls(
            base_url=d.get("base_url", ""),
            postman_env=d.get("postman_env"),
            overrides=d.get("overrides"),
            identities_file=d.get("identities_file"),
            proxy_enabled=bool(proxy.get("enabled", False)),
            proxy_url=proxy.get("url", "http://127.0.0.1:8080"),
            proxy_verify_tls=bool(proxy.get("verify_tls", False)),
            stability_runs=int(oracle.get("stability_runs", 3)),
            stability_required=int(oracle.get("stability_required", 3)),
            request_timeout_s=int(oracle.get("request_timeout_s", 30)),
            poll_interval_s=int(oracle.get("poll_interval_s", 2)),
            poll_max_s=int(oracle.get("poll_max_s", 120)),
            oob_domain=oob.get("domain", "") or "",
            oob_hits_file=oob.get("hits_file", "") or "",
            upload_bind_host=up.get("bind_host", "0.0.0.0"),
            upload_bind_port=int(up.get("bind_port", 0) or 0),
            upload_public_base=up.get("public_base", "") or "",
            max_concurrency=int(tp.get("max_concurrency", 4)),
            per_request_delay_ms=int(tp.get("per_request_delay_ms", 0)),
            corpus_dir=ml.get("corpus_dir", "corpus"),
            llm_in_pipeline=bool(ml.get("llm_in_pipeline", True)),
            raw=d,
        )


def load_identities(path: str | Path) -> dict[str, Identity]:
    d = _load(path)
    out: dict[str, Identity] = {}
    for key, v in d.items():
        out[key] = Identity(
            key=key,
            label=v.get("label", key),
            account_id=v.get("account_id", ""),
            api_key=v.get("api_key", ""),
        )
    return out
