"""Findings report: dedup, stability-gate summary, JSON + Markdown output."""
from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .oracle import Finding, Severity

_SEV_ORDER = {
    Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
    Severity.LOW: 3, Severity.INFO: 4,
}


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for f in findings:
        if f.key() not in seen:
            seen[f.key()] = f
    return sorted(seen.values(), key=lambda f: _SEV_ORDER.get(f.severity, 9))


def to_json(findings: list[Finding], meta: dict) -> str:
    return json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "meta": meta,
        "count": len(findings),
        "findings": [
            {**asdict(f), "severity": f.severity.value} for f in findings
        ],
    }, indent=2)


def to_markdown(findings: list[Finding], meta: dict) -> str:
    lines = [
        "# API Security Test Report",
        f"_Generated {datetime.now(timezone.utc).isoformat()}_",
        "",
        f"- Target: `{meta.get('base_url','?')}`",
        f"- Endpoints tested: {meta.get('endpoints','?')}",
        f"- Proxy (Burp): {'on' if meta.get('proxy') else 'off'}",
        f"- Stability gate: {meta.get('stability_required','?')}/{meta.get('stability_runs','?')}",
        f"- **Findings: {len(findings)}** "
        f"(every finding below was confirmed by differential, OOB, or a reproduced stability gate)",
        "",
    ]
    if not findings:
        lines += ["No confirmed findings. (Candidate signals that failed "
                  "confirmation were discarded, not reported.)"]
        return "\n".join(lines)
    for f in findings:
        lines += [
            f"## [{f.severity.value.upper()}] {f.title}",
            f"- **Class:** {f.owasp}",
            f"- **Endpoint:** `{f.endpoint}`",
            f"- **Confirmed by:** {f.confirmed_by}"
            + (f" (reproduced {f.reproductions}x)" if f.reproductions else ""),
            "- **Evidence:**",
            "```json",
            json.dumps(f.evidence, indent=2),
            "```",
            "",
        ]
    return "\n".join(lines)


def write(findings: list[Finding], meta: dict, out_dir: str | Path) -> dict[str, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    findings = dedupe(findings)
    j = out / "report.json"
    m = out / "report.md"
    j.write_text(to_json(findings, meta))
    m.write_text(to_markdown(findings, meta))
    return {"json": j, "markdown": m}
