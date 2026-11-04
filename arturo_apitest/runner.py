"""CLI runner: parse collections, resolve env, run selected suites, report.

Usage:
  python -m arturo_apitest.runner --config config/settings.yaml \\
      --collections collections/*.json --suites authz,injection,ml --out out/

Each suite is opt-in. Nothing fires without identities (authz) / an OOB domain
(injection) / a corpus (ml). A `--dry-run` parses + plans without any network.
"""
from __future__ import annotations

import argparse
import glob
import sys
from pathlib import Path

from .engine import report
from .engine.client import Client
from .engine.collection import parse_many, RequestTemplate
from .engine.config import Settings, load_identities
from .engine.envresolve import EnvResolver
from .engine.oracle import OOBProbe, FileOOBProbe, Finding


def _default_decision_reader(resp) -> bool | None:
    """Heuristic PASS reader for ML corpus — OVERRIDE per service as needed.

    Returns True (backend considers doc good), False (rejected/flagged), or None
    (couldn't tell). This is only ever compared against YOUR corpus label, so a
    None is skipped, never guessed. Tune the keys to the real response schema.
    """
    j = resp.json
    if not isinstance(j, (dict, list)):
        return None
    doc = j[0] if isinstance(j, list) and j else j
    if not isinstance(doc, dict):
        return None
    result = doc.get("result", doc)
    if not isinstance(result, dict):
        return None
    for key in ("is_tampered", "tampered", "is_deepfake", "fraud_detected"):
        if key in result:
            return result[key] is False  # PASS == not tampered/fake
    for key in ("verified", "is_genuine", "authentic"):
        if key in result:
            return result[key] is True
    status = str(result.get("verification_status", result.get("status", ""))).lower()
    if status in {"passed", "genuine", "authentic", "verified"}:
        return True
    if status in {"failed", "rejected", "tampered", "fake"}:
        return False
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="arturo_apitest")
    ap.add_argument("--config", required=True)
    ap.add_argument("--collections", nargs="+", required=True,
                    help="collection json paths or globs")
    ap.add_argument("--suites",
                    default="authz,injection,ml,broken_auth,misconfig,bopla,file_upload,redirect_host")
    ap.add_argument("--out", default="out")
    ap.add_argument("--dry-run", action="store_true",
                    help="parse + plan only; no network")
    args = ap.parse_args(argv)

    settings = Settings.load(args.config)

    # expand globs
    paths: list[str] = []
    for c in args.collections:
        paths.extend(glob.glob(c))
    if not paths:
        print("no collections matched", file=sys.stderr)
        return 2

    templates: list[RequestTemplate] = parse_many(paths)

    # env resolver: base_url seeds base_url if the files don't.
    resolver = EnvResolver.from_sources(
        postman_env=settings.postman_env if settings.postman_env and Path(settings.postman_env).exists() else None,
        overrides=settings.overrides if settings.overrides and Path(settings.overrides).exists() else None,
        extra={"base_url": settings.base_url} if settings.base_url else None,
    )

    # --- security hygiene surfacing (always, free) --------------------------
    leaked = [(t.uid, len(t.hardcoded_auth_headers())) for t in templates if t.hardcoded_auth_headers()]

    plan = {
        "collections": len(paths),
        "endpoints": len(templates),
        "sync": sum(1 for t in templates if t.mode == "sync"),
        "async": sum(1 for t in templates if t.mode == "async"),
        "poll": sum(1 for t in templates if t.mode == "poll"),
        "injectable_fields": sum(len(t.injectable_paths) for t in templates),
        "doc_url_sinks": sum(len(t.document_url_paths) for t in templates),
        "endpoints_with_leaked_creds": len(leaked),
    }
    print("PLAN:", plan)
    if resolver.unresolved:
        print("note: templates reference vars not in env (fine if auth-only):",
              sorted(resolver.unresolved)[:10])

    if args.dry_run:
        meta = {**plan, "base_url": settings.base_url, "proxy": settings.proxy_enabled,
                "stability_runs": settings.stability_runs,
                "stability_required": settings.stability_required, "dry_run": True}
        # report the leaked-cred hygiene finding even in dry-run
        findings = _leak_findings(leaked)
        out = report.write(findings, meta, args.out)
        print(f"dry-run report: {out['markdown']}")
        return 0

    suites = {s.strip() for s in args.suites.split(",") if s.strip()}
    findings: list[Finding] = _leak_findings(leaked)

    with Client(settings, resolver) as client:
        if "authz" in suites:
            from .suites import authz
            ids = load_identities(settings.identities_file) if settings.identities_file else {}
            if "A" in ids and "B" in ids and _ids_filled(ids):
                findings += authz.run(templates, client, settings, ids["A"], ids["B"])
            else:
                print("authz: skipped (need two filled identities in identities.yaml)")

        if "injection" in suites:
            from .suites import injection
            ids = load_identities(settings.identities_file) if settings.identities_file else {}
            identity = ids.get("A")
            probe = None
            if settings.oob_domain and settings.oob_hits_file:
                probe = FileOOBProbe(settings.oob_domain, settings.oob_hits_file)
            elif settings.oob_domain:
                probe = OOBProbe(settings.oob_domain)  # payloads fire; confirm needs was_hit wired
            if identity and probe and settings.oob_hits_file:
                findings += injection.run(templates, client, settings, identity, probe)
            elif identity and probe:
                print("injection: firing payloads but cannot confirm — set oob.hits_file to a "
                      "collaborator/interactsh hits file so was_hit() can confirm callbacks")
                findings += injection.run(templates, client, settings, identity, probe)
            else:
                print("injection: skipped (need identity A + oob.domain)")

        if "ml" in suites:
            from .suites import ml_image
            ids = load_identities(settings.identities_file) if settings.identities_file else {}
            identity = ids.get("A")
            if identity:
                findings += ml_image.run(templates, client, settings, identity, _default_decision_reader)
            else:
                print("ml: skipped (need identity A)")

        if "broken_auth" in suites:
            from .suites import broken_auth
            ids = load_identities(settings.identities_file) if settings.identities_file else {}
            identity = ids.get("A")
            if identity and identity.account_id and not identity.account_id.startswith("REPLACE"):
                id_b = ids.get("B")
                if id_b and id_b.account_id.startswith("REPLACE"):
                    id_b = None
                findings += broken_auth.run(templates, client, settings, identity, id_b)
            else:
                print("broken_auth: skipped (need identity A)")

        if "misconfig" in suites:
            from .suites import misconfig
            ids = load_identities(settings.identities_file) if settings.identities_file else {}
            identity = ids.get("A")
            if identity:
                findings += misconfig.run(templates, client, settings, identity)
            else:
                print("misconfig: skipped (need identity A)")

        if "bopla" in suites:
            from .suites import mass_assignment
            ids = load_identities(settings.identities_file) if settings.identities_file else {}
            identity = ids.get("A")
            if identity and identity.account_id and not identity.account_id.startswith("REPLACE"):
                findings += mass_assignment.run(templates, client, settings, identity)
            else:
                print("bopla: skipped (need identity A)")

        if "redirect_host" in suites:
            from .suites import redirect_host
            ids = load_identities(settings.identities_file) if settings.identities_file else {}
            identity = ids.get("A")
            if identity:
                findings += redirect_host.run(templates, client, settings, identity)
            else:
                print("redirect_host: skipped (need identity A)")

        if "file_upload" in suites:
            from .suites import file_upload
            from .engine.catcher import Catcher
            ids = load_identities(settings.identities_file) if settings.identities_file else {}
            identity = ids.get("A")
            if not identity:
                print("file_upload: skipped (need identity A)")
            elif not settings.upload_public_base:
                print("file_upload: skipped (set upload.public_base to a URL the target can "
                      "reach, plus upload.bind_port, so the catcher can confirm parsing)")
            else:
                catcher = Catcher(settings.upload_bind_host, settings.upload_bind_port,
                                  settings.upload_public_base).start()
                try:
                    findings += file_upload.run(templates, client, settings, identity, catcher)
                finally:
                    catcher.stop()

    meta = {**plan, "base_url": settings.base_url, "proxy": settings.proxy_enabled,
            "stability_runs": settings.stability_runs,
            "stability_required": settings.stability_required}
    out = report.write(findings, meta, args.out)
    print(f"report: {out['markdown']}  ({len(report.dedupe(findings))} findings)")
    return 0


def _ids_filled(ids) -> bool:
    for k in ("A", "B"):
        v = ids[k]
        if not v.account_id or v.account_id.startswith("REPLACE") or not v.api_key or v.api_key.startswith("REPLACE"):
            return False
    return True


def _leak_findings(leaked) -> list[Finding]:
    from .engine.oracle import Finding, Severity
    out = []
    for uid, n in leaked:
        out.append(Finding(
            suite="hygiene",
            owasp="API8:2023 Security Misconfiguration (hardcoded secrets in collection)",
            endpoint=uid,
            title="Hardcoded account-id/api-key present in Postman collection",
            severity=Severity.MEDIUM,
            confirmed_by="static",
            evidence={"leaked_header_values": n,
                      "note": "rotate these keys; they are committed in the collection export"},
        ))
    return out


if __name__ == "__main__":
    raise SystemExit(main())
