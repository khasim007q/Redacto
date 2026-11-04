"""Operator CLI for workspace configuration, review, approval and revocation.

The CLI is the "application" in the approval model: it is what issues the
short-lived confirmation token. The agent-facing MCP surface cannot do this.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from redacto.config import load_settings
from redacto.engine import Engine
from redacto.errors import HmacKeyError, RedactoError
from redacto.receipts import to_json, to_markdown


def _print(payload: object) -> None:
    print(json.dumps(payload, indent=2, default=str))


def _stores(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]


def _settings(args: argparse.Namespace):
    profile = getattr(args, "profile", None)
    return load_settings(profile=profile) if profile else load_settings()


def _engine(args: argparse.Namespace) -> Engine:
    return Engine(_settings(args))


def cmd_setup(args: argparse.Namespace) -> int:
    from redacto.profiles import setup_workspace

    result = setup_workspace(args.workspace, state_dir=args.state_dir, managed_memory=args.managed_memory)
    if args.client != "generic" or args.config:
        args.profile = Path(result["profile"])
        result["connection"] = _connect(args)
    _print(result)
    return 0


def _connect(args: argparse.Namespace) -> dict:
    from redacto.connectivity import client_config, default_config_path, register

    profile = getattr(args, "profile", None) or os.environ.get("REDACTO_PROFILE")
    url = getattr(args, "url", None)
    resolved = Path(profile).expanduser().resolve() if profile else None
    config = client_config(profile=resolved, client=args.client, name=args.name, url=url,
                           token_env=getattr(args, "token_env", "REDACTO_HTTP_TOKEN"))
    if args.print_only or (args.client == "generic" and not args.config):
        return {"ok": True, "configuration": config}
    workspace = load_settings(resolved).workspace_root if resolved else None
    path = args.config or default_config_path(args.client, workspace)
    return register(config, path, replace=args.replace)


def cmd_connect(args: argparse.Namespace) -> int:
    _print(_connect(args))
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    settings = _settings(args)
    settings.current_hmac_key
    status = Engine(settings).status(transport="local-cli")
    from redacto.adapters.registry import build_adapters

    slots = build_adapters(settings)
    checks = [{"store_id": name, "reachable": slot.adapter is not None,
               "reason": slot.unavailable_reason} for name, slot in slots.items()]
    revocation = status["revocation"]
    healthy = (all(check["reachable"] for check in checks)
               and not revocation["protection_degraded"]
               and not revocation["semantic_protection_degraded"]
               and (not settings.db_path.exists() or revocation["available"]))
    _print({"ok": healthy, "stores": checks, "status": status,
            "note": "Checks configured connections only; no deletion, corpus scan or model download."})
    return 0 if healthy else 2


def cmd_status(args: argparse.Namespace) -> int:
    engine = _engine(args)
    _print(engine.status(transport="local-cli"))
    return 0


def _target_text(args: argparse.Namespace) -> str | None:
    """The fact/secret value, read from stdin or an env var, never from argv.

    Taking the value as a plain argument would leave it in shell history and in
    process listings.
    """
    if getattr(args, "kind", "source") == "source":
        if getattr(args, "text_stdin", False) or getattr(args, "text_env", None):
            raise RedactoError("invalid_target_text", "--text-stdin/--text-env need --kind fact|secret.")
        return None
    if getattr(args, "text_env", None):
        value = os.environ.get(args.text_env, "")
    elif getattr(args, "text_stdin", False):
        value = sys.stdin.read()
    else:
        raise RedactoError(
            "missing_target_text",
            "A fact/secret target needs its value: pipe it with --text-stdin or name an env var "
            "with --text-env.",
        )
    value = value.strip()
    if not value:
        raise RedactoError("missing_target_text", "The fact/secret value is empty.")
    return value


def cmd_scan(args: argparse.Namespace) -> int:
    engine = _engine(args)
    _print(
        {
            "ok": True,
            **engine.scan(
                target_id=args.target_id,
                target_kind=args.kind,
                stores=_stores(args.stores),
                depth=args.depth,
                use_model=not args.no_model,
                target_text=_target_text(args),
            ),
        }
    )
    return 0


def cmd_trace(args: argparse.Namespace) -> int:
    engine = _engine(args)
    _print({"ok": True, **engine.trace(source_id=args.source_id, depth=args.depth)})
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    engine = _engine(args)
    mode = args.mode or ("source_revocation" if args.kind == "source" else "fact_revocation")
    result = engine.plan(
        target_id=args.target_id,
        mode=mode,
        target_kind=args.kind,
        stores=_stores(args.stores),
        depth=args.depth,
        use_model=not args.no_model,
        target_text=_target_text(args),
    )
    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    _print(result)
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    engine = _engine(args)
    _print(engine.approve_plan(plan_id=args.plan_id, approval_ref=args.ref, ttl_seconds=args.ttl))
    return 0


def cmd_review_item(args: argparse.Namespace) -> int:
    engine = _engine(args)
    _print(
        engine.review_plan_item(
            plan_id=args.plan_id,
            item_id=args.item_id,
            decision=args.decision,
            reviewer=args.reviewer,
            note=args.note,
            action=getattr(args, "action", None),
        )
    )
    return 0


def cmd_cancel(args: argparse.Namespace) -> int:
    engine = _engine(args)
    _print(engine.cancel_plan(plan_id=args.plan_id, reason=args.reason or ""))
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    engine = _engine(args)
    if args.dry_run is None:
        # Same default as MCP redacto_apply: REDACTO_DRY_RUN decides.
        print(
            f"    dry_run not specified; using REDACTO_DRY_RUN default "
            f"({engine.settings.dry_run}). Pass --no-dry-run for a real run.",
            file=sys.stderr,
        )
    _print(
        engine.apply(
            plan_id=args.plan_id,
            plan_version=args.version,
            approval_ref=args.ref,
            confirmation_token=args.token,
            dry_run=args.dry_run,
        )
    )
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    engine = _engine(args)
    result = engine.verify(
        request_id=args.request_id,
        receipt_id=args.receipt_id,
        stores=_stores(args.stores),
    )
    if args.out:
        Path(args.out).write_text(to_json(result["receipt"]), encoding="utf-8")
    if args.markdown:
        Path(args.markdown).write_text(to_markdown(result["receipt"]), encoding="utf-8")
    _print(result)
    return 0


def cmd_tombstones(args: argparse.Namespace) -> int:
    engine = _engine(args)
    statuses = _stores(args.statuses) or ["active"]
    _print(engine.tombstones(statuses=statuses))
    return 0


def cmd_quarantine(args: argparse.Namespace) -> int:
    engine = _engine(args)
    statuses = _stores(args.statuses) or ["pending_review"]
    _print(engine.quarantine(statuses=statuses))
    return 0


def cmd_check_receipt(args: argparse.Namespace) -> int:
    from redacto.receipts import check_receipt

    try:
        summary = json.loads(Path(args.path).read_text(encoding="utf-8"))
        if not isinstance(summary, dict):
            raise ValueError("receipt must be an object")
    except (OSError, ValueError) as exc:
        raise RedactoError("invalid_receipt", "Receipt is not a readable JSON object.") from exc
    result = check_receipt(summary, keyring=_settings(args).hmac_keys)
    _print(result)
    return 0 if result["valid"] else 1


def cmd_check_embeddings(args: argparse.Namespace) -> int:
    """Load explicitly selected weights using public synthetic text only."""
    from dataclasses import replace
    from redacto.discovery.embeddings import embedding_scores

    settings = _settings(args)
    if args.offline:
        settings = replace(settings, embedding_local_files_only=True)
    provider = Engine(settings).embedder()
    first = provider.embed("The public SDK supports Linux.")
    second = provider.embed("Le SDK public prend en charge Linux.")
    scores = embedding_scores(first, provider.model_id, second, provider.model_id)
    _print({"ok": True, "provider": settings.embedding_provider, "model_id": provider.model_id,
            "dimensions": len(first), "local_files_only": settings.embedding_local_files_only,
            "synthetic_translation_similarity": round(max(scores.values(), default=0.0), 4),
            "component_similarities": {name: round(score, 4) for name, score in sorted(scores.items())},
            "candidate_threshold": settings.embedding_candidate_threshold,
            "quarantine_threshold": settings.embedding_quarantine_threshold,
            "role": "advisory candidates only; similarity is not proof of derivation"})
    return 0


def cmd_keyring(args: argparse.Namespace) -> int:
    engine = _engine(args)
    _print(engine.keyring_report(retire_version=args.retire))
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from redacto.report import build_report

    engine = _engine(args)
    request_id = args.request_id or engine.repo.latest_request_id()
    if not request_id:
        raise RedactoError(
            "no_requests",
            f"No revocation has been planned in {engine.settings.db_path} yet. "
            "Run `redacto plan --target-id <id>` first.",
        )
    html = build_report(engine, request_id=request_id)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    _print({"ok": True, "request_id": request_id, "report": str(out.resolve())})
    return 0


def cmd_clean_temps(args: argparse.Namespace) -> int:
    engine = _engine(args)
    _print(engine.clean_leftover_temps(delete=args.delete))
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    engine = _engine(args)
    _print(engine.reingest_stores(stores=_stores(args.stores)))
    return 0


def cmd_resolve_quarantine(args: argparse.Namespace) -> int:
    engine = _engine(args)
    _print(
        engine.resolve_quarantine(
            quarantine_id=args.id,
            decision=args.decision,
            reviewer=args.reviewer,
            note=args.note,
        )
    )
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    settings = _settings(args)
    if args.transport == "http":
        from redacto.mcp.http_server import build_app
        import uvicorn

        app, resolved = build_app(settings)
        uvicorn.run(app, host=resolved.http_host, port=resolved.http_port)
        return 0
    from redacto.mcp.server import create_server

    create_server(settings, transport="stdio").run(transport="stdio")
    return 0


def _add_target_text_args(parser: argparse.ArgumentParser) -> None:
    text = parser.add_mutually_exclusive_group()
    text.add_argument(
        "--text-stdin",
        action="store_true",
        help="read the fact/secret value from stdin (kept out of shell history)",
    )
    text.add_argument("--text-env", metavar="VAR", help="read the fact/secret value from this env var")


def build_parser() -> argparse.ArgumentParser:
    from redacto.connectivity import CLIENTS
    parser = argparse.ArgumentParser(prog="redacto", description="Provenance-aware revocation engine")
    parser.add_argument("--profile", type=Path, help="saved workspace profile (also REDACTO_PROFILE)")
    sub = parser.add_subparsers(dest="command", required=True)

    setup = sub.add_parser("setup", help="connect an ordinary folder to Claude or another MCP client")
    setup.add_argument("--workspace", type=Path, required=True)
    setup.add_argument("--state-dir", type=Path, help="private state directory outside the scanned folder")
    setup.add_argument("--managed-memory", action="store_true", help="create owned SQLite memory/cache and JSONL stores")
    connect = sub.add_parser("connect", help="register or print a client-specific MCP connection")
    connect.add_argument("--url", help="HTTPS MCP endpoint (HTTP permitted for loopback only)")
    connect.add_argument("--token-env", default="REDACTO_HTTP_TOKEN")
    connect.set_defaults(func=cmd_connect)
    for command in (setup, connect):
        command.add_argument("--client", choices=CLIENTS, default="generic")
        command.add_argument("--config", type=Path, help="explicit client JSON path")
        command.add_argument("--name", default="redacto", help="unique client server entry name")
        command.add_argument("--replace", action="store_true", help="replace a conflicting server entry after backup")
        command.add_argument("--print-only", action="store_true", help="print client settings without editing client files")
    setup.set_defaults(func=cmd_setup)
    sub.add_parser("doctor", help="check profile, keyring and enabled store connections").set_defaults(func=cmd_doctor)

    sub.add_parser("status", help="adapter health and configured scope").set_defaults(func=cmd_status)

    scan = sub.add_parser("scan", help="discover candidates without editing source-store content")
    scan.add_argument("--target-id", required=True)
    scan.add_argument("--kind", default="source", choices=["source", "fact", "secret"])
    scan.add_argument("--stores")
    scan.add_argument("--depth", type=int, default=3)
    scan.add_argument("--no-model", action="store_true")
    _add_target_text_args(scan)
    scan.set_defaults(func=cmd_scan)

    trace = sub.add_parser("trace", help="explain lineage and candidates without editing source-store content")
    trace.add_argument("--source-id", required=True)
    trace.add_argument("--depth", type=int, default=3)
    trace.set_defaults(func=cmd_trace)

    plan = sub.add_parser("plan", help="create a draft revocation plan (non-destructive)")
    plan.add_argument("--target-id", required=True)
    plan.add_argument("--kind", default="source", choices=["source", "fact", "secret"])
    plan.add_argument(
        "--mode",
        choices=["source_revocation", "fact_revocation"],
        help="default: source_revocation for --kind source, otherwise fact_revocation",
    )
    _add_target_text_args(plan)
    plan.add_argument("--stores")
    plan.add_argument("--depth", type=int, default=3)
    plan.add_argument("--no-model", action="store_true")
    plan.add_argument("--out")
    plan.set_defaults(func=cmd_plan)

    approve = sub.add_parser("approve", help="application issues a confirmation token")
    approve.add_argument("--plan-id", required=True)
    approve.add_argument("--ref", required=True)
    approve.add_argument("--ttl", type=int, default=600)
    approve.set_defaults(func=cmd_approve)

    review_item = sub.add_parser(
        "review-item", help="approve or reject one REVIEW_REQUIRED plan item"
    )
    review_item.add_argument("--plan-id", required=True)
    review_item.add_argument("--item-id", required=True)
    review_item.add_argument("--decision", required=True, choices=["approved", "rejected"])
    review_item.add_argument("--reviewer", default="local-operator")
    review_item.add_argument("--note")
    review_item.add_argument("--action", choices=["redact", "delete"], help="default: preserve other content with a planned redaction when available")
    review_item.set_defaults(func=cmd_review_item)

    cancel = sub.add_parser("cancel", help="cancel a plan before it starts executing")
    cancel.add_argument("--plan-id", required=True)
    cancel.add_argument("--reason")
    cancel.set_defaults(func=cmd_cancel)

    apply_cmd = sub.add_parser("apply", help="apply an approved plan (destructive)")
    apply_cmd.add_argument("--plan-id", required=True)
    apply_cmd.add_argument("--version", type=int, required=True)
    apply_cmd.add_argument("--ref", required=True)
    apply_cmd.add_argument("--token", required=True)
    apply_mode = apply_cmd.add_mutually_exclusive_group()
    apply_mode.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        default=None,
        help="simulate only (default: REDACTO_DRY_RUN)",
    )
    apply_mode.add_argument(
        "--no-dry-run",
        "--execute",
        dest="dry_run",
        action="store_false",
        help="delete for real even when REDACTO_DRY_RUN=true",
    )
    apply_cmd.set_defaults(func=cmd_apply)

    verify = sub.add_parser("verify", help="rescan and write a scoped receipt")
    verify.add_argument("--request-id")
    verify.add_argument("--receipt-id")
    verify.add_argument("--stores")
    verify.add_argument("--out")
    verify.add_argument("--markdown")
    verify.set_defaults(func=cmd_verify)

    tombstones = sub.add_parser("tombstones", help="list revocation tombstones (no content)")
    tombstones.add_argument("--statuses", default="active")
    tombstones.set_defaults(func=cmd_tombstones)

    quarantine = sub.add_parser("quarantine", help="list guard-quarantined records")
    quarantine.add_argument("--statuses", default="pending_review")
    quarantine.set_defaults(func=cmd_quarantine)

    check = sub.add_parser("check-receipt", help="verify a JSON receipt's HMAC integrity against the configured keyring")
    check.add_argument("path")
    check.set_defaults(func=cmd_check_receipt)

    embeddings = sub.add_parser("check-embeddings", help="check the configured embedder with public synthetic text; downloads weights only when explicitly enabled")
    embeddings.add_argument("--offline", action="store_true", help="load cached model files only")
    embeddings.set_defaults(func=cmd_check_embeddings)

    report = sub.add_parser(
        "report", help="write a read-only HTML report: stores, lineage, plan, timeline, receipt"
    )
    report.add_argument("--request-id", help="default: the most recent revocation request")
    report.add_argument("--out", default="var/report.html")
    report.set_defaults(func=cmd_report)

    clean = sub.add_parser(
        "clean-temps", help="list (or --delete) temp copies left by interrupted store rewrites"
    )
    clean.add_argument("--delete", action="store_true", help="remove them (older than 60 seconds only)")
    clean.set_defaults(func=cmd_clean_temps)

    keyring = sub.add_parser("keyring", help="audit HMAC key versions and rotation safety")
    keyring.add_argument("--retire", type=int)
    keyring.set_defaults(func=cmd_keyring)

    ingest = sub.add_parser("ingest", help="re-run the ingestion guard over configured stores")
    ingest.add_argument("--stores")
    ingest.set_defaults(func=cmd_ingest)

    resolve = sub.add_parser("resolve-quarantine", help="mark a quarantine entry reviewed")
    resolve.add_argument("--id", required=True)
    resolve.add_argument("--decision", required=True, choices=["approved", "rejected"])
    resolve.add_argument("--reviewer", default="local-operator")
    resolve.add_argument("--note")
    resolve.set_defaults(func=cmd_resolve_quarantine)

    serve = sub.add_parser("serve", help="run the MCP server")
    serve.add_argument("--transport", default="stdio", choices=["stdio", "http"])
    serve.set_defaults(func=cmd_serve)
    # Accept the profile before or after a subcommand without erasing a global value.
    for command in sub.choices.values():
        command.add_argument("--profile", type=Path, default=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except HmacKeyError as exc:
        _print({"ok": False, "error": {"code": exc.code, "message": exc.message}})
        return 2
    except RedactoError as exc:
        _print(exc.as_dict())
        return 2


if __name__ == "__main__":
    sys.exit(main())
