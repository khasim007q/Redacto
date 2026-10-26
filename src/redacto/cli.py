"""Local terminal application: seed, plan approval, demo and JSON tool access.

The CLI is the "application" in the approval model: it is what issues the
short-lived confirmation token. The agent-facing MCP surface cannot do this.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from redacto.config import load_settings
from redacto.engine import Engine
from redacto.errors import RedactoError
from redacto.fixtures import ACQUISITION_PLAN, SOURCE_ID, seed_workspace
from redacto.receipts import to_json, to_markdown


def _print(payload: object) -> None:
    print(json.dumps(payload, indent=2, default=str))


def _stores(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]


def _engine() -> Engine:
    return Engine(load_settings())


def cmd_seed(args: argparse.Namespace) -> int:
    settings = load_settings()
    result = seed_workspace(settings)
    _print(result)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    engine = _engine()
    _print(engine.status(transport="local-cli"))
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    engine = _engine()
    _print(
        {
            "ok": True,
            **engine.scan(
                target_id=args.target_id,
                target_kind=args.kind,
                stores=_stores(args.stores),
                depth=args.depth,
                use_model=not args.no_model,
            ),
        }
    )
    return 0


def cmd_trace(args: argparse.Namespace) -> int:
    engine = _engine()
    _print({"ok": True, **engine.trace(source_id=args.source_id, depth=args.depth)})
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    engine = _engine()
    result = engine.plan(
        target_id=args.target_id,
        mode=args.mode,
        stores=_stores(args.stores),
        depth=args.depth,
        use_model=not args.no_model,
    )
    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    _print(result)
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    engine = _engine()
    _print(engine.approve_plan(plan_id=args.plan_id, approval_ref=args.ref, ttl_seconds=args.ttl))
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    engine = _engine()
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
    engine = _engine()
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
    engine = _engine()
    statuses = _stores(args.statuses) or ["active"]
    _print(engine.tombstones(statuses=statuses))
    return 0


def cmd_quarantine(args: argparse.Namespace) -> int:
    engine = _engine()
    statuses = _stores(args.statuses) or ["pending_review"]
    _print(engine.quarantine(statuses=statuses))
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    engine = _engine()
    _print(engine.reingest_stores(stores=_stores(args.stores)))
    return 0


def cmd_resolve_quarantine(args: argparse.Namespace) -> int:
    engine = _engine()
    _print(engine.resolve_quarantine(quarantine_id=args.id, decision=args.decision))
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    settings = load_settings()
    var = settings.db_path.parent
    print("== Redacto demo ==")
    seed = seed_workspace(settings)
    print(f"[1] Seeded synthetic workspace: {seed['records_seeded']} records in {seed['workspace_root']}")
    print(f"    Target: {SOURCE_ID} (confidential acquisition plan)")

    engine = Engine(settings)
    trace = engine.trace(source_id=SOURCE_ID, depth=3)
    print("\n[2] Provenance graph")
    print(f"    confirmed descendants: {len(trace['confirmed_descendants'])}")
    for node in trace["confirmed_descendants"]:
        print(f"      - {node['record_id']} (depth {node['depth']}, {node['via'][-1]['relation']})")
    for node in trace["weak_exposure"]:
        print(f"      ~ weak exposure only: {node['record_id']} (READ_FROM, not destructive)")
    print(f"    candidate relationships: {len(trace['candidate_relationships'])}")

    plan = engine.plan(target_id=SOURCE_ID, mode="source_revocation", depth=3)
    print(f"\n[3] Draft plan {plan['plan_id']} (v{plan['plan_version']}) state={plan['state']}")
    for item in plan["items"]:
        flag = "APPROVED-ITEM" if item["approved"] else "review/preserve"
        print(
            f"      {item['evidence_class']:<22} {item['proposed_action']:<18} "
            f"{item['record_id']:<32} [{flag}] {item['reason_redacted']}"
        )
    print(f"    estimated impact: {plan['estimated_impact']}")
    for warning in plan["warnings"]:
        print(f"    ! {warning}")

    approval_ref = "demo-operator-approval 2026-10-26"
    approval = engine.approve_plan(plan_id=plan["plan_id"], approval_ref=approval_ref)
    print(f"\n[4] Application issued approval {approval['approval_id']} "
          f"(token valid until {approval['expires_at']}, single use)")

    dry = engine.apply(
        plan_id=plan["plan_id"],
        plan_version=plan["plan_version"],
        approval_ref=approval_ref,
        confirmation_token=approval["confirmation_token"],
        dry_run=True,
    )
    print(f"    dry run: {dry['counts']} (no destructive operation performed)")

    applied = engine.apply(
        plan_id=plan["plan_id"],
        plan_version=plan["plan_version"],
        approval_ref=approval_ref,
        confirmation_token=approval["confirmation_token"],
        dry_run=False,
    )
    print(f"\n[5] Apply results: {applied['counts']} state={applied['plan_state']}")
    for result in applied["results"]:
        print(
            f"      - {result.get('adapter_id')}: {result.get('operation')} "
            f"{result.get('record_id', '')} -> {result.get('result')}"
        )
    for blocked in applied["review_required"]:
        print(f"      ! review required (not deleted): {blocked['record_id']} ({blocked['evidence_class']})")

    verified = engine.verify(request_id=applied["request_id"])
    summary = verified["receipt"]
    print(f"\n[6] Verification: {verified['status']} (receipt {verified['receipt_id']})")
    for key, value in summary["counts"].items():
        print(f"      {key}: {value}")
    for store in summary["stores"]:
        print(f"      store {store['store_id']}: {store['outcome']} (residuals {store['residual_count']})")

    var.mkdir(parents=True, exist_ok=True)
    (var / "demo_receipt.json").write_text(to_json(summary), encoding="utf-8")
    (var / "demo_receipt.md").write_text(to_markdown(summary), encoding="utf-8")
    print(f"\n[7] Receipt written to {var / 'demo_receipt.json'} and {var / 'demo_receipt.md'}")
    print(f"    {summary['statement']}")

    print("\n[8] Re-ingestion attack")
    restored = settings.workspace_root / "acquisition-plan.md"
    restored.write_text(ACQUISITION_PLAN, encoding="utf-8")
    with sqlite3.connect(settings.sqlite_store_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO memories (id, content, created_at, sensitivity) VALUES (?, ?, ?, ?)",
            (
                "mem-reintroduced-paraphrase",
                "Kestrel deal was about $42 million, I believe.",
                "2026-10-26T12:00:00+00:00",
                "confidential",
            ),
        )
        conn.commit()
    reingest = engine.reingest_stores(stores=["filesystem", "sqlite_memory"])
    print(f"    guard counts: {reingest['counts']} (active tombstones: {reingest['guard']['active_tombstones']})")
    for finding in reingest["findings"]:
        print(
            f"      {finding['decision']:<12} {finding['record_id']:<34} "
            f"{finding['reason_code']} (score {finding['match_score']})"
        )
    print("    Restored exact copies are blocked; paraphrases are quarantined for review, not deleted.")
    print("    Learn more: README.md and docs/demo-script.md")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    settings = load_settings()
    if args.transport == "http":
        from redacto.mcp.http_server import build_app
        import uvicorn

        app, resolved = build_app()
        uvicorn.run(app, host=resolved.http_host, port=resolved.http_port)
        return 0
    from redacto.mcp.server import create_server

    create_server(settings, transport="stdio").run(transport="stdio")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="redacto", description="Provenance-aware revocation engine")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("seed", help="create the synthetic fixture workspace and graph").set_defaults(func=cmd_seed)
    sub.add_parser("status", help="adapter health and configured scope").set_defaults(func=cmd_status)

    scan = sub.add_parser("scan", help="discover candidates (read-only)")
    scan.add_argument("--target-id", required=True)
    scan.add_argument("--kind", default="source", choices=["source", "fact", "secret"])
    scan.add_argument("--stores")
    scan.add_argument("--depth", type=int, default=3)
    scan.add_argument("--no-model", action="store_true")
    scan.set_defaults(func=cmd_scan)

    trace = sub.add_parser("trace", help="explain lineage and candidates (read-only)")
    trace.add_argument("--source-id", required=True)
    trace.add_argument("--depth", type=int, default=3)
    trace.set_defaults(func=cmd_trace)

    plan = sub.add_parser("plan", help="create a draft revocation plan (non-destructive)")
    plan.add_argument("--target-id", required=True)
    plan.add_argument("--mode", default="source_revocation", choices=["source_revocation", "fact_revocation"])
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

    apply_cmd = sub.add_parser("apply", help="apply an approved plan (destructive)")
    apply_cmd.add_argument("--plan-id", required=True)
    apply_cmd.add_argument("--version", type=int, required=True)
    apply_cmd.add_argument("--ref", required=True)
    apply_cmd.add_argument("--token", required=True)
    apply_cmd.add_argument("--dry-run", action="store_true")
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

    ingest = sub.add_parser("ingest", help="re-run the ingestion guard over configured stores")
    ingest.add_argument("--stores")
    ingest.set_defaults(func=cmd_ingest)

    resolve = sub.add_parser("resolve-quarantine", help="mark a quarantine entry reviewed")
    resolve.add_argument("--id", required=True)
    resolve.add_argument("--decision", required=True, choices=["approved", "rejected"])
    resolve.set_defaults(func=cmd_resolve_quarantine)

    demo = sub.add_parser("demo", help="run the 90-120 second end-to-end storyboard")
    demo.set_defaults(func=cmd_demo)

    serve = sub.add_parser("serve", help="run the MCP server")
    serve.add_argument("--transport", default="stdio", choices=["stdio", "http"])
    serve.set_defaults(func=cmd_serve)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except RedactoError as exc:
        _print(exc.as_dict())
        return 2


if __name__ == "__main__":
    sys.exit(main())