"""`redacto_status` business logic, independent of MCP transport."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from redacto import __version__
from redacto.adapters.registry import build_adapters
from redacto.config import Settings


def _model_status(settings: Settings) -> dict[str, object]:
    provider = settings.model_provider
    configured = bool(settings.model_base_url and settings.model_name)
    if provider in {"none", "", "disabled"}:
        return {
            "provider": "none",
            "available": False,
            "deterministic_fallback": True,
            "detail": "Semantic assessment disabled; deterministic discovery only.",
        }
    if not configured:
        return {
            "provider": provider,
            "available": False,
            "deterministic_fallback": True,
            "detail": "Provider name set but base URL/model missing; assessment returns unassessed.",
        }
    return {
        "provider": provider,
        "available": True,
        "deterministic_fallback": True,
        "model": settings.model_name,
        "detail": "Model output is advisory and schema-validated.",
    }


def _revocation_counts(db_path: Path) -> dict[str, object]:
    """Read-only counts; never creates or mutates the graph database."""
    if not db_path.is_file():
        return {"available": False, "active_tombstones": 0, "quarantine_pending": 0}
    try:
        conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True, timeout=2)
    except sqlite3.Error:
        return {"available": False, "active_tombstones": 0, "quarantine_pending": 0}
    try:
        active = conn.execute("SELECT COUNT(*) FROM tombstones WHERE status = 'active'").fetchone()[0]
        pending = conn.execute(
            "SELECT COUNT(*) FROM quarantine WHERE status = 'pending_review'"
        ).fetchone()[0]
        return {"available": True, "active_tombstones": active, "quarantine_pending": pending}
    except sqlite3.Error:
        return {"available": False, "active_tombstones": 0, "quarantine_pending": 0}
    finally:
        conn.close()


def collect_status(settings: Settings, *, transport: str) -> dict[str, object]:
    slots = build_adapters(settings)
    adapters: list[dict[str, object]] = []
    for adapter_id, slot in slots.items():
        if slot.adapter is None:
            adapters.append(
                {
                    "adapter_id": adapter_id,
                    "reachable": False,
                    "unavailable_reason": slot.unavailable_reason,
                    "capabilities": None,
                }
            )
            continue
        adapters.append(
            {
                "adapter_id": adapter_id,
                "store_id": slot.adapter.store_id,
                "capabilities": slot.adapter.capabilities().as_dict(),
                "health": slot.adapter.health(),
            }
        )

    reachable = [a for a in adapters if a.get("health", {}).get("reachable")] if adapters else []
    unreachable = [a["adapter_id"] for a in adapters if a not in reachable]

    pending_db = not settings.db_path.parent.exists()

    return {
        "service": "redacto",
        "version": __version__,
        "transport": transport,
        "safety_mode": settings.safety_mode,
        "dry_run_default": settings.dry_run,
        "destructive_actions_require": "approved plan version + application confirmation token",
        "scope": settings.public_summary(),
        "adapters": adapters,
        "reachable_adapter_count": len(reachable),
        "unreachable_adapters": unreachable,
        "model_assessment": _model_status(settings),
        "storage": {
            "graph_db": str(settings.db_path),
            "graph_db_parent_ready": not pending_db,
        },
        "revocation": _revocation_counts(settings.db_path),
        "limitations": [
            "Verification covers configured, reachable stores only.",
            "A successful adapter response is not proof that copies, backups or provider logs are gone.",
        ],
    }
