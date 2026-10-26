"""`redacto_status` business logic, independent of MCP transport."""

from __future__ import annotations

import json
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


def _revocation_status(settings: Settings) -> dict[str, object]:
    """Read-only tombstone/keyring health; never creates or mutates the database."""
    base: dict[str, object] = {
        "available": False,
        "active_tombstones": 0,
        "quarantine_pending": 0,
        "tombstones_by_key_version": {},
        "in_use_key_versions": [],
        "missing_key_versions": [],
        "protection_degraded": bool(settings.keyring_error),
        "keyring_error": settings.keyring_error,
        "configured_key_versions": sorted(settings.hmac_keys),
        "current_key_version": settings.hmac_key_version,
    }
    db_path = settings.db_path
    if not db_path.is_file():
        return base
    try:
        conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True, timeout=2)
    except sqlite3.Error:
        return base
    try:
        active = conn.execute("SELECT COUNT(*) FROM tombstones WHERE status = 'active'").fetchone()[0]
        pending = conn.execute(
            "SELECT COUNT(*) FROM quarantine WHERE status = 'pending_review'"
        ).fetchone()[0]
        by_version = {
            int(row[0]): int(row[1])
            for row in conn.execute(
                "SELECT key_version, COUNT(*) FROM tombstones WHERE status = 'active' "
                "GROUP BY key_version"
            ).fetchall()
        }
        required_versions: set[int] = set(by_version)
        for row in conn.execute(
            "SELECT related_fingerprints_json FROM tombstones WHERE status = 'active'"
        ).fetchall():
            try:
                entries = json.loads(row[0] or "[]")
            except json.JSONDecodeError:
                continue
            for entry in entries:
                if isinstance(entry, dict) and entry.get("version"):
                    required_versions.add(int(entry["version"]))
    except sqlite3.Error:
        return base
    finally:
        conn.close()

    missing = sorted(v for v in required_versions if v not in settings.hmac_keys)
    current_missing = settings.hmac_key_version not in settings.hmac_keys
    base.update(
        {
            "available": True,
            "active_tombstones": active,
            "quarantine_pending": pending,
            "tombstones_by_key_version": by_version,
            "in_use_key_versions": sorted(required_versions),
            "missing_key_versions": missing,
            "protection_degraded": bool(
                settings.keyring_error or missing or current_missing
            ),
        }
    )
    return base


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
        "embeddings": {
            "provider": settings.embedding_provider,
            "candidate_threshold": settings.embedding_candidate_threshold,
            "quarantine_threshold": settings.embedding_quarantine_threshold,
            "role": "candidate generation and risk scoring only; never proof of lineage",
        },
        "storage": {
            "graph_db": str(settings.db_path),
            "graph_db_parent_ready": not pending_db,
        },
        "revocation": _revocation_status(settings),
        "limitations": [
            "Verification covers configured, reachable stores only.",
            "A successful adapter response is not proof that copies, backups or provider logs are gone.",
        ],
    }
