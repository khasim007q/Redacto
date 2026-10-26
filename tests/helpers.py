"""Shared test helpers."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from redacto.config import Settings  # noqa: E402
from redacto.fixtures import seed_workspace  # noqa: E402


def make_settings(tmp_path: Path, **overrides: Any) -> Settings:
    workspace = tmp_path / "workspace"
    values: dict[str, Any] = {
        "db_path": tmp_path / "var" / "redacto.sqlite3",
        "workspace_root": workspace,
        "sqlite_store_path": workspace / "agent_memory.sqlite3",
        "jsonl_log_path": workspace / "agent_events.jsonl",
        "vector_fixture_path": workspace / "vector_chunks.json",
        "hmac_keys": {1: "unit-test-fixture-key"},
        "hmac_key_version": 1,
        "embedding_provider": "local_hashing",
        "embedding_candidate_threshold": 0.25,
        "embedding_quarantine_threshold": 0.30,
        "safety_mode": "review",
        "dry_run": False,
        "max_scan_records": 500,
        "model_provider": "none",
        "model_base_url": None,
        "model_name": None,
        "model_timeout_seconds": 0.5,
        "http_host": "127.0.0.1",
        "http_port": 8765,
        "http_token": None,
    }
    values.update(overrides)
    return Settings(**values)


def seeded_settings(tmp_path: Path, **overrides: Any) -> Settings:
    settings = make_settings(tmp_path, **overrides)
    seed_workspace(settings)
    return settings


def sqlite_rows(db_path: Path, query: str) -> list[sqlite3.Row]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(query).fetchall()
    finally:
        conn.close()