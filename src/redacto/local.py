"""Explicit settings for isolated examples and benchmarks; never reads .env."""

from pathlib import Path

from redacto.config import Settings


def local_settings(root: Path, *, hmac_key: str) -> Settings:
    root = Path(root).resolve()
    return Settings(
        db_path=root / "graph.sqlite3", workspace_root=root / "documents",
        sqlite_store_path=root / "memory.sqlite3", jsonl_log_path=root / "events.jsonl",
        vector_fixture_path=root / "chunks.json", hmac_keys={1: hmac_key}, hmac_key_version=1,
        embedding_provider="local_hashing", embedding_candidate_threshold=0.25,
        embedding_quarantine_threshold=0.30, safety_mode="strict", dry_run=True,
        max_scan_records=1000, max_record_bytes=1_000_000, model_provider="none",
        model_base_url=None, model_name=None, model_timeout_seconds=10,
        http_host="127.0.0.1", http_port=8765, http_token=None,
    )
