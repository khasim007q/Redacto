"""Runtime configuration for Redacto.

Everything is explicitly configured. Adapters fail closed when their scope is
missing, so a caller can never broaden the blast radius with a prompt.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env_path(name: str, default: str) -> Path:
    return Path(os.environ.get(name, default)).expanduser().resolve()


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    """Immutable settings resolved once at process start."""

    db_path: Path
    workspace_root: Path
    sqlite_store_path: Path
    jsonl_log_path: Path
    vector_fixture_path: Path
    hmac_key: str
    safety_mode: str
    dry_run: bool
    max_scan_records: int
    model_provider: str
    model_base_url: str | None
    model_name: str | None
    model_timeout_seconds: float
    http_host: str
    http_port: int
    http_token: str | None
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def adapters_configured(self) -> dict[str, bool]:
        return {
            "filesystem": self.workspace_root.exists(),
            "sqlite": self.sqlite_store_path.exists(),
            "jsonl": self.jsonl_log_path.exists(),
            "vector_fixture": self.vector_fixture_path.exists(),
        }

    def public_summary(self) -> dict[str, object]:
        """Safe-to-return view: no keys, tokens or file contents."""
        return {
            "db_path": str(self.db_path),
            "workspace_root": str(self.workspace_root),
            "sqlite_store": str(self.sqlite_store_path),
            "jsonl_log": str(self.jsonl_log_path),
            "vector_fixture": str(self.vector_fixture_path),
            "safety_mode": self.safety_mode,
            "dry_run_default": self.dry_run,
            "max_scan_records": self.max_scan_records,
            "model_provider": self.model_provider,
            "model_configured": bool(self.model_base_url and self.model_name),
            "http_bind": f"{self.http_host}:{self.http_port}",
            "http_auth_required": bool(self.http_token),
        }


def load_settings() -> Settings:
    base = Path.cwd()
    model_provider = os.environ.get("REDACTO_MODEL_PROVIDER", "none").strip().lower()
    return Settings(
        db_path=_env_path("REDACTO_DB_PATH", str(base / "var" / "redacto.sqlite3")),
        workspace_root=_env_path("REDACTO_WORKSPACE_ROOT", str(base / "fixtures" / "workspace")),
        sqlite_store_path=_env_path(
            "REDACTO_SQLITE_PATH", str(base / "fixtures" / "workspace" / "agent_memory.sqlite3")
        ),
        jsonl_log_path=_env_path(
            "REDACTO_JSONL_PATH", str(base / "fixtures" / "workspace" / "agent_events.jsonl")
        ),
        vector_fixture_path=_env_path(
            "REDACTO_VECTOR_PATH", str(base / "fixtures" / "workspace" / "vector_chunks.json")
        ),
        hmac_key=os.environ.get("REDACTO_HMAC_KEY", "dev-only-synthetic-fixture-key"),
        safety_mode=os.environ.get("REDACTO_SAFETY_MODE", "review"),
        dry_run=_env_bool("REDACTO_DRY_RUN", True),
        max_scan_records=int(os.environ.get("REDACTO_MAX_SCAN_RECORDS", "500")),
        model_provider=model_provider,
        model_base_url=os.environ.get("REDACTO_MODEL_BASE_URL") or None,
        model_name=os.environ.get("REDACTO_MODEL_NAME") or None,
        model_timeout_seconds=float(os.environ.get("REDACTO_MODEL_TIMEOUT", "10")),
        http_host=os.environ.get("REDACTO_HTTP_HOST", "127.0.0.1"),
        http_port=int(os.environ.get("REDACTO_HTTP_PORT", "8765")),
        http_token=os.environ.get("REDACTO_HTTP_TOKEN") or None,
    )
