"""Runtime configuration for Redacto.

Everything is explicitly configured. Adapters fail closed when their scope is
missing, so a caller can never broaden the blast radius with a prompt.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from redacto.errors import HmacKeyError


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
    hmac_keys: dict[int, str]
    hmac_key_version: int
    embedding_provider: str
    embedding_candidate_threshold: float
    embedding_quarantine_threshold: float
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
    keyring_error: str | None = None
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def current_hmac_key(self) -> str:
        if self.keyring_error:
            raise HmacKeyError("keyring_invalid", self.keyring_error)
        key = self.hmac_keys.get(self.hmac_key_version)
        if not key:
            raise HmacKeyError(
                "current_key_unavailable",
                f"No HMAC key configured for current version {self.hmac_key_version}.",
            )
        return key

    @property
    def hmac_key(self) -> str:
        """Legacy alias for the current key."""
        return self.current_hmac_key

    def key_for_version(self, version: int | None) -> str | None:
        if version is None:
            return self.current_hmac_key
        return self.hmac_keys.get(version)

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
            "hmac_key_version": self.hmac_key_version,
            "hmac_key_versions": sorted(self.hmac_keys),
            "keyring_error": self.keyring_error,
            "embedding_provider": self.embedding_provider,
            "embedding_candidate_threshold": self.embedding_candidate_threshold,
            "embedding_quarantine_threshold": self.embedding_quarantine_threshold,
        }


def _load_keyring(default_key: str) -> tuple[dict[int, str], int, str | None]:
    """Versioned key ring: old versions stay available during rotation."""
    try:
        current_version = int(os.environ.get("REDACTO_HMAC_KEY_VERSION", "1"))
    except ValueError:
        return {}, 1, "REDACTO_HMAC_KEY_VERSION must be an integer."
    if current_version < 1:
        return {}, current_version, "REDACTO_HMAC_KEY_VERSION must be >= 1."

    raw = os.environ.get("REDACTO_HMAC_KEYS")
    if not raw:
        return {current_version: default_key}, current_version, None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}, current_version, "REDACTO_HMAC_KEYS must be a JSON object of version -> key."
    if not isinstance(parsed, dict) or not parsed:
        return {}, current_version, "REDACTO_HMAC_KEYS must be a non-empty JSON object."
    keys: dict[int, str] = {}
    for version_text, key in parsed.items():
        try:
            version = int(version_text)
        except (TypeError, ValueError):
            return {}, current_version, "REDACTO_HMAC_KEYS versions must be integers."
        if not isinstance(key, str) or not key:
            return {}, current_version, "REDACTO_HMAC_KEYS values must be non-empty strings."
        keys[version] = key
    if current_version not in keys:
        return keys, current_version, (
            f"Current HMAC key version {current_version} is not present in REDACTO_HMAC_KEYS."
        )
    return keys, current_version, None


def load_settings() -> Settings:
    base = Path.cwd()
    model_provider = os.environ.get("REDACTO_MODEL_PROVIDER", "none").strip().lower()
    hmac_keys, hmac_key_version, keyring_error = _load_keyring(
        os.environ.get("REDACTO_HMAC_KEY", "dev-only-synthetic-fixture-key")
    )
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
        hmac_keys=hmac_keys,
        hmac_key_version=hmac_key_version,
        embedding_provider=os.environ.get("REDACTO_EMBEDDING_PROVIDER", "local_hashing").strip().lower(),
        embedding_candidate_threshold=float(
            os.environ.get("REDACTO_EMBEDDING_CANDIDATE_THRESHOLD", "0.25")
        ),
        embedding_quarantine_threshold=float(
            os.environ.get("REDACTO_EMBEDDING_QUARANTINE_THRESHOLD", "0.30")
        ),
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
        keyring_error=keyring_error,
    )
