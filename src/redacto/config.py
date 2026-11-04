"""Runtime configuration for Redacto.

Everything is explicitly configured. Adapters fail closed when their scope is
missing, so a caller can never broaden the blast radius with a prompt.
"""

from __future__ import annotations

import json
import os
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from redacto.errors import HmacKeyError, RedactoError


def _env_path(name: str, default: str, env: Mapping[str, str] = os.environ) -> Path:
    return Path(env.get(name, default)).expanduser().resolve()


def _env_bool(name: str, default: bool, env: Mapping[str, str] = os.environ) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value not in {"1", "true", "yes", "on", "0", "false", "no", "off"}:
        raise RedactoError("invalid_configuration", f"{name} must be a boolean (true/false).")
    return value in {"1", "true", "yes", "on"}


def _env_list(name: str, env: Mapping[str, str] = os.environ) -> tuple[str, ...]:
    return tuple(part.strip() for part in env.get(name, "").split(",") if part.strip())


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
    max_record_bytes: int
    model_provider: str
    model_base_url: str | None
    model_name: str | None
    model_timeout_seconds: float
    http_host: str
    http_port: int
    http_token: str | None
    keyring_error: str | None = None
    extra: dict[str, str] = field(default_factory=dict)
    # Optional real stores. Each is only in scope when explicitly configured.
    chroma_path: Path | None = None
    chroma_collections: tuple[str, ...] = ()
    redis_url: str | None = None
    redis_key_patterns: tuple[str, ...] = ()
    # Opt-in: rebuild confirmed derivatives from their remaining allowed sources.
    regenerate_derivatives: bool = False
    embedding_model: str | None = None
    embedding_revision: str | None = None
    embedding_local_files_only: bool = False
    embedding_lexical_candidate_threshold: float = 0.25
    embedding_lexical_quarantine_threshold: float = 0.30
    enabled_stores: tuple[str, ...] | None = None
    http_allowed_hosts: tuple[str, ...] = ()
    http_allowed_origins: tuple[str, ...] = ()

    def __post_init__(self):
        if not 1 <= self.http_port <= 65535:
            raise RedactoError("invalid_configuration", "HTTP port must be between 1 and 65535.")
        known = {"filesystem", "sqlite_memory", "jsonl_logs", "vector_fixture", "chroma", "redis_cache"}
        if self.enabled_stores is not None and (
            not self.enabled_stores or set(self.enabled_stores) - known
            or len(set(self.enabled_stores)) != len(self.enabled_stores)
        ):
            raise RedactoError("invalid_configuration", "REDACTO_STORES must list distinct supported store IDs.")
        if self.embedding_provider not in {"local_hashing", "local-hashing", "hashing", "sentence_transformers", "sentence-transformers", "hybrid", "none", "disabled", ""}:
            raise RedactoError("invalid_configuration", "Unknown REDACTO_EMBEDDING_PROVIDER.")
        if self.embedding_provider in {"sentence_transformers", "sentence-transformers", "hybrid"}:
            if self.embedding_model and not self.embedding_revision:
                raise RedactoError("invalid_configuration", "A custom neural model requires REDACTO_EMBEDDING_REVISION.")
            if self.embedding_revision and not re.fullmatch(r"[a-fA-F0-9]{40}", self.embedding_revision):
                raise RedactoError("invalid_configuration", "REDACTO_EMBEDDING_REVISION must be an immutable commit hash.")
        if self.safety_mode not in {"review", "strict", "dry_run_only"}:
            raise RedactoError("invalid_configuration", "Unknown REDACTO_SAFETY_MODE.")
        if self.max_scan_records <= 0 or self.max_record_bytes <= 0:
            raise RedactoError("invalid_configuration", "Scan and record byte limits must be positive.")
        for threshold in (self.embedding_candidate_threshold, self.embedding_quarantine_threshold,
                          self.embedding_lexical_candidate_threshold, self.embedding_lexical_quarantine_threshold):
            if not math.isfinite(threshold) or not 0 <= threshold <= 1:
                raise RedactoError("invalid_configuration", "Embedding thresholds must be finite numbers between 0 and 1.")
        if not math.isfinite(self.model_timeout_seconds) or self.model_timeout_seconds <= 0:
            raise RedactoError("invalid_configuration", "Model timeout must be a positive finite number.")

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
            "max_record_bytes": self.max_record_bytes,
            "model_provider": self.model_provider,
            "model_configured": bool(self.model_base_url and self.model_name),
            "http_bind": f"{self.http_host}:{self.http_port}",
            "http_auth_required": bool(self.http_token),
            "hmac_key_version": self.hmac_key_version,
            "hmac_key_versions": sorted(self.hmac_keys),
            "keyring_error": self.keyring_error,
            "embedding_provider": self.embedding_provider,
            "embedding_model": self.embedding_model,
            "embedding_revision": self.embedding_revision,
            "embedding_local_files_only": self.embedding_local_files_only,
            "embedding_lexical_candidate_threshold": self.embedding_lexical_candidate_threshold,
            "embedding_lexical_quarantine_threshold": self.embedding_lexical_quarantine_threshold,
            "embedding_candidate_threshold": self.embedding_candidate_threshold,
            "embedding_quarantine_threshold": self.embedding_quarantine_threshold,
            "chroma": (
                {"path": str(self.chroma_path), "collections": list(self.chroma_collections)}
                if self.chroma_path
                else None
            ),
            # The URL may carry a password, so only its presence is reported.
            "redis": (
                {"configured": True, "key_patterns": list(self.redis_key_patterns)}
                if self.redis_url
                else None
            ),
            "regenerate_derivatives": self.regenerate_derivatives,
            "enabled_stores": list(self.enabled_stores) if self.enabled_stores is not None else None,
        }


def _load_keyring(default_key: str, env: Mapping[str, str] = os.environ) -> tuple[dict[int, str], int, str | None]:
    """Versioned key ring: old versions stay available during rotation."""
    try:
        current_version = int(env.get("REDACTO_HMAC_KEY_VERSION", "1"))
    except ValueError:
        return {}, 1, "REDACTO_HMAC_KEY_VERSION must be an integer."
    if current_version < 1:
        return {}, current_version, "REDACTO_HMAC_KEY_VERSION must be >= 1."

    raw = env.get("REDACTO_HMAC_KEYS")
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
        if str(version) != str(version_text):
            return {}, current_version, (
                "REDACTO_HMAC_KEYS versions must be canonical integers without leading "
                "zeros or signs."
            )
        if version < 1:
            return {}, current_version, "REDACTO_HMAC_KEYS versions must be >= 1."
        if version in keys:
            return {}, current_version, "REDACTO_HMAC_KEYS contains duplicate versions."
        if not isinstance(key, str) or not key:
            return {}, current_version, "REDACTO_HMAC_KEYS values must be non-empty strings."
        keys[version] = key
    if current_version not in keys:
        return keys, current_version, (
            f"Current HMAC key version {current_version} is not present in REDACTO_HMAC_KEYS."
        )
    return keys, current_version, None


def _load_dotenv(path: Path, env: dict[str, str]) -> None:
    """Load a simple KEY=VALUE .env without overriding real environment values."""
    if not path.is_file():
        return
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        value = value.strip()
        if value and value[0] in {"'", '"'} and value[-1] == value[0]:
            value = value[1:-1]
        if key and key not in env:
            env[key] = value


def load_settings(profile: str | Path | None = None) -> Settings:
    try:
        return _load_settings(profile)
    except (ValueError, OverflowError) as exc:
        raise RedactoError("invalid_configuration", "A numeric runtime setting is invalid.") from exc


def _load_settings(profile: str | Path | None = None) -> Settings:
    base = Path.cwd()
    env = dict(os.environ)
    profile = profile or env.get("REDACTO_PROFILE")
    if not profile:
        _load_dotenv(base / ".env", env)
        profile = env.get("REDACTO_PROFILE")
    if profile:
        from redacto.profiles import profile_environment

        env = profile_environment(Path(profile), transport_env=env)
    else:
        if not env.get("REDACTO_WORKSPACE_ROOT"):
            raise RedactoError("configuration_required", "Run redacto setup --workspace <folder>, then pass --profile or REDACTO_PROFILE.")
    model_provider = env.get("REDACTO_MODEL_PROVIDER", "none").strip().lower()
    embedding_provider = env.get("REDACTO_EMBEDDING_PROVIDER", "local_hashing").strip().lower()
    neural = embedding_provider in {"sentence_transformers", "sentence-transformers", "hybrid"}
    hmac_keys, hmac_key_version, keyring_error = _load_keyring(
        env.get("REDACTO_HMAC_KEY", ""), env
    )
    return Settings(
        db_path=_env_path("REDACTO_DB_PATH", str(base / "var" / "redacto.sqlite3"), env),
        workspace_root=_env_path("REDACTO_WORKSPACE_ROOT", str(base), env),
        sqlite_store_path=_env_path(
            "REDACTO_SQLITE_PATH", str(base / "var" / "memory.sqlite3"), env
        ),
        jsonl_log_path=_env_path(
            "REDACTO_JSONL_PATH", str(base / "var" / "events.jsonl"), env
        ),
        vector_fixture_path=_env_path(
            "REDACTO_VECTOR_PATH", str(base / "var" / "chunks.json"), env
        ),
        hmac_keys=hmac_keys,
        hmac_key_version=hmac_key_version,
        embedding_provider=embedding_provider,
        embedding_model=env.get("REDACTO_EMBEDDING_MODEL") or None,
        embedding_revision=env.get("REDACTO_EMBEDDING_REVISION") or None,
        embedding_local_files_only=_env_bool("REDACTO_EMBEDDING_LOCAL_FILES_ONLY", False, env),
        embedding_lexical_candidate_threshold=float(env.get("REDACTO_EMBEDDING_LEXICAL_CANDIDATE_THRESHOLD", "0.25")),
        embedding_lexical_quarantine_threshold=float(env.get("REDACTO_EMBEDDING_LEXICAL_QUARANTINE_THRESHOLD", "0.30")),
        embedding_candidate_threshold=float(
            env.get("REDACTO_EMBEDDING_CANDIDATE_THRESHOLD", "0.55" if neural else "0.25")
        ),
        embedding_quarantine_threshold=float(
            env.get("REDACTO_EMBEDDING_QUARANTINE_THRESHOLD", "0.60" if neural else "0.30")
        ),
        safety_mode=env.get("REDACTO_SAFETY_MODE", "review"),
        dry_run=_env_bool("REDACTO_DRY_RUN", True, env),
        max_scan_records=int(env.get("REDACTO_MAX_SCAN_RECORDS", "500")),
        max_record_bytes=int(env.get("REDACTO_MAX_RECORD_BYTES", "1000000")),
        model_provider=model_provider,
        model_base_url=env.get("REDACTO_MODEL_BASE_URL") or None,
        model_name=env.get("REDACTO_MODEL_NAME") or None,
        model_timeout_seconds=float(env.get("REDACTO_MODEL_TIMEOUT", "10")),
        http_host=env.get("REDACTO_HTTP_HOST", "127.0.0.1"),
        http_port=int(env.get("REDACTO_HTTP_PORT", "8765")),
        http_token=env.get("REDACTO_HTTP_TOKEN") or None,
        keyring_error=keyring_error,
        chroma_path=(
            Path(env["REDACTO_CHROMA_PATH"]).expanduser().resolve()
            if env.get("REDACTO_CHROMA_PATH")
            else None
        ),
        chroma_collections=_env_list("REDACTO_CHROMA_COLLECTIONS", env),
        redis_url=env.get("REDACTO_REDIS_URL") or None,
        redis_key_patterns=_env_list("REDACTO_REDIS_KEY_PATTERNS", env),
        enabled_stores=(_env_list("REDACTO_STORES", env) if "REDACTO_STORES" in env else tuple(
            ["filesystem"] + [store for setting, store in (
                ("REDACTO_SQLITE_PATH", "sqlite_memory"), ("REDACTO_JSONL_PATH", "jsonl_logs"),
                ("REDACTO_VECTOR_PATH", "vector_fixture"), ("REDACTO_CHROMA_PATH", "chroma"),
                ("REDACTO_REDIS_URL", "redis_cache")) if env.get(setting)])),
        http_allowed_hosts=_env_list("REDACTO_HTTP_ALLOWED_HOSTS", env),
        http_allowed_origins=_env_list("REDACTO_HTTP_ALLOWED_ORIGINS", env),
        regenerate_derivatives=_env_bool("REDACTO_REGENERATE", False, env),
    )
