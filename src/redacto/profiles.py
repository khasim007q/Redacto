"""Portable workspace profiles shared by the CLI, MCP server and application SDK."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

from redacto.errors import RedactoError
from redacto.locking import is_lock_file, resource_lock

_OPTIONS = {
    "REDACTO_EMBEDDING_PROVIDER", "REDACTO_EMBEDDING_MODEL", "REDACTO_EMBEDDING_REVISION",
    "REDACTO_EMBEDDING_LOCAL_FILES_ONLY", "REDACTO_EMBEDDING_CANDIDATE_THRESHOLD",
    "REDACTO_EMBEDDING_QUARANTINE_THRESHOLD", "REDACTO_EMBEDDING_LEXICAL_CANDIDATE_THRESHOLD",
    "REDACTO_EMBEDDING_LEXICAL_QUARANTINE_THRESHOLD", "REDACTO_MAX_SCAN_RECORDS",
    "REDACTO_MAX_RECORD_BYTES", "REDACTO_REGENERATE",
}


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_object)
        if not isinstance(value, dict):
            raise ValueError("expected object")
        return value
    except (OSError, UnicodeError, ValueError) as exc:
        raise RedactoError("invalid_profile", "Cannot read a valid workspace profile or keyring.") from exc


def _absolute(value) -> Path:
    if not isinstance(value, str) or not value or not Path(value).is_absolute():
        raise RedactoError("invalid_profile", "Workspace and state paths must be absolute.")
    return Path(value).expanduser().resolve()


def profile_environment(path: Path, *, transport_env: dict[str, str] | None = None) -> dict[str, str]:
    """Resolve a complete scope without inheriting cwd .env or ambient overrides."""
    profile = _read_json(path)
    required = {"version", "workspace_root", "state_dir", "mode", "options"}
    if set(profile) != required or type(profile["version"]) is not int or profile["version"] != 1:
        raise RedactoError("invalid_profile", "Unsupported workspace profile schema.")
    root, state = _absolute(profile["workspace_root"]), _absolute(profile["state_dir"])
    if state == root or state.is_relative_to(root):
        raise RedactoError("invalid_profile", "Private state must be outside the scanned workspace.")
    mode, options = profile["mode"], profile["options"]
    if not isinstance(mode, str) or mode not in {"files", "managed"} or not isinstance(options, dict):
        raise RedactoError("invalid_profile", "Unsupported workspace profile mode or options.")
    if set(options) - _OPTIONS or any(not isinstance(value, str) for value in options.values()):
        raise RedactoError("invalid_profile", "Profile options contain unknown settings or invalid values.")
    keys = _read_json(state / "keys.json")
    if set(keys) != {"current_version", "keys"} or type(keys["current_version"]) is not int:
        raise RedactoError("invalid_profile", "Invalid profile keyring schema.")
    if not isinstance(keys["keys"], dict) or any(
        not isinstance(key, str) or len(key) < 32 for key in keys["keys"].values()
    ):
        raise RedactoError("invalid_profile", "Profile keys must contain at least 32 characters.")
    stores = ["filesystem"]
    store_root = state / "stores"
    if mode == "managed":
        stores += ["sqlite_memory", "jsonl_logs"]
    transport_env = os.environ if transport_env is None else transport_env
    transport = {name: transport_env[name] for name in (
        "REDACTO_HTTP_HOST", "REDACTO_HTTP_PORT", "REDACTO_HTTP_TOKEN",
        "REDACTO_HTTP_ALLOWED_HOSTS", "REDACTO_HTTP_ALLOWED_ORIGINS") if name in transport_env}
    return {
        "REDACTO_WORKSPACE_ROOT": str(root),
        "REDACTO_DB_PATH": str(state / "redacto.sqlite3"),
        "REDACTO_SQLITE_PATH": str(store_root / "agent_memory.sqlite3"),
        "REDACTO_JSONL_PATH": str(store_root / "agent_events.jsonl"),
        "REDACTO_VECTOR_PATH": str(store_root / "vector_chunks.json"),
        "REDACTO_STORES": ",".join(stores),
        "REDACTO_HMAC_KEYS": json.dumps(keys["keys"]),
        "REDACTO_HMAC_KEY_VERSION": str(keys["current_version"]),
        "REDACTO_MODEL_PROVIDER": "none",
        "REDACTO_SAFETY_MODE": "review",
        "REDACTO_DRY_RUN": "true",
        **options,
        **transport,
    }


def _write_json(path: Path, value: dict) -> None:
    temp = path.with_suffix(path.suffix + ".tmp")
    try:
        with temp.open("w", encoding="utf-8") as handle:
            if os.name != "nt":
                os.chmod(temp, 0o600)
            json.dump(value, handle, indent=2)
            handle.write("\n")
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def setup_workspace(workspace: Path, *, state_dir: Path | None = None,
                    managed_memory: bool = False) -> dict:
    """Initialize only explicitly owned state; never seed ordinary user folders."""
    from redacto.config import load_settings

    root = workspace.expanduser().resolve()
    digest = hashlib.sha256(os.path.normcase(str(root)).encode()).hexdigest()[:16]
    state = (state_dir or Path.home() / ".redacto" / "workspaces" / digest).expanduser().resolve()
    if state == root or state.is_relative_to(root):
        raise RedactoError("invalid_configuration", "Choose a private state directory outside the scanned folder.")
    mode = "managed" if managed_memory else "files"
    profile = {"version": 1, "workspace_root": str(root), "state_dir": str(state), "mode": mode, "options": {}}
    path = state / "profile.json"
    try:
        with resource_lock(path):
            if path.exists():
                old = _read_json(path)
                if any(old.get(field) != profile[field] for field in ("workspace_root", "state_dir", "mode")):
                    raise RedactoError("profile_conflict", "This state directory belongs to a different scope or mode.")
                load_settings(path).current_hmac_key  # Validate without changing existing keys or stores.
            else:
                ownership = state / "workspace-owner.json"
                # Windows cannot read the byte currently locked by this process.
                own_lock = ".redacto-lock-" + hashlib.sha256(os.path.normcase(str(path)).encode()).hexdigest()[:24]
                existing = [entry for entry in state.iterdir()
                            if entry.name != own_lock and not is_lock_file(entry)]
                if existing and not ownership.exists():
                    raise RedactoError("state_not_empty", "Choose a new private state directory; existing unowned data is not reused.")
                if ownership.exists() and _read_json(ownership) != profile:
                    raise RedactoError("profile_conflict", "Incomplete setup belongs to a different workspace or mode.")
                if not root.is_dir():
                    raise RedactoError("invalid_workspace", "The workspace folder must already exist.")
                state.mkdir(parents=True, exist_ok=True)
                if os.name != "nt":
                    os.chmod(state, 0o700)
                if not ownership.exists():
                    _write_json(ownership, profile)
                keys_path = state / "keys.json"
                if not keys_path.exists():
                    _write_json(keys_path, {"current_version": 1, "keys": {"1": secrets.token_hex(32)}})
                # Prepare using a temporary profile; publish only after initialization succeeds.
                pending = state / "setup-profile.json"
                _write_json(pending, profile)
                try:
                    settings = load_settings(pending)
                    settings.current_hmac_key
                    if managed_memory:
                        stores = state / "stores"
                        stores.mkdir(exist_ok=True)
                        with closing(sqlite3.connect(settings.sqlite_store_path)) as conn, conn:
                            for table in ("memories", "response_cache"):
                                conn.execute(f"CREATE TABLE IF NOT EXISTS {table} "
                                             "(id TEXT PRIMARY KEY, content TEXT, created_at TEXT, sensitivity TEXT)")
                        settings.jsonl_log_path.touch(exist_ok=True)
                    os.replace(pending, path)
                finally:
                    pending.unlink(missing_ok=True)
    except OSError as exc:
        raise RedactoError("setup_failed", "Cannot initialize the workspace state directory.") from exc
    settings = load_settings(path)
    return {
        "ok": True, "profile": str(path), "workspace_root": str(root), "mode": mode,
        "stores": list(settings.enabled_stores or ()),
        "mcp_config": {"mcpServers": {"redacto": {
            "command": sys.executable,
            "args": ["-m", "redacto.mcp.stdio_server"],
            "env": {"REDACTO_PROFILE": str(path)},
        }}},
        "next": "Paste mcp_config into your MCP client settings, then restart the client. Use --profile for operator commands.",
    }
