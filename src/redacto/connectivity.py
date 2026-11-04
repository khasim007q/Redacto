"""Client-specific MCP exports and conservative configuration registration."""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from redacto.adapters.base import AdapterError, checked_replace
from redacto.errors import RedactoError
from redacto.locking import resource_lock
from redacto.profiles import _object

CLIENTS = ("generic", "claude-desktop", "claude-code", "cursor", "vscode")


def client_config(*, profile: Path | None, client: str = "generic", name: str = "redacto",
                  url: str | None = None, token_env: str = "REDACTO_HTTP_TOKEN") -> dict:
    if client not in CLIENTS or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", name):
        raise RedactoError("invalid_client", "Choose a supported client and a short server name.")
    if url:
        try:
            parsed = urlsplit(url)
            parsed.port
        except ValueError as exc:
            raise RedactoError("invalid_url", "Invalid MCP endpoint URL.") from exc
        if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise RedactoError("invalid_url", "Use an HTTP(S) MCP endpoint without embedded credentials or a fragment.")
        if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise RedactoError("invalid_url", "Remote MCP endpoints require HTTPS.")
        if client == "claude-desktop":
            raise RedactoError("unsupported_client_transport", "Use local stdio for Desktop JSON configuration; remote connectors use the client's connector UI and authentication requirements.")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token_env):
            raise RedactoError("invalid_configuration", "Name an environment variable for the HTTP bearer token.")
        variable = "${" + token_env + "}" if client == "claude-code" else "${env:" + token_env + "}"
        server = {"url": url, "headers": {"Authorization": "Bearer " + variable}}
        if client != "cursor":
            server["type"] = "http"
    else:
        if profile is None:
            raise RedactoError("configuration_required", "Pass --profile for a local MCP connection.")
        from redacto.config import load_settings

        load_settings(profile).current_hmac_key
        server = {"command": sys.executable, "args": ["-m", "redacto.mcp.stdio_server"],
                  "env": {"REDACTO_PROFILE": str(profile.expanduser().resolve())}}
        if client == "vscode":
            server["type"] = "stdio"
    return {"servers" if client == "vscode" else "mcpServers": {name: server}}


def default_config_path(client: str, workspace: Path | None) -> Path:
    if client == "claude-desktop":
        if sys.platform == "win32":
            folder = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")) / "Claude"
        elif sys.platform == "darwin":
            folder = Path.home() / "Library" / "Application Support" / "Claude"
        else:
            folder = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "Claude"
        return folder / "claude_desktop_config.json"
    if client == "cursor":
        return Path.home() / ".cursor" / "mcp.json"
    if workspace is not None and client == "claude-code":
        return workspace / ".mcp.json"
    if workspace is not None and client == "vscode":
        return workspace / ".vscode" / "mcp.json"
    raise RedactoError("configuration_required", "Use --config for this client or a local workspace profile.")


def register(config: dict, path: Path, *, replace: bool = False) -> dict:
    """Merge one entry, back up original bytes, and reject concurrent rewrites."""
    path = path.expanduser().absolute()
    try:
        if path.is_symlink() or (path.exists() and path.stat().st_nlink > 1):
            raise RedactoError("unsafe_configuration_path", "Client configuration must be a regular unaliased file.")
        with resource_lock(path):
            original = path.read_bytes() if path.exists() else None
            if original is not None and len(original) > 1_000_000:
                raise RedactoError("client_configuration_invalid", "Client configuration exceeds the edit size limit.")
            try:
                existing = json.loads(original.decode("utf-8-sig"), object_pairs_hook=_object) if original is not None else {}
                if not isinstance(existing, dict):
                    raise ValueError()
            except (ValueError, UnicodeError) as exc:
                raise RedactoError("client_configuration_invalid", "Client configuration must be a JSON object without duplicate keys. For JSONC, print the entry and merge it in your editor.") from exc
            section, entry = next(iter(config.items()))
            name, server = next(iter(entry.items()))
            servers = existing.setdefault(section, {})
            if not isinstance(servers, dict):
                raise RedactoError("client_configuration_invalid", "The client's server section must be an object.")
            if servers.get(name) == server:
                return {"ok": True, "changed": False, "config_path": str(path)}
            if name in servers and not replace:
                raise RedactoError("client_entry_conflict", "A different server uses this name. Choose --name or explicitly --replace.")
            servers[name] = server
            backup = None
            if original is not None:
                fd, filename = tempfile.mkstemp(prefix=path.name + ".", suffix=".bak", dir=path.parent)
                with os.fdopen(fd, "wb") as handle:
                    handle.write(original)
                backup = filename
            fd, filename = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(existing, handle, indent=2, ensure_ascii=False)
                    handle.write("\n")
                checked_replace(filename, path, lambda: (path.read_bytes() if path.exists() else None) == original)
            finally:
                Path(filename).unlink(missing_ok=True)
            return {"ok": True, "changed": True, "config_path": str(path), "backup": backup,
                    "next": "Restart or reconnect the MCP client. Its own trust prompts still apply."}
    except AdapterError as exc:
        raise RedactoError("client_configuration_changed", "Client configuration changed during registration; inspect it and retry.") from exc
    except OSError as exc:
        raise RedactoError("client_configuration_write_failed", "Cannot read or update the selected client configuration.") from exc
