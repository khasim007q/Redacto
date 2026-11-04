import json
from dataclasses import replace
from pathlib import Path
import pytest
from redacto.cli import main
from redacto.config import load_settings
from redacto.connectivity import client_config, register
from redacto.errors import RedactoError
from redacto.profiles import setup_workspace


def profile(tmp_path):
    root = tmp_path / "ordinary notes"
    root.mkdir()
    return Path(setup_workspace(root, state_dir=tmp_path / "state")["profile"])


@pytest.mark.parametrize("client", ["generic", "claude-desktop", "claude-code", "cursor", "vscode"])
def test_client_exports_have_absolute_scope_and_client_specific_schema(tmp_path, client):
    path = profile(tmp_path)
    exported = client_config(profile=path, client=client)
    key = "servers" if client == "vscode" else "mcpServers"
    server = exported[key]["redacto"]
    assert Path(server["command"]).is_absolute()
    assert server["env"] == {"REDACTO_PROFILE": str(path)}
    assert server["args"] == ["-m", "redacto.mcp.stdio_server"]
    if client == "vscode":
        assert server["type"] == "stdio"


def test_registration_preserves_other_settings_backs_up_and_is_idempotent(tmp_path):
    path = tmp_path / "client.json"
    original = b'{"mcpServers":{"other":{"command":"existing"}},"theme":"dark"}'
    path.write_bytes(original)
    config = client_config(profile=profile(tmp_path), client="cursor")
    result = register(config, path)
    assert Path(result["backup"]).read_bytes() == original
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["theme"] == "dark" and saved["mcpServers"]["other"]["command"] == "existing"
    before = path.read_bytes()
    assert register(config, path)["changed"] is False and path.read_bytes() == before
    config["mcpServers"]["redacto"]["command"] = "changed"
    with pytest.raises(RedactoError) as error:
        register(config, path)
    assert error.value.code == "client_entry_conflict" and path.read_bytes() == before
    assert register(config, path, replace=True)["changed"]


@pytest.mark.parametrize("body", ['[]', '{"mcpServers":[]}', '{"a":1,"a":2}', '// jsonc\n{}'])
def test_invalid_client_files_are_never_overwritten(tmp_path, body):
    path = tmp_path / "client.json"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(RedactoError):
        register({"mcpServers": {"redacto": {"command": "python"}}}, path)
    assert path.read_text(encoding="utf-8") == body


def test_profile_works_after_subcommand_and_setup_can_register_once(tmp_path, capsys):
    root = tmp_path / "notes"
    root.mkdir()
    config = tmp_path / "mcp.json"
    assert main(["setup", "--workspace", str(root), "--state-dir", str(tmp_path / "state"),
                 "--client", "vscode", "--config", str(config)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["connection"]["changed"]
    assert main(["connect", "--profile", result["profile"], "--client", "vscode", "--config", str(config)]) == 0
    assert json.loads(capsys.readouterr().out)["changed"] is False


def test_profile_http_credentials_are_available_without_scope_overrides(tmp_path, monkeypatch):
    path = profile(tmp_path)
    monkeypatch.setenv("REDACTO_HTTP_TOKEN", "private-token-value")
    monkeypatch.setenv("REDACTO_HTTP_PORT", "9999")
    monkeypatch.setenv("REDACTO_WORKSPACE_ROOT", str(tmp_path / "wrong"))
    settings = load_settings(path)
    assert settings.http_token == "private-token-value" and settings.http_port == 9999
    assert settings.workspace_root.name == "ordinary notes"
    assert "private-token-value" not in json.dumps(settings.public_summary())


def test_managed_setup_releases_its_sqlite_file_before_returning(tmp_path):
    root = tmp_path / "notes"
    root.mkdir()
    result = setup_workspace(root, state_dir=tmp_path / "state", managed_memory=True)
    path = load_settings(result["profile"]).sqlite_store_path
    # Windows refuses deletion while an initializing SQLite connection is open.
    path.unlink()
    assert not path.exists()


def test_dotenv_can_select_a_profile_without_loading_ambient_scope(tmp_path, monkeypatch):
    import os
    path = profile(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("REDACTO_PROFILE", raising=False)
    (tmp_path / ".env").write_text(f"REDACTO_PROFILE={path}\nREDACTO_WORKSPACE_ROOT=/wrong\n", encoding="utf-8")
    assert load_settings().workspace_root.name == "ordinary notes"
    assert "REDACTO_PROFILE" not in os.environ


def test_unconfigured_runtime_has_no_implicit_sample_scope_or_default_key(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for name in ("REDACTO_PROFILE", "REDACTO_WORKSPACE_ROOT", "REDACTO_HMAC_KEY", "REDACTO_HMAC_KEYS"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(RedactoError) as error:
        load_settings()
    assert error.value.code == "configuration_required"
    monkeypatch.setenv("REDACTO_WORKSPACE_ROOT", str(tmp_path))
    with pytest.raises(RuntimeError):
        load_settings().current_hmac_key


def test_http_export_never_embeds_bearer_secrets_and_requires_remote_https():
    config = client_config(profile=None, client="vscode", url="https://mcp.example/mcp")
    assert config["servers"]["redacto"]["headers"]["Authorization"] == "Bearer ${env:REDACTO_HTTP_TOKEN}"
    for url in ("http://remote.example/mcp", "https://user:secret@mcp.example/mcp", "http://[broken"):
        with pytest.raises(RedactoError):
            client_config(profile=None, url=url)
    with pytest.raises(RedactoError):
        client_config(profile=None, client="claude-desktop", url="https://mcp.example/mcp")


def test_http_auth_origin_host_and_browser_preflight(tmp_path):
    from mcp.types import LATEST_PROTOCOL_VERSION
    from redacto.mcp.http_server import build_app
    from starlette.testclient import TestClient
    settings = replace(load_settings(profile(tmp_path)), http_token="test-token",
                       http_allowed_hosts=("mcp.example",), http_allowed_origins=("https://web.example",))
    app, _ = build_app(settings)
    headers = {"Authorization": "Bearer test-token", "Accept": "application/json, text/event-stream"}
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": LATEST_PROTOCOL_VERSION, "capabilities": {}, "clientInfo": {"name": "compatibility-test", "version": "1"}}}
    with TestClient(app, base_url="https://mcp.example") as client:
        assert client.post("/mcp", json=init).status_code == 401
        assert client.post("/mcp", json=init, headers={**headers, "Origin": "https://untrusted.example"}).status_code == 403
        assert client.post("/mcp", json=init, headers={**headers, "Host": "untrusted.example"}).status_code == 421
        preflight = client.options("/mcp", headers={"Origin": "https://web.example", "Access-Control-Request-Method": "POST",
                                                   "Access-Control-Request-Headers": "Authorization,MCP-Protocol-Version"})
        assert preflight.status_code == 200 and preflight.headers["access-control-allow-origin"] == "https://web.example"
        for _ in range(2):
            reply = client.post("/mcp", json=init, headers={**headers, "Origin": "https://web.example"})
            assert reply.status_code == 200 and reply.headers["content-type"].startswith("application/json")
            assert "mcp-session-id" not in reply.headers
