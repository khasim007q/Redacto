"""Packaging and plugin manifest checks."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_runtime_dependencies_include_http_clients_and_server():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = project["project"]["dependencies"]
    joined = " ".join(dependencies)
    assert "httpx" in joined
    assert "uvicorn" in joined
    assert "httpx" not in " ".join(project["project"]["optional-dependencies"]["dev"])


def test_plugin_manifests_are_valid_and_point_at_the_stdio_server():
    mcp = json.loads((ROOT / ".mcp.json").read_text(encoding="utf-8"))
    plugin = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    server = mcp["mcpServers"]["redacto"]
    assert server["args"][-2:] == ["-m", "redacto.mcp.stdio_server"]
    # cwd is not a supported stdio MCP field in Claude Code; every path is absolute.
    assert "cwd" not in server
    # Stores live in the writable data folder, never in the shipped fixtures, so an
    # apply cannot edit files inside the plugin.
    for key in ("REDACTO_WORKSPACE_ROOT", "REDACTO_SQLITE_PATH", "REDACTO_JSONL_PATH", "REDACTO_VECTOR_PATH"):
        assert server["env"][key].startswith("${CLAUDE_PLUGIN_DATA}/"), key
    assert server["env"]["REDACTO_DEMO_SEED_IF_MISSING"] == "true"
    assert server["env"]["REDACTO_DB_PATH"].startswith("${CLAUDE_PLUGIN_DATA}/")
    assert server["env"]["UV_PROJECT_ENVIRONMENT"].startswith("${CLAUDE_PLUGIN_DATA}/")
    assert plugin["name"] == "redacto"
    assert plugin["version"] == "0.1.0"
    assert (ROOT / "skills" / "redacto" / "SKILL.md").is_file()
    # The custom root-level manifest was replaced by the standard plugin layout.
    assert not (ROOT / "plugin.json").exists()


def test_ci_covers_linux_and_windows_and_runtime_install():
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "ubuntu-latest" in workflow
    assert "windows-latest" in workflow
    assert "pip install ." in workflow
    assert "python -m redacto --help" in workflow


def test_status_does_not_create_a_stray_database(tmp_path):
    from helpers import make_settings
    from redacto.engine import Engine

    settings = make_settings(tmp_path / "unconfigured")
    engine = Engine(settings)
    status = engine.status(transport="test")
    assert status["service"] == "redacto"
    assert not settings.db_path.exists()


def test_stdio_seeds_the_demo_workspace_only_when_missing(tmp_path, monkeypatch):
    from redacto.mcp import stdio_server

    workspace = tmp_path / "data" / "workspace"
    for key, value in {
        "REDACTO_WORKSPACE_ROOT": workspace,
        "REDACTO_DB_PATH": tmp_path / "data" / "redacto.sqlite3",
        "REDACTO_SQLITE_PATH": workspace / "agent_memory.sqlite3",
        "REDACTO_JSONL_PATH": workspace / "agent_events.jsonl",
        "REDACTO_VECTOR_PATH": workspace / "vector_chunks.json",
    }.items():
        monkeypatch.setenv(key, str(value))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("REDACTO_DEMO_SEED_IF_MISSING", "false")
    stdio_server._seed_demo_if_missing()
    assert not workspace.exists()
    monkeypatch.setenv("REDACTO_DEMO_SEED_IF_MISSING", "true")
    stdio_server._seed_demo_if_missing()
    assert (workspace / "acquisition-plan.md").is_file()
    (workspace / "acquisition-plan.md").unlink()
    stdio_server._seed_demo_if_missing()  # an existing workspace is never reseeded
    assert not (workspace / "acquisition-plan.md").exists()
