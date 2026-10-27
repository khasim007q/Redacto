"""Operator safety: seed/demo never destroy a workspace, CLI and MCP share defaults."""

from __future__ import annotations

import sqlite3

import pytest

from helpers import seeded_settings
from redacto.engine import Engine
from redacto.errors import RedactoError
from redacto.fixtures import SOURCE_ID, seed_workspace


def _all_bytes(settings) -> bytes:
    data = b""
    for path in settings.workspace_root.rglob("*"):
        if path.is_file():
            data += path.read_bytes()
    return data


# ------------------------------------------------------------------ seed guard
def test_seed_refuses_a_workspace_with_user_files(tmp_path):
    settings = seeded_settings(tmp_path)
    (settings.workspace_root / "my-notes.md").write_text("mine", encoding="utf-8")
    with pytest.raises(RedactoError) as excinfo:
        seed_workspace(settings)
    assert excinfo.value.code == "seed_would_destroy_data"
    assert (settings.workspace_root / "my-notes.md").read_text(encoding="utf-8") == "mine"


def test_seed_refuses_a_store_with_extra_tables(tmp_path):
    settings = seeded_settings(tmp_path)
    conn = sqlite3.connect(settings.sqlite_store_path)
    conn.execute("CREATE TABLE chat_history (id TEXT)")
    conn.commit()
    conn.close()
    with pytest.raises(RedactoError):
        seed_workspace(settings)


def test_seed_honours_the_configured_sqlite_path(tmp_path):
    custom = tmp_path / "elsewhere" / "memory.sqlite3"
    custom.parent.mkdir()
    settings = seeded_settings(tmp_path, sqlite_store_path=custom)
    assert custom.is_file()
    assert Engine(settings).trace(source_id=SOURCE_ID)["confirmed_descendants"]


def test_seed_does_not_write_outside_the_graph_dir(tmp_path):
    settings = seeded_settings(tmp_path)
    assert not (settings.workspace_root.parent / "expected_results.json").exists() or (
        settings.workspace_root.parent == settings.db_path.parent
    )
    assert (settings.db_path.parent / "expected_results.json").is_file()


def test_demo_uses_an_isolated_workspace_by_default(tmp_path, monkeypatch, capsys):
    from redacto import cli

    settings = seeded_settings(tmp_path)
    (settings.workspace_root / "my-notes.md").write_text("mine", encoding="utf-8")
    before = _all_bytes(settings)
    monkeypatch.setattr(cli, "load_settings", lambda: settings)
    args = cli.build_parser().parse_args(["demo"])
    demo_settings = cli._demo_settings(args)
    assert demo_settings.workspace_root != settings.workspace_root
    assert demo_settings.db_path != settings.db_path
    assert _all_bytes(settings) == before


# ----------------------------------------------------------------- CLI + env
def _cli_flow(tmp_path, monkeypatch, *apply_flags, env_dry_run: bool):
    from dataclasses import replace

    from redacto import cli

    settings = replace(seeded_settings(tmp_path), dry_run=env_dry_run)
    monkeypatch.setattr(cli, "load_settings", lambda: settings)
    engine = Engine(settings)
    plan = engine.plan(target_id=SOURCE_ID)
    approval = engine.approve_plan(plan_id=plan["plan_id"], approval_ref="cli-operator")
    args = cli.build_parser().parse_args(
        [
            "apply",
            "--plan",
            plan["plan_id"],
            "--version",
            str(plan["plan_version"]),
            "--ref",
            "cli-operator",
            "--token",
            approval["confirmation_token"],
            *apply_flags,
        ]
    )
    args.func(args)
    return settings


def test_cli_apply_honours_redacto_dry_run(tmp_path, monkeypatch):
    settings = _cli_flow(tmp_path, monkeypatch, env_dry_run=True)
    assert (settings.workspace_root / "acquisition-plan.md").exists()


@pytest.mark.parametrize("flag", ["--no-dry-run", "--execute"])
def test_cli_apply_explicit_real_run_overrides_the_env(tmp_path, monkeypatch, flag):
    settings = _cli_flow(tmp_path, monkeypatch, flag, env_dry_run=True)
    assert not (settings.workspace_root / "acquisition-plan.md").exists()


def test_cli_apply_explicit_dry_run(tmp_path, monkeypatch):
    settings = _cli_flow(tmp_path, monkeypatch, "--dry-run", env_dry_run=False)
    assert (settings.workspace_root / "acquisition-plan.md").exists()


def test_dotenv_is_loaded_without_overriding_the_environment(tmp_path, monkeypatch):
    from redacto.config import load_settings

    (tmp_path / ".env").write_text(
        "# comment\nREDACTO_SAFETY_MODE=dry_run_only\nREDACTO_HTTP_PORT='9999'\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("REDACTO_SAFETY_MODE", raising=False)
    monkeypatch.setenv("REDACTO_HTTP_PORT", "8000")
    settings = load_settings()
    assert settings.safety_mode == "dry_run_only"
    assert settings.http_port == 8000
