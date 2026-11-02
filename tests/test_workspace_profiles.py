"""Ordinary-folder setup, strict scope loading and guarded application integration."""

import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from conftest import approve_and_apply
from redacto.adapters.registry import build_adapters
from redacto.cli import main
from redacto.config import load_settings
from redacto.errors import RedactoError
from redacto.profiles import setup_workspace
from redacto.workspace import WorkspaceClient

PRIVATE = 'The private flight named "Azure Finch" launches after confidential clearance on Tuesday morning.'
PUBLIC = "The public support guide explains log rotation and backup recovery for all operators."


def _setup(tmp_path, **kwargs):
    root = tmp_path / "ordinary folder"
    root.mkdir()
    return setup_workspace(root, state_dir=tmp_path / "private state", **kwargs)


def test_files_only_setup_is_idempotent_and_never_seeds_user_content(tmp_path):
    result = _setup(tmp_path)
    root, profile = Path(result["workspace_root"]), Path(result["profile"])
    keys = (profile.parent / "keys.json").read_bytes()
    (root / "my-notes.txt").write_text("existing user content", encoding="utf-8")
    assert setup_workspace(root, state_dir=profile.parent) == result
    assert (profile.parent / "keys.json").read_bytes() == keys
    assert sorted(p.name for p in root.iterdir()) == ["my-notes.txt"]
    settings = load_settings(profile)
    assert set(build_adapters(settings)) == {"filesystem"}
    assert len(settings.current_hmac_key) == 64
    assert settings.current_hmac_key not in json.dumps(result)
    assert not (profile.parent / "redacto.sqlite3").exists()
    assert result["mcp_config"]["mcpServers"]["redacto"]["env"] == {"REDACTO_PROFILE": str(profile)}


def test_profile_ignores_launch_directory_dotenv_and_ambient_scope(tmp_path, monkeypatch):
    result = _setup(tmp_path)
    launch = tmp_path / "elsewhere"
    launch.mkdir()
    (launch / ".env").write_text("REDACTO_WORKSPACE_ROOT=/wrong\nREDACTO_HMAC_KEY=wrong\n", encoding="utf-8")
    monkeypatch.chdir(launch)
    monkeypatch.setenv("REDACTO_WORKSPACE_ROOT", "/also-wrong")
    monkeypatch.setenv("REDACTO_HMAC_KEY", "ambient-wrong")
    monkeypatch.setenv("REDACTO_STORES", "redis_cache")
    monkeypatch.setenv("REDACTO_PROFILE", result["profile"])
    settings = load_settings()
    assert settings.workspace_root == Path(result["workspace_root"])
    assert settings.current_hmac_key not in {"wrong", "ambient-wrong"}
    assert settings.enabled_stores == ("filesystem",)
    assert __import__("os").environ["REDACTO_WORKSPACE_ROOT"] == "/also-wrong"


@pytest.mark.parametrize("change", [
    lambda p: p.update(version=2),
    lambda p: p.update(workspace_root="relative"),
    lambda p: p.update(state_dir=p["workspace_root"]),
    lambda p: p.update(options={"REDACTO_HMAC_KEY": "injected"}),
    lambda p: p.update(options={"REDACTO_MAX_SCAN_RECORDS": 10}),
    lambda p: p.update(unrecognized=True),
    lambda p: p.update(mode=[]),
])
def test_malformed_profiles_fail_closed(tmp_path, change):
    result = _setup(tmp_path)
    path = Path(result["profile"])
    profile = json.loads(path.read_text(encoding="utf-8"))
    change(profile)
    path.write_text(json.dumps(profile), encoding="utf-8")
    with pytest.raises(RedactoError, match="profile|Profile|paths|state"):
        load_settings(path)


def test_missing_keyring_never_falls_back_to_development_key(tmp_path):
    result = _setup(tmp_path)
    path = Path(result["profile"])
    (path.parent / "keys.json").unlink()
    with pytest.raises(RedactoError) as error:
        load_settings(path)
    assert error.value.code == "invalid_profile"


def test_setup_refuses_conflicting_scope_and_state_inside_workspace(tmp_path):
    result = _setup(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    with pytest.raises(RedactoError) as error:
        setup_workspace(other, state_dir=Path(result["profile"]).parent)
    assert error.value.code == "profile_conflict"
    with pytest.raises(RedactoError):
        setup_workspace(other, state_dir=other / "private")


def test_setup_does_not_adopt_unowned_state_and_profile_launch_never_autoseeds(tmp_path, monkeypatch):
    from redacto.mcp.stdio_server import _seed_demo_if_missing

    user = tmp_path / "user"
    user.mkdir()
    state = tmp_path / "foreign-state"
    state.mkdir()
    (state / "redacto.sqlite3").write_bytes(b"somebody else's state")
    with pytest.raises(RedactoError) as error:
        setup_workspace(user, state_dir=state)
    assert error.value.code == "state_not_empty"
    result = _setup(tmp_path)
    Path(result["workspace_root"]).rmdir()
    monkeypatch.setenv("REDACTO_PROFILE", result["profile"])
    monkeypatch.setenv("REDACTO_DEMO_SEED_IF_MISSING", "true")
    _seed_demo_if_missing()
    assert not Path(result["workspace_root"]).exists()


def test_demo_is_explicit_and_refuses_nonempty_user_folders(tmp_path):
    root = tmp_path / "demo"
    result = setup_workspace(root, state_dir=tmp_path / "demo-state", demo=True)
    assert (root / "acquisition-plan.md").is_file()
    assert len(build_adapters(load_settings(result["profile"]))) == 4
    user = tmp_path / "user"
    user.mkdir()
    (user / "mine.txt").write_text("my file", encoding="utf-8")
    with pytest.raises(RedactoError) as error:
        setup_workspace(user, state_dir=tmp_path / "other-state", demo=True)
    assert error.value.code == "workspace_not_empty"
    assert (user / "mine.txt").read_text(encoding="utf-8") == "my file"


def test_doctor_and_enabled_store_loss_are_honest(tmp_path, capsys):
    result = _setup(tmp_path, managed_memory=True)
    profile = result["profile"]
    assert main(["--profile", profile, "doctor"]) == 0
    assert json.loads(capsys.readouterr().out)["ok"]
    settings = load_settings(profile)
    settings.jsonl_log_path.unlink()
    assert main(["--profile", profile, "doctor"]) == 2
    checks = json.loads(capsys.readouterr().out)["stores"]
    assert next(c for c in checks if c["store_id"] == "jsonl_logs")["reachable"] is False
    # Rerunning setup must not silently recreate a lost configured store.
    setup_workspace(settings.workspace_root, state_dir=Path(profile).parent, managed_memory=True)
    assert not settings.jsonl_log_path.exists()
    slots = build_adapters(replace(settings, enabled_stores=("redis_cache",)))
    assert slots["redis_cache"].adapter is None
    assert not (Path(profile).parent / "redacto.sqlite3").exists()


def test_doctor_fails_if_a_required_old_tombstone_key_is_removed(tmp_path, capsys):
    result = _setup(tmp_path)
    client = WorkspaceClient(result["profile"])
    client.write_document("private.md", PRIVATE)
    plan = client.engine.plan(target_id="fs:private.md")
    approve_and_apply(client.engine, plan)
    keys = Path(result["profile"]).parent / "keys.json"
    keys.write_text(json.dumps({"current_version": 2, "keys": {"2": "new-synthetic-key-" * 4}}), encoding="utf-8")
    assert main(["--profile", result["profile"], "doctor"]) == 2
    status = json.loads(capsys.readouterr().out)["status"]
    assert status["revocation"]["missing_key_versions"] == [1]


def test_sdk_revocation_preserves_mixed_memory_and_guards_every_write_store(tmp_path):
    result = _setup(tmp_path, managed_memory=True)
    client = WorkspaceClient(result["profile"])
    client.write_document("private.md", PRIVATE)
    client.write_document("public.md", PUBLIC)
    client.remember("mixed", PRIVATE + "\n" + PUBLIC, sources=["fs:private.md", "fs:public.md"])
    client.cache("private-answer", PRIVATE, sources=["fs:private.md"])
    client.append_event("private-answer", PRIVATE, sources=["fs:private.md"])
    engine = client.engine
    plan = engine.plan(target_id="fs:private.md")
    assert all(slot.adapter is not None for slot in engine.adapters().values())
    mixed = next(i for i in plan["items"] if i["record_id"] == "mem:mixed")
    assert mixed["proposed_action"] == "REVIEW_REQUIRED"
    reviewed = engine.review_plan_item(plan_id=plan["plan_id"], item_id=mixed["item_id"],
                                       decision="approved", reviewer="operator", action="redact")
    applied = approve_and_apply(engine, reviewed)
    assert applied["counts"]["failed"] == 0
    remaining = client.read("mem:mixed")
    assert PUBLIC in remaining.core_content and PRIVATE not in remaining.content
    assert client.read("fs:public.md").content == PUBLIC
    for write in (lambda: client.write_document("replay.md", PRIVATE),
                  lambda: client.remember("replay", PRIVATE),
                  lambda: client.cache("replay", PRIVATE),
                  lambda: client.append_event("replay", PRIVATE)):
        assert not write()["results"][0].get("admitted")
    assert not (engine.settings.workspace_root / "replay.md").exists()
    receipt = engine.verify(request_id=plan["request_id"])
    assert receipt["counts"]["records_redacted"] == 1
    assert receipt["counts"]["records_removed"] == 3


def test_sdk_checks_dependencies_before_writing_and_filters_direct_bypass(tmp_path):
    result = _setup(tmp_path, managed_memory=True)
    client = WorkspaceClient(result["profile"])
    client.write_document("private.md", PRIVATE)
    with pytest.raises(RedactoError):
        client.remember("bad", PUBLIC, sources=["fs:missing.md"])
    with sqlite3.connect(client.engine.settings.sqlite_store_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0] == 0
    plan = client.engine.plan(target_id="fs:private.md")
    approve_and_apply(client.engine, plan)
    with pytest.raises(RedactoError):
        client.remember("bad", PUBLIC, sources=["fs:private.md"])
    # A writer deliberately bypassing the SDK can store a replay; reads refuse it.
    bypass = client.engine.settings.workspace_root / "bypass.md"
    bypass.write_text(PRIVATE, encoding="utf-8")
    with pytest.raises(RedactoError) as error:
        client.read("fs:bypass.md")
    assert error.value.code == "record_restricted"
    assert client.engine.reingest_stores()["counts"]["blocked"] >= 1


def test_sdk_reports_partial_persistence_honestly(tmp_path, monkeypatch):
    client = WorkspaceClient(_setup(tmp_path, managed_memory=True)["profile"])
    client.write_document("public.md", PUBLIC)
    def fail(**kwargs):
        raise sqlite3.OperationalError("simulated graph unavailable")
    monkeypatch.setattr(client.engine, "record_lineage", fail)
    with pytest.raises(RedactoError) as error:
        client.remember("output", PUBLIC, sources=["fs:public.md"])
    assert error.value.code == "integration_write_incomplete"
    assert error.value.details["written_to_store"] is True
    assert client.read("mem:output").core_content == PUBLIC


def test_invalid_numeric_options_are_structured_errors_and_duplicate_events_are_refused(tmp_path):
    result = _setup(tmp_path, managed_memory=True)
    client = WorkspaceClient(result["profile"])
    client.append_event("one", PUBLIC)
    with pytest.raises(RedactoError) as error:
        client.append_event("one", "Changed event")
    assert error.value.code == "record_exists"
    assert client.read("log:one").core_content == PUBLIC
    path = Path(result["profile"])
    profile = json.loads(path.read_text(encoding="utf-8"))
    profile["options"]["REDACTO_MAX_SCAN_RECORDS"] = "not a number"
    path.write_text(json.dumps(profile), encoding="utf-8")
    with pytest.raises(RedactoError) as error:
        load_settings(path)
    assert error.value.code == "invalid_configuration"


@pytest.mark.parametrize("name", ["../escape.md", "C:\\escape.md", "/escape.md"])
def test_sdk_refuses_document_path_escape(tmp_path, name):
    client = WorkspaceClient(_setup(tmp_path)["profile"])
    with pytest.raises(RedactoError) as error:
        client.write_document(name, PUBLIC)
    assert error.value.code == "invalid_locator"
