"""Regressions from the Windows CI failure and the lease/verify/file audit.

Pins: cross-platform liveness without os.kill on Windows, stuck-lease recovery,
no TTL theft of a live apply, in-place file edits, config-style secret detection
at verify, and concurrent appends during a log rewrite.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from pathlib import Path

import pytest

from conftest import approve_and_apply
from helpers import seeded_settings
from redacto.adapters.base import AdapterError
from redacto.adapters.filesystem import FilesystemAdapter
from redacto.adapters.jsonl_logs import JsonlLogAdapter
from redacto.discovery.normalization import fingerprint, normalize_loose
from redacto.engine import Engine, contains_normalized
from redacto.fixtures import SOURCE_ID
from redacto.process import pid_alive

SECRET = "sk-synthetic-CONFIG-4b8e2d-NEVER-STORE"


# ------------------------------------------------------------------ liveness


def test_pid_alive_reports_the_current_process():
    assert pid_alive(os.getpid()) is True


def test_pid_alive_reports_a_missing_process():
    assert pid_alive(999_999) is False


def test_pid_alive_rejects_invalid_values():
    assert pid_alive(0) is False
    assert pid_alive(-5) is False
    assert pid_alive("not-a-pid") is False


def test_liveness_does_not_use_os_kill_on_windows(monkeypatch):
    """os.kill(pid, 0) means Ctrl+C on Windows; the probe must not call it."""
    import redacto.process as process

    calls: list[tuple] = []
    monkeypatch.setattr(process.os, "kill", lambda *args: calls.append(args))
    monkeypatch.setattr(process.sys, "platform", "win32")
    monkeypatch.setattr(process, "_pid_alive_windows", lambda pid: True)
    assert process.pid_alive(4242) is True
    assert calls == []


def test_posix_path_uses_os_kill(monkeypatch):
    import redacto.process as process

    calls: list[tuple] = []
    monkeypatch.setattr(process.sys, "platform", "linux")
    monkeypatch.setattr(process.os, "kill", lambda *args: calls.append(args))
    assert process.pid_alive(4242) is True
    assert calls == [(4242, 0)]


# ---------------------------------------------------------------- leases


def test_plan_stuck_before_executing_is_recoverable(tmp_path):
    engine = Engine(seeded_settings(tmp_path))
    plan = engine.plan(target_id=SOURCE_ID)
    assert engine.repo.claim_plan_execution(plan["plan_id"])
    conn = sqlite3.connect(engine.settings.db_path)
    try:
        conn.execute(
            "UPDATE revocation_plans SET execution_pid = ? WHERE plan_id = ?",
            (999_999, plan["plan_id"]),
        )
        conn.commit()
    finally:
        conn.close()
    approval = engine.approve_plan(plan_id=plan["plan_id"], approval_ref="recovery-approval")
    assert engine.repo.plan_execution_lease(plan["plan_id"]) is None
    applied = engine.apply(
        plan_id=plan["plan_id"],
        plan_version=plan["plan_version"],
        approval_ref="recovery-approval",
        confirmation_token=approval["confirmation_token"],
    )
    assert applied["counts"]["succeeded"] == 7


def test_apply_itself_clears_a_dead_owners_lease(tmp_path):
    engine = Engine(seeded_settings(tmp_path))
    plan = engine.plan(target_id=SOURCE_ID)
    assert engine.repo.claim_plan_execution(plan["plan_id"])
    conn = sqlite3.connect(engine.settings.db_path)
    try:
        conn.execute(
            "UPDATE revocation_plans SET execution_pid = ? WHERE plan_id = ?",
            (999_999, plan["plan_id"]),
        )
        conn.commit()
    finally:
        conn.close()
    approval = engine.approve_plan(plan_id=plan["plan_id"], approval_ref="operator-approval")
    applied = engine.apply(
        plan_id=plan["plan_id"],
        plan_version=plan["plan_version"],
        approval_ref="operator-approval",
        confirmation_token=approval["confirmation_token"],
    )
    assert applied["counts"]["succeeded"] == 7


# -------------------------------------------------------- secret verification


def test_contains_normalized_matches_config_style_forms():
    key = "unit-test-key"
    length = len(normalize_loose(SECRET))
    target = fingerprint(SECRET, key)
    for text in (
        f"STRIPE_KEY={SECRET}",
        f"key:{SECRET}",
        f"?token={SECRET}",
        f"prefix{SECRET}suffix",
        f"  {SECRET}  ",
    ):
        assert contains_normalized(text, target, length, key) is True, text


def test_contains_normalized_does_not_match_unrelated_text():
    key = "unit-test-key"
    length = len(normalize_loose(SECRET))
    target = fingerprint(SECRET, key)
    assert contains_normalized("a completely unrelated note", target, length, key) is False
    assert contains_normalized("", target, length, key) is False


@pytest.mark.parametrize(
    "template",
    ["STRIPE_KEY={secret}", "key:{secret}", "?token={secret}", "xx{secret}yy"],
)
def test_verify_flags_config_style_secret(tmp_path, template):
    settings = seeded_settings(tmp_path)
    engine = Engine(settings)
    plan = engine.plan(
        target_id=SOURCE_ID, target_kind="secret", target_text=SECRET, mode="fact_revocation"
    )
    applied = approve_and_apply(engine, plan)
    (settings.workspace_root / "config.md").write_text(
        template.format(secret=SECRET) + "\n", encoding="utf-8"
    )
    verified = engine.verify(request_id=applied["request_id"])
    assert verified["status"] == "PARTIAL"
    filesystem = next(s for s in verified["stores"] if s["store_id"] == "filesystem")
    assert "fs:config.md" in filesystem["residual_record_ids"]


# ------------------------------------------------------- filesystem TOCTOU


def test_in_place_edit_with_same_inode_is_refused(tmp_path):
    settings = seeded_settings(tmp_path)
    adapter = FilesystemAdapter(settings.workspace_root, "k")
    path = settings.workspace_root / "acquisition-plan.md"
    record = adapter.read_record({"path": "acquisition-plan.md"})
    expected = fingerprint(record.content, "k")

    # In-place edit: same inode, new content of the same length.
    original = path.read_text(encoding="utf-8")
    replacement = "X" * len(original)
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(replacement)

    with pytest.raises(AdapterError) as excinfo:
        adapter.delete_record(
            {"path": "acquisition-plan.md"}, expected_fingerprint=expected, key="k"
        )
    assert excinfo.value.code == "content_changed"
    assert path.exists()


# ------------------------------------------------------ concurrent log writes


def test_line_appended_during_rewrite_is_not_lost(tmp_path, monkeypatch):
    path = tmp_path / "events.jsonl"
    path.write_text(
        '{"event_id":"keep-1","content":"one"}\n'
        '{"event_id":"delete-me","content":"two"}\n',
        encoding="utf-8",
    )
    adapter = JsonlLogAdapter(path, "k")

    real_read = Path.read_text
    state = {"appended": False}

    def read_with_concurrent_append(self, *args, **kwargs):
        data = real_read(self, *args, **kwargs)
        if self == path and not state["appended"]:
            state["appended"] = True
            # Simulate the agent appending a line mid-delete.
            with path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write('{"event_id":"appended","content":"three"}\n')
        return data

    monkeypatch.setattr(Path, "read_text", read_with_concurrent_append)
    adapter.delete_record({"event_id": "delete-me"})
    monkeypatch.setattr(Path, "read_text", real_read)

    remaining = path.read_text(encoding="utf-8")
    assert "delete-me" not in remaining
    assert "keep-1" in remaining
    assert "appended" in remaining, "a concurrently appended line must not be lost"


def test_delete_conflict_is_reported_when_the_file_never_settles(tmp_path, monkeypatch):
    path = tmp_path / "events.jsonl"
    path.write_text('{"event_id":"a","content":"one"}\n', encoding="utf-8")
    adapter = JsonlLogAdapter(path, "k")

    real_read = Path.read_text
    counter = {"n": 0}

    def always_changing(self, *args, **kwargs):
        data = real_read(self, *args, **kwargs)
        if self == path:
            counter["n"] += 1
            with path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(f'{{"event_id":"churn-{counter["n"]}","content":"x"}}\n')
        return data

    monkeypatch.setattr(Path, "read_text", always_changing)
    with pytest.raises(AdapterError) as excinfo:
        adapter.delete_record({"event_id": "a"})
    assert excinfo.value.code == "delete_conflict"