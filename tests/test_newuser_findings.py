"""Regression tests for the brand-new-user and Windows reports (data handling).

Each test plants data the way a real agent workspace holds it, runs the documented
flow, and checks the bytes on disk and Redacto's own outputs.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from conftest import approve_and_apply
from helpers import make_settings, seeded_settings
from redacto.engine import Engine
from redacto.errors import RedactoError
from redacto.fixtures import ACQUISITION_PLAN, SOURCE_ID

SECRET = "sk-live-NEWUSER-0123456789abcdef"


CLEAN = {"VERIFIED_WITHIN_SCOPE", "NEEDS_REVIEW"}  # the fixture anchor has unrelated review edges


def _secret_flow(settings) -> tuple[dict, dict]:
    engine = Engine(settings)
    plan = engine.plan(
        target_id=SOURCE_ID, target_kind="secret", target_text=SECRET, mode="fact_revocation"
    )
    applied = approve_and_apply(engine, plan)
    return plan, engine.verify(request_id=applied["request_id"])


def _all_bytes(settings) -> bytes:
    data = b""
    for path in settings.workspace_root.rglob("*"):
        if path.is_file():
            data += path.read_bytes()
    return data


def _append_events(settings, *events: dict) -> None:
    with settings.jsonl_log_path.open("a", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")


def _add_chunks(settings, *chunks: dict) -> None:
    payload = json.loads(settings.vector_fixture_path.read_text(encoding="utf-8"))
    payload["chunks"].extend(chunks)
    settings.vector_fixture_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


# ------------------------------------------------------------- field coverage
@pytest.mark.parametrize(
    "event",
    [
        {"event_id": "e-args-id", "kind": "tool_call", "args": {"id": SECRET}},
        {"event_id": "e-headers-ts", "kind": "tool_call", "headers": {"ts": SECRET}},
        {"event_id": "e-key", "kind": "tool_call", "args": {SECRET: "value"}},
        {"event_id": "e-sens", "kind": "note", "sensitivity": SECRET},
        {
            "event_id": "e-deep",
            "kind": "tool_call",
            "args": json.loads("[" * 20 + json.dumps(SECRET) + "]" * 20),
        },
    ],
    ids=["nested-id", "nested-ts", "dict-key", "sensitivity", "depth-20"],
)
def test_secret_anywhere_in_a_log_event_is_removed(tmp_path, event):
    settings = seeded_settings(tmp_path)
    _append_events(settings, event)
    _, receipt = _secret_flow(settings)
    assert SECRET.encode() not in settings.jsonl_log_path.read_bytes()
    assert receipt["status"] in CLEAN
    assert receipt["counts"]["residual_matches"] == 0


@pytest.mark.parametrize(
    "chunk",
    [
        {"id": "c-content", "content": f"key {SECRET}"},
        {"id": "c-page", "page_content": f"key {SECRET}", "metadata": {"source": "x"}},
        {"id": "c-nested", "text": "hello", "metadata": {"auth": {"token": SECRET}}},
        {"id": "c-list", "text": "hello", "metadata": {"headers": [{"v": SECRET}]}},
        {"id": "c-top", "text": "hello", "extra_field": SECRET},
    ],
    ids=["content", "page_content", "nested-metadata", "list-of-dicts", "top-level-field"],
)
def test_secret_anywhere_in_a_vector_chunk_is_removed(tmp_path, chunk):
    settings = seeded_settings(tmp_path)
    _add_chunks(settings, chunk)
    _, receipt = _secret_flow(settings)
    assert SECRET.encode() not in settings.vector_fixture_path.read_bytes()
    assert receipt["status"] in CLEAN
    assert receipt["counts"]["residual_matches"] == 0


@pytest.mark.parametrize("column", ["tags", "sensitivity", "created_at"])
def test_secret_in_any_sqlite_column_is_removed(tmp_path, column):
    settings = seeded_settings(tmp_path)
    conn = sqlite3.connect(settings.sqlite_store_path)
    try:
        if column == "tags":
            conn.execute("ALTER TABLE memories ADD COLUMN tags TEXT")
        conn.execute(
            f"INSERT INTO memories (id, content, {column}) VALUES (?, ?, ?)",
            ("mem-col", "an ordinary memory", SECRET),
        )
        conn.commit()
    finally:
        conn.close()
    _, receipt = _secret_flow(settings)
    rows = sqlite3.connect(settings.sqlite_store_path).execute("SELECT * FROM memories").fetchall()
    assert SECRET not in json.dumps(rows)
    assert receipt["status"] in CLEAN
    assert receipt["counts"]["residual_matches"] == 0


def test_status_lists_unapproved_sqlite_tables(tmp_path):
    from redacto.status import collect_status

    settings = seeded_settings(tmp_path)
    conn = sqlite3.connect(settings.sqlite_store_path)
    conn.execute("CREATE TABLE chat_history (id TEXT, body TEXT)")
    conn.commit()
    conn.close()
    status = collect_status(settings, transport="test")
    sqlite_entry = next(a for a in status["adapters"] if a["adapter_id"] == "sqlite_memory")
    assert sqlite_entry["unscanned_tables"]["tables"][0]["table"] == "chat_history"


# ----------------------------------------------------------- fresh workspace
def _fresh_workspace(tmp_path: Path):
    settings = make_settings(tmp_path)
    root = settings.workspace_root
    root.mkdir(parents=True)
    (root / "board.md").write_text(ACQUISITION_PLAN, encoding="utf-8")
    (root / "copy.md").write_text(ACQUISITION_PLAN, encoding="utf-8")
    conn = sqlite3.connect(settings.sqlite_store_path)
    conn.execute("CREATE TABLE memories (id TEXT PRIMARY KEY, content TEXT, created_at TEXT, sensitivity TEXT)")
    conn.execute("INSERT INTO memories VALUES ('m1', 'unrelated', '', '')")
    conn.commit()
    conn.close()
    settings.jsonl_log_path.write_text(json.dumps({"event_id": "e1", "content": "hi"}) + "\n", encoding="utf-8")
    settings.vector_fixture_path.write_text(json.dumps({"chunks": []}), encoding="utf-8")
    return settings


def test_fresh_workspace_plans_without_an_ingest_step(tmp_path):
    settings = _fresh_workspace(tmp_path)
    engine = Engine(settings)
    plan = engine.plan(target_id="fs:board.md")
    ids = {item["record_id"] for item in plan["items"]}
    assert {"fs:board.md", "fs:copy.md"} <= ids
    applied = approve_and_apply(engine, plan)
    receipt = engine.verify(request_id=applied["request_id"])
    assert receipt["status"] == "VERIFIED_WITHIN_SCOPE"
    assert not (settings.workspace_root / "copy.md").exists()


def test_fresh_workspace_unknown_target_explains_itself(tmp_path):
    settings = _fresh_workspace(tmp_path)
    with pytest.raises(RedactoError) as excinfo:
        Engine(settings).plan(target_id="fs:nope.md")
    assert excinfo.value.code == "unknown_record"
    assert "not found in any configured store" in excinfo.value.message


# --------------------------------------------- verbatim copies + extra fields
def test_verbatim_copy_with_extra_fields_is_a_direct_match(tmp_path):
    settings = seeded_settings(tmp_path)
    _add_chunks(
        settings,
        {"id": "c-copy", "text": ACQUISITION_PLAN, "metadata": {"source": "upload", "page": 1}},
    )
    _append_events(
        settings,
        {
            "event_id": "e-read",
            "kind": "tool_result",
            "tool": "read_file",
            "args": {"path": "C:/docs/acquisition-plan.md"},
            "output": ACQUISITION_PLAN,
        },
    )
    engine = Engine(settings)
    plan = engine.plan(target_id=SOURCE_ID)
    items = {item["record_id"]: item for item in plan["items"]}
    for record_id in ("vec:c-copy", "log:e-read"):
        assert items[record_id]["evidence_class"] == "DIRECT_MATCH", items[record_id]
        assert items[record_id]["approved"] is True
    applied = approve_and_apply(engine, plan)
    receipt = engine.verify(request_id=applied["request_id"])
    assert receipt["counts"]["residual_matches"] == 0
    # The receipt and the ingestion guard must agree: nothing present in a store
    # may still be blocked as a copy of the revoked document.
    guard = engine.reingest_stores()
    present = [
        f for f in guard["findings"] if f.get("present_in_store") and f.get("decision") == "blocked"
    ]
    assert present == []


# ---------------------------------------------- secrets never leak via ids
@pytest.mark.xfail(strict=True, reason="secret-bearing ids are not aliased yet")
@pytest.mark.parametrize("where", ["chunk_id", "event_id", "sensitivity", "created_at"])
def test_secret_in_an_identifier_does_not_leak_into_outputs(tmp_path, where):
    settings = seeded_settings(tmp_path)
    if where == "chunk_id":
        _add_chunks(settings, {"id": f"chunk-{SECRET}", "text": f"key {SECRET}"})
    elif where == "event_id":
        _append_events(settings, {"event_id": SECRET, "content": f"key {SECRET}"})
    else:
        conn = sqlite3.connect(settings.sqlite_store_path)
        conn.execute(
            f"INSERT INTO memories (id, content, {where}) VALUES (?, ?, ?)",
            ("mem-leak", f"key {SECRET}", SECRET),
        )
        conn.commit()
        conn.close()
    engine = Engine(settings)
    plan = engine.plan(
        target_id=SOURCE_ID, target_kind="secret", target_text=SECRET, mode="fact_revocation"
    )
    applied = approve_and_apply(engine, plan)
    receipt = engine.verify(request_id=applied["request_id"])
    for output in (plan, applied, receipt):
        assert SECRET not in json.dumps(output), output
    assert SECRET.encode() not in settings.db_path.read_bytes()
    assert SECRET.encode() not in _all_bytes(settings)


# ------------------------------------------------------------------ Windows
def test_vector_rewrite_keeps_lf_line_endings(tmp_path):
    settings = seeded_settings(tmp_path)
    engine = Engine(settings)
    approve_and_apply(engine, engine.plan(target_id=SOURCE_ID))
    assert b"\r\n" not in settings.vector_fixture_path.read_bytes()


def test_failed_rewrite_leaves_no_temp_file(tmp_path, monkeypatch):
    import os

    from redacto.adapters.jsonl_logs import JsonlLogAdapter

    settings = seeded_settings(tmp_path)
    adapter = JsonlLogAdapter(settings.jsonl_log_path, "unit-test-fixture-key")
    record = next(iter(adapter.list_records()))

    def fail_replace(src, dst):
        raise PermissionError("file in use")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(Exception):
        adapter.delete_record(record.locator)
    assert not list(settings.workspace_root.glob("*.tmp"))


def test_leftover_temp_file_holding_the_secret_fails_verify(tmp_path):
    settings = seeded_settings(tmp_path)
    _append_events(settings, {"event_id": "e-s", "content": f"key {SECRET}"})
    # A temp copy of the log left behind by an earlier crashed rewrite.
    leftover = settings.workspace_root / "tmpab12cd34.tmp"
    leftover.write_text(settings.jsonl_log_path.read_text(encoding="utf-8"), encoding="utf-8")
    _, receipt = _secret_flow(settings)
    assert receipt["status"] != "VERIFIED_WITHIN_SCOPE"
    assert receipt["counts"]["residual_matches"] >= 1
    assert any("tmpab12cd34.tmp" in json.dumps(s) for s in receipt["stores"])


def test_partial_plan_can_be_reapproved_after_the_store_is_freed(tmp_path, monkeypatch):
    import os

    settings = seeded_settings(tmp_path)
    engine = Engine(settings)
    plan = engine.plan(target_id=SOURCE_ID)
    real_replace = os.replace

    def locked(src, dst):
        if str(dst).endswith("agent_events.jsonl"):
            raise PermissionError("The process cannot access the file because it is being used")
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", locked)
    first = approve_and_apply(engine, plan)
    assert first["plan_state"] == "PARTIAL"
    failed = [r for r in first["results"] if r["result"] == "failed"]
    assert failed and "in use" in failed[0]["message"]
    monkeypatch.setattr(os, "replace", real_replace)
    second = approve_and_apply(engine, plan)
    assert second["counts"]["failed"] == 0
    receipt = engine.verify(request_id=second["request_id"])
    assert receipt["status"] in CLEAN
    assert receipt["counts"]["residual_matches"] == 0
