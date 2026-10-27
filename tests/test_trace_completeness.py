"""Trace-completeness hardening from the removal audit.

Covers: secret anchors, secret rescan at verification, every string field in logs
and vector metadata, price+date disclosure, snippet number masking, file modes,
unscanned-file reporting, secure delete and adapter-level atomic delete.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from pathlib import Path

import pytest

from conftest import approve_and_apply
from helpers import seeded_settings
from redacto.adapters.base import AdapterError
from redacto.adapters.filesystem import FilesystemAdapter
from redacto.adapters.jsonl_logs import JsonlLogAdapter
from redacto.adapters.sqlite_store import SqliteMemoryAdapter
from redacto.adapters.vector_fixture import VectorFixtureAdapter
from redacto.discovery.normalization import fingerprint
from redacto.discovery.relationship_assessor import minimize_snippet
from redacto.engine import Engine
from redacto.fixtures import SOURCE_ID

SECRET = "sk-synthetic-LEAK-9f3a7c1e-NEVER-STORE"


def test_secret_anchor_without_the_secret_is_not_deleted(tmp_path):
    settings = seeded_settings(tmp_path)
    engine = Engine(settings)
    plan = engine.plan(
        target_id=SOURCE_ID, target_kind="secret", target_text=SECRET, mode="fact_revocation"
    )
    anchor = next(
        (i for i in plan["items"] if i["record_id"] == SOURCE_ID), None
    )
    # The anchor does not contain the secret, so it must not be plan-approved.
    assert anchor is None or anchor["approved"] is False
    approve_and_apply(engine, plan)
    assert (settings.workspace_root / "acquisition-plan.md").exists()


def test_secret_is_found_in_log_tool_arguments(tmp_path):
    settings = seeded_settings(tmp_path)
    with settings.jsonl_log_path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(
            json.dumps(
                {
                    "event_id": "evt-tool-call",
                    "kind": "tool_call",
                    "tool": {"name": "http.post", "arguments": {"headers": {"x-api-key": SECRET}}},
                }
            )
            + "\n"
        )
    engine = Engine(settings)
    plan = engine.plan(
        target_id=SOURCE_ID, target_kind="secret", target_text=SECRET, mode="fact_revocation"
    )
    item = next(i for i in plan["items"] if i["record_id"] == "log:evt-tool-call")
    assert item["evidence_class"] == "DIRECT_MATCH"
    assert item["approved"] is True


def test_secret_is_found_in_vector_metadata(tmp_path):
    settings = seeded_settings(tmp_path)
    payload = json.loads(settings.vector_fixture_path.read_text(encoding="utf-8"))
    payload["chunks"].append(
        {"id": "chunk-meta", "text": "unrelated text", "metadata": {"api_key": SECRET}}
    )
    settings.vector_fixture_path.write_text(json.dumps(payload), encoding="utf-8")
    engine = Engine(settings)
    plan = engine.plan(
        target_id=SOURCE_ID, target_kind="secret", target_text=SECRET, mode="fact_revocation"
    )
    item = next(i for i in plan["items"] if i["record_id"] == "vec:chunk-meta")
    assert item["evidence_class"] == "DIRECT_MATCH"
    assert item["approved"] is True


def test_secret_written_back_before_verify_is_reported(tmp_path):
    settings = seeded_settings(tmp_path)
    engine = Engine(settings)
    plan = engine.plan(
        target_id=SOURCE_ID, target_kind="secret", target_text=SECRET, mode="fact_revocation"
    )
    applied = approve_and_apply(engine, plan)
    # Secret reappears in a store that was not part of the plan.
    conn = sqlite3.connect(settings.sqlite_store_path)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO memories (id, content, created_at, sensitivity) VALUES (?,?,?,?)",
            ("mem-late-secret", f"token {SECRET}", "2026-10-26", "confidential"),
        )
        conn.commit()
    finally:
        conn.close()
    verified = engine.verify(request_id=applied["request_id"])
    assert verified["status"] == "PARTIAL"
    assert verified["counts"]["residual_matches"] >= 1
    sqlite_store = next(s for s in verified["stores"] if s["store_id"] == "sqlite_memory")
    assert "mem:mem-late-secret" in sqlite_result_residuals(sqlite_store)


def sqlite_result_residuals(store: dict) -> list[str]:
    return store.get("residual_record_ids", [])


def test_price_and_closing_date_note_goes_to_review(tmp_path):
    settings = seeded_settings(tmp_path)
    (settings.workspace_root / "deal-note.md").write_text(
        "# Deal note\n\nThe buyer is Halcyon Robotics at $42 million, closing 14 March 2027.\n",
        encoding="utf-8",
    )
    plan = Engine(settings).plan(target_id=SOURCE_ID)
    item = next(i for i in plan["items"] if i["record_id"] == "fs:deal-note.md")
    assert item["evidence_class"] == "SUSPECTED_DERIVATIVE"
    assert item["proposed_action"] == "REVIEW_REQUIRED"
    assert item["approved"] is False


def test_snippet_masks_spelled_out_amounts():
    snippet = minimize_snippet("The firm is paying forty-two million dollars for the maker.")
    assert "forty-two million" not in snippet.lower()
    assert "[NUMBER]" in snippet


def test_jsonl_rewrite_preserves_file_mode(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text('{"event_id":"a","content":"one"}\n{"event_id":"b","content":"two"}\n', encoding="utf-8")
    os.chmod(path, 0o644 if os.name == "posix" else 0o666)
    before = stat.S_IMODE(path.stat().st_mode)
    adapter = JsonlLogAdapter(path, "k")
    adapter.delete_record({"event_id": "a"})
    assert stat.S_IMODE(path.stat().st_mode) == before


def test_vector_rewrite_preserves_file_mode(tmp_path):
    path = tmp_path / "chunks.json"
    path.write_text(json.dumps({"chunks": [{"id": "a", "text": "one"}]}), encoding="utf-8")
    os.chmod(path, 0o644 if os.name == "posix" else 0o666)
    before = stat.S_IMODE(path.stat().st_mode)
    adapter = VectorFixtureAdapter(path, "k")
    adapter.delete_record({"id": "a"})
    assert stat.S_IMODE(path.stat().st_mode) == before


def test_status_reports_unscanned_files(tmp_path):
    settings = seeded_settings(tmp_path)
    (settings.workspace_root / ".env").write_text("SECRET=1\n", encoding="utf-8")
    (settings.workspace_root / "dump.bak").write_text("backup\n", encoding="utf-8")
    status = Engine(settings).status(transport="test")
    filesystem = next(a for a in status["adapters"] if a["adapter_id"] == "filesystem")
    assert filesystem["unscanned_files"]["count"] >= 2
    assert any(name.endswith(".env") or name.endswith(".bak") for name in filesystem["unscanned_files"]["sample"])


def test_sqlite_adapter_verifies_fingerprint_atomically(tmp_path):
    settings = seeded_settings(tmp_path)
    adapter = SqliteMemoryAdapter(settings.sqlite_store_path, "k")
    record = adapter.read_record({"table": "memories", "id": "mem-summary-paraphrase"})
    expected = fingerprint(record.content, "k")
    # Change the row behind the plan's back.
    conn = sqlite3.connect(settings.sqlite_store_path)
    try:
        conn.execute("UPDATE memories SET content = ? WHERE id = ?", ("changed", "mem-summary-paraphrase"))
        conn.commit()
    finally:
        conn.close()
    with pytest.raises(AdapterError) as excinfo:
        adapter.delete_record(
            {"table": "memories", "id": "mem-summary-paraphrase"},
            expected_fingerprint=expected,
            key="k",
        )
    assert excinfo.value.code == "content_changed"
    assert adapter.read_record({"table": "memories", "id": "mem-summary-paraphrase"}).content == "changed"


def test_filesystem_adapter_verifies_fingerprint(tmp_path):
    settings = seeded_settings(tmp_path)
    adapter = FilesystemAdapter(settings.workspace_root, "k")
    record = adapter.read_record({"path": "acquisition-plan.md"})
    expected = fingerprint(record.content, "k")
    (settings.workspace_root / "acquisition-plan.md").write_text("replaced", encoding="utf-8")
    with pytest.raises(AdapterError) as excinfo:
        adapter.delete_record({"path": "acquisition-plan.md"}, expected_fingerprint=expected, key="k")
    assert excinfo.value.code == "content_changed"
    assert (settings.workspace_root / "acquisition-plan.md").exists()


def test_sqlite_uses_secure_delete_and_checkpoints(tmp_path):
    settings = seeded_settings(tmp_path)
    adapter = SqliteMemoryAdapter(settings.sqlite_store_path, "k")
    record = adapter.read_record({"table": "memories", "id": "mem-summary-paraphrase"})
    adapter.delete_record(
        {"table": "memories", "id": "mem-summary-paraphrase"},
        expected_fingerprint=fingerprint(record.content, "k"),
        key="k",
    )
    raw = settings.sqlite_store_path.read_bytes()
    assert record.content.encode("utf-8") not in raw


def test_secret_journey_removes_secret_but_keeps_anchor(tmp_path):
    settings = seeded_settings(tmp_path)
    leaked_file = settings.workspace_root / "leaked-key.txt"
    leaked_file.write_text(f"{SECRET}\n", encoding="utf-8")
    conn = sqlite3.connect(settings.sqlite_store_path)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO memories (id, content, created_at, sensitivity) VALUES (?,?,?,?)",
            ("mem-leak", f"key: {SECRET}", "2026-10-26", "credential"),
        )
        conn.commit()
    finally:
        conn.close()

    engine = Engine(settings)
    plan = engine.plan(
        target_id=SOURCE_ID, target_kind="secret", target_text=SECRET, mode="fact_revocation"
    )
    approved = {i["record_id"] for i in plan["items"] if i["approved"]}
    assert "fs:leaked-key.txt" in approved
    assert "mem:mem-leak" in approved
    assert SOURCE_ID not in approved

    applied = approve_and_apply(engine, plan)
    assert applied["counts"]["succeeded"] >= 2
    assert not leaked_file.exists()
    assert (settings.workspace_root / "acquisition-plan.md").exists()

    verified = engine.verify(request_id=applied["request_id"])
    assert verified["counts"]["residual_matches"] == 0
    assert verified["status"] in {"VERIFIED_WITHIN_SCOPE", "NEEDS_REVIEW"}


def test_secret_verify_catches_a_reintroduced_secret_even_when_planned_records_are_gone(tmp_path):
    settings = seeded_settings(tmp_path)
    engine = Engine(settings)
    plan = engine.plan(
        target_id=SOURCE_ID, target_kind="secret", target_text=SECRET, mode="fact_revocation"
    )
    applied = approve_and_apply(engine, plan)
    (settings.workspace_root / "notes.md").write_text(
        f"remember the key {SECRET} for later\n", encoding="utf-8"
    )
    verified = engine.verify(request_id=applied["request_id"])
    assert verified["status"] == "PARTIAL"
    filesystem = next(s for s in verified["stores"] if s["store_id"] == "filesystem")
    assert "fs:notes.md" in filesystem["residual_record_ids"]


def test_small_secret_mention_waits_for_review_then_verifies_clean(tmp_path):
    """A 40-byte key inside a 5 KB handbook must not auto-delete the handbook.

    The record is held for review; verify honestly reports PARTIAL until a
    reviewer approves the item, after which verification is clean.
    """
    settings = seeded_settings(tmp_path)
    handbook = settings.workspace_root / "handbook.md"
    handbook.write_text(
        "# Handbook\n\nRotate keys quarterly.\n\n"
        + "\n".join(f"- Step {i}: check the dashboard." for i in range(120))
        + f"\n\nOps note: STRIPE_KEY={SECRET}\n",
        encoding="utf-8",
    )
    engine = Engine(settings)
    plan = engine.plan(
        target_id=SOURCE_ID, target_kind="secret", target_text=SECRET, mode="fact_revocation"
    )
    item = next(i for i in plan["items"] if i["record_id"] == "fs:handbook.md")
    assert item["evidence_class"] == "DIRECT_MATCH"
    assert item["proposed_action"] == "REVIEW_REQUIRED"
    assert item["approved"] is False
    assert item["match_ratio"] < 0.5

    applied = approve_and_apply(engine, plan)
    assert handbook.exists()
    first = engine.verify(request_id=applied["request_id"])
    assert first["status"] == "PARTIAL"
    filesystem = next(s for s in first["stores"] if s["store_id"] == "filesystem")
    assert "fs:handbook.md" in filesystem["residual_record_ids"]

    review = engine.review_plan_item(
        plan_id=plan["plan_id"],
        item_id=item["item_id"],
        decision="approved",
        reviewer="reviewer-1",
        note="handbook is 99% unrelated; approve the whole-record delete",
    )
    approval = engine.approve_plan(plan_id=plan["plan_id"], approval_ref="after-review")
    assert approval["plan_version"] == review["plan_version"]
    engine.apply(
        plan_id=plan["plan_id"],
        plan_version=review["plan_version"],
        approval_ref="after-review",
        confirmation_token=approval["confirmation_token"],
    )
    final = engine.verify(request_id=applied["request_id"])
    assert final["counts"]["residual_matches"] == 0
    assert final["status"] in {"VERIFIED_WITHIN_SCOPE", "NEEDS_REVIEW"}
    assert not handbook.exists()