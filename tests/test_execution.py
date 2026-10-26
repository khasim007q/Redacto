"""Approval boundary, execution semantics and idempotency."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from conftest import approve_and_apply
from helpers import seeded_settings
from redacto.adapters.base import AdapterError
from redacto.engine import Engine
from redacto.errors import RedactoError
from redacto.fixtures import SOURCE_ID


def test_apply_rejects_missing_or_wrong_approval(engine):
    plan = engine.plan(target_id=SOURCE_ID)
    with pytest.raises(RedactoError) as excinfo:
        engine.apply(
            plan_id=plan["plan_id"],
            plan_version=plan["plan_version"],
            approval_ref="nobody-approved-this",
            confirmation_token="not-a-real-token",
        )
    assert excinfo.value.code == "unauthorized_apply"
    assert (engine.settings.workspace_root / "acquisition-plan.md").exists()


def test_apply_rejects_stale_version(engine):
    plan = engine.plan(target_id=SOURCE_ID)
    approval = engine.approve_plan(plan_id=plan["plan_id"], approval_ref="operator-approval")
    with pytest.raises(RedactoError) as excinfo:
        engine.apply(
            plan_id=plan["plan_id"],
            plan_version=plan["plan_version"] + 1,
            approval_ref="operator-approval",
            confirmation_token=approval["confirmation_token"],
        )
    assert excinfo.value.code == "stale_plan"


def test_apply_rejects_tampered_plan(engine):
    plan = engine.plan(target_id=SOURCE_ID)
    approval = engine.approve_plan(plan_id=plan["plan_id"], approval_ref="operator-approval")
    conn = sqlite3.connect(engine.settings.db_path)
    conn.execute(
        "UPDATE revocation_plan_items SET record_id = 'mem:mem-unrelated-eng' WHERE plan_id = ?",
        (plan["plan_id"],),
    )
    conn.commit()
    conn.close()
    with pytest.raises(RedactoError) as excinfo:
        engine.apply(
            plan_id=plan["plan_id"],
            plan_version=plan["plan_version"],
            approval_ref="operator-approval",
            confirmation_token=approval["confirmation_token"],
        )
    assert excinfo.value.code == "stale_plan"


def test_dry_run_changes_nothing(engine):
    plan = engine.plan(target_id=SOURCE_ID)
    result = approve_and_apply(engine, plan, dry_run=True)
    assert result["dry_run"] is True
    assert result["counts"]["dry_run"] == 7
    assert (engine.settings.workspace_root / "acquisition-plan.md").exists()
    assert result["plan_state"] == "APPROVED"


def test_apply_removes_target_and_derivatives_but_preserves_unrelated(engine):
    plan = engine.plan(target_id=SOURCE_ID)
    result = approve_and_apply(engine, plan)
    assert result["counts"]["succeeded"] == 7
    workspace = engine.settings.workspace_root
    assert not (workspace / "acquisition-plan.md").exists()
    assert not (workspace / "generated-summary.md").exists()
    # Unrelated and related-non-disclosing records survive, including the embedded-instruction file.
    assert (workspace / "eng-notes.md").exists()
    assert (workspace / "sibling-public-mention.md").exists()
    conn = sqlite3.connect(workspace / "agent_memory.sqlite3")
    memories = {row[0] for row in conn.execute("SELECT id FROM memories")}
    cache = {row[0] for row in conn.execute("SELECT id FROM response_cache")}
    conn.close()
    assert "mem-unrelated-eng" in memories
    assert "mem-sibling-public" in memories
    assert "cache-unrelated-1" in cache
    assert "mem-summary-paraphrase" not in memories
    assert "cache-response-1" not in cache


def test_reapplying_the_same_plan_is_idempotent(engine):
    plan = engine.plan(target_id=SOURCE_ID)
    first = approve_and_apply(engine, plan)
    second = engine.apply(
        plan_id=plan["plan_id"],
        plan_version=plan["plan_version"],
        approval_ref="operator-approval",
        confirmation_token="ignored-because-already-applied",
    )
    assert second["already_completed"] is True
    assert len(second["results"]) == len(first["results"])


def test_already_absent_record_is_not_counted_as_deleted(engine):
    plan = engine.plan(target_id=SOURCE_ID)
    approval = engine.approve_plan(plan_id=plan["plan_id"], approval_ref="operator-approval")
    (engine.settings.workspace_root / "generated-summary.md").unlink()
    result = engine.apply(
        plan_id=plan["plan_id"],
        plan_version=plan["plan_version"],
        approval_ref="operator-approval",
        confirmation_token=approval["confirmation_token"],
    )
    assert result["counts"]["already_absent"] >= 1


def test_adapter_failure_is_reported_not_hidden(tmp_path, monkeypatch):
    settings = seeded_settings(tmp_path)
    engine = Engine(settings)
    plan = engine.plan(target_id=SOURCE_ID)
    approval = engine.approve_plan(plan_id=plan["plan_id"], approval_ref="operator-approval")

    from redacto.adapters.filesystem import FilesystemAdapter

    def boom(self, locator):
        raise AdapterError("simulated delete failure", code="delete_failed")

    monkeypatch.setattr(FilesystemAdapter, "delete_record", boom)
    result = engine.apply(
        plan_id=plan["plan_id"],
        plan_version=plan["plan_version"],
        approval_ref="operator-approval",
        confirmation_token=approval["confirmation_token"],
    )
    assert result["plan_state"] == "PARTIAL"
    failed = [r for r in result["results"] if r["result"] == "failed"]
    assert failed and all(r["error_code"] == "delete_failed" for r in failed)
    assert (settings.workspace_root / "acquisition-plan.md").exists()

    verified = engine.verify(request_id=result["request_id"])
    assert verified["status"] == "PARTIAL"
    assert verified["counts"]["residual_matches"] >= 1


def test_store_that_disappears_after_planning_fails_visibly(tmp_path):
    settings = seeded_settings(tmp_path)
    engine = Engine(settings)
    plan = engine.plan(target_id=SOURCE_ID)
    approval = engine.approve_plan(plan_id=plan["plan_id"], approval_ref="operator-approval")

    # The store was reachable at plan time and disappears before apply.
    settings.jsonl_log_path.unlink()

    result = engine.apply(
        plan_id=plan["plan_id"],
        plan_version=plan["plan_version"],
        approval_ref="operator-approval",
        confirmation_token=approval["confirmation_token"],
    )
    assert result["plan_state"] == "PARTIAL"
    assert any(r.get("error_code") == "adapter_unavailable" for r in result["results"])

    verified = engine.verify(request_id=result["request_id"])
    assert verified["status"] == "PARTIAL"
    assert "jsonl_logs" in verified["unreachable_stores"]


def test_unreachable_store_is_reported_in_plan_and_verification(tmp_path):
    settings = seeded_settings(tmp_path, jsonl_log_path=tmp_path / "missing.jsonl")
    engine = Engine(settings)
    plan = engine.plan(target_id=SOURCE_ID)
    assert "jsonl_logs" in plan["unreachable_stores"]
    applied = approve_and_apply(engine, plan)
    assert applied["plan_state"] != "VERIFIED_WITHIN_SCOPE"
    verified = engine.verify(request_id=applied["request_id"])
    assert verified["status"] == "PARTIAL"
    assert "jsonl_logs" in verified["unreachable_stores"]


def test_unknown_stores_are_rejected(engine):
    with pytest.raises(RedactoError) as excinfo:
        engine.scan(target_id=SOURCE_ID, stores=["filesystem", "not_a_store"])
    assert excinfo.value.code == "out_of_scope_store"


def test_seed_reseeds_cleanly(tmp_path):
    from redacto.fixtures import seed_workspace

    settings = seeded_settings(tmp_path)
    engine = Engine(settings)
    plan = engine.plan(target_id=SOURCE_ID)
    approve_and_apply(engine, plan)
    seed_workspace(settings)
    assert (settings.workspace_root / "acquisition-plan.md").exists()
    assert Engine(settings).trace(source_id=SOURCE_ID)["confirmed_descendants"]
    assert Path(settings.db_path).exists()


def test_apply_enters_executing_before_any_mutation(engine, monkeypatch):
    plan = engine.plan(target_id=SOURCE_ID)
    approval = engine.approve_plan(plan_id=plan["plan_id"], approval_ref="operator-approval")
    observed: list[str] = []

    from redacto.adapters.filesystem import FilesystemAdapter

    original_delete = FilesystemAdapter.delete_record

    def wrapped(self, locator):
        observed.append(engine.repo.get_plan(plan["plan_id"])["state"])
        return original_delete(self, locator)

    monkeypatch.setattr(FilesystemAdapter, "delete_record", wrapped)
    engine.apply(
        plan_id=plan["plan_id"],
        plan_version=plan["plan_version"],
        approval_ref="operator-approval",
        confirmation_token=approval["confirmation_token"],
    )
    assert observed
    assert all(state == "EXECUTING" for state in observed)


def test_unreachable_store_yields_unreachable_actions(tmp_path):
    settings = seeded_settings(tmp_path, jsonl_log_path=tmp_path / "missing.jsonl")
    engine = Engine(settings)
    plan = engine.plan(target_id=SOURCE_ID)
    unreachable_items = [
        item for item in plan["items"] if item["proposed_action"] == "UNREACHABLE"
    ]
    assert unreachable_items
    assert all(item["approved"] is False for item in unreachable_items)
    assert any(item["record_id"] == "log:evt-summary-gen" for item in unreachable_items)
    assert plan["estimated_impact"]["unreachable"] >= 1


def test_executing_plan_can_be_retried_without_duplicate_work(engine):
    plan = engine.plan(target_id=SOURCE_ID)
    approval = engine.approve_plan(plan_id=plan["plan_id"], approval_ref="operator-approval")
    # Simulate a crash after the plan entered EXECUTING but before completion.
    engine.repo.set_plan_state(plan["plan_id"], "EXECUTING")
    result = engine.apply(
        plan_id=plan["plan_id"],
        plan_version=plan["plan_version"],
        approval_ref="operator-approval",
        confirmation_token=approval["confirmation_token"],
    )
    assert result.get("already_completed") is not True
    assert result["counts"]["succeeded"] == 7
    assert result["plan_state"] == "VERIFYING"