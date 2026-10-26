"""Crash recovery, review-item approval, and terminal plan states."""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import approve_and_apply
from helpers import seeded_settings
from redacto.adapters.base import AdapterError
from redacto.engine import Engine
from redacto.errors import RedactoError
from redacto.fixtures import SOURCE_ID

RUNBOOK = "\n".join(
    f"- Runbook step {i}: rotate staging certs, restart worker pool {i}, check Grafana panel {i}."
    for i in range(60)
)


def _item(plan: dict, record_id: str) -> dict:
    return next(item for item in plan["items"] if item["record_id"] == record_id)


def test_crashed_executing_plan_can_be_reapproved_and_resumed(tmp_path):
    engine = Engine(seeded_settings(tmp_path))
    plan = engine.plan(target_id=SOURCE_ID)
    first = engine.approve_plan(plan_id=plan["plan_id"], approval_ref="first-approval")
    row = engine.repo.find_approval(
        plan_id=plan["plan_id"],
        plan_version=plan["plan_version"],
        approval_ref="first-approval",
    )
    # Simulate: the token was claimed, then the process died before completing.
    assert engine.repo.claim_approval(row["approval_id"]) is True
    engine.repo.set_plan_state(plan["plan_id"], "EXECUTING")

    recovery = engine.approve_plan(plan_id=plan["plan_id"], approval_ref="recovery-approval")
    assert recovery["recovery"] is True
    assert recovery["plan_version"] == plan["plan_version"]

    result = engine.apply(
        plan_id=plan["plan_id"],
        plan_version=plan["plan_version"],
        approval_ref="recovery-approval",
        confirmation_token=recovery["confirmation_token"],
    )
    assert result["counts"]["succeeded"] == 7
    assert result["plan_state"] == "VERIFYING"


def test_review_item_approval_requires_a_new_plan_version_and_token(tmp_path):
    settings = seeded_settings(tmp_path)
    handbook = settings.workspace_root / "team-handbook.md"
    handbook.write_text(
        "# Team handbook\n\nInvestor note: Meridian Capital joined the board.\n\n" + RUNBOOK,
        encoding="utf-8",
    )
    engine = Engine(settings)
    plan = engine.plan(
        target_id=SOURCE_ID,
        target_kind="fact",
        target_text="Meridian Capital",
        mode="fact_revocation",
    )
    item = _item(plan, "fs:team-handbook.md")
    assert item["proposed_action"] == "REVIEW_REQUIRED"
    assert item["approved"] is False

    review = engine.review_plan_item(
        plan_id=plan["plan_id"],
        item_id=item["item_id"],
        decision="approved",
        reviewer="reviewer-1",
        note="handbook is 99% unrelated; decide explicitly",
    )
    assert review["plan_version"] == plan["plan_version"] + 1
    assert review["state"] == "READY_FOR_APPROVAL"
    assert engine.repo.get_plan_item(item["item_id"])["proposed_action"] == "DELETE_RECORD"
    assert engine.repo.get_plan_item(item["item_id"])["approved"] is True
    assert engine.repo.plan_item_reviews(plan["plan_id"])[0]["decision"] == "approved"

    # The old token is bound to the old version; the new version needs a new one.
    approval = engine.approve_plan(plan_id=plan["plan_id"], approval_ref="after-review")
    assert approval["plan_version"] == review["plan_version"]
    result = engine.apply(
        plan_id=plan["plan_id"],
        plan_version=review["plan_version"],
        approval_ref="after-review",
        confirmation_token=approval["confirmation_token"],
    )
    assert result["counts"]["succeeded"] >= 1
    assert not handbook.exists()


def test_review_item_rejection_keeps_the_item_unapproved(tmp_path):
    settings = seeded_settings(tmp_path)
    handbook = settings.workspace_root / "team-handbook.md"
    handbook.write_text("# Handbook\n\nMeridian Capital note.\n\n" + RUNBOOK, encoding="utf-8")
    engine = Engine(settings)
    plan = engine.plan(
        target_id=SOURCE_ID,
        target_kind="fact",
        target_text="Meridian Capital",
        mode="fact_revocation",
    )
    item = _item(plan, "fs:team-handbook.md")
    review = engine.review_plan_item(
        plan_id=plan["plan_id"],
        item_id=item["item_id"],
        decision="rejected",
        reviewer="reviewer-2",
    )
    assert review["plan_version"] == plan["plan_version"] + 1
    assert engine.repo.get_plan_item(item["item_id"])["approved"] is False
    assert engine.repo.get_plan_item(item["item_id"])["state"] == "review_rejected"
    assert handbook.exists()


def test_high_coverage_partial_secret_is_still_auto_deleted(tmp_path):
    settings = seeded_settings(tmp_path)
    secret = "sk-synthetic-LEAKED-KEY-1234567890"
    leaked = settings.workspace_root / "leaked-key.txt"
    leaked.write_text(secret + " padding", encoding="utf-8")  # >50% of the record is the secret
    engine = Engine(settings)
    plan = engine.plan(
        target_id=SOURCE_ID,
        target_kind="secret",
        target_text=secret,
        mode="fact_revocation",
    )
    item = _item(plan, "fs:leaked-key.txt")
    assert item["match_ratio"] > 0.5
    assert item["proposed_action"] == "DELETE_RECORD"
    assert item["approved"] is True


def test_cancel_plan_prevents_approval_and_apply(engine):
    plan = engine.plan(target_id=SOURCE_ID)
    cancelled = engine.cancel_plan(plan_id=plan["plan_id"], reason="operator stopped")
    assert cancelled["state"] == "CANCELLED"
    with pytest.raises(RedactoError) as excinfo:
        engine.approve_plan(plan_id=plan["plan_id"], approval_ref="too-late")
    assert excinfo.value.code == "plan_not_approvable"
    result = engine.apply(
        plan_id=plan["plan_id"],
        plan_version=plan["plan_version"],
        approval_ref="too-late",
        confirmation_token="none",
    )
    assert result["already_completed"] is True
    assert result["plan_state"] == "CANCELLED"


def test_all_actions_failing_marks_the_plan_failed(engine, monkeypatch):
    from redacto.adapters.filesystem import FilesystemAdapter
    from redacto.adapters.jsonl_logs import JsonlLogAdapter
    from redacto.adapters.sqlite_store import SqliteMemoryAdapter
    from redacto.adapters.vector_fixture import VectorFixtureAdapter

    def boom(*args, **kwargs):
        raise AdapterError("simulated total failure", code="delete_failed")

    monkeypatch.setattr(FilesystemAdapter, "delete_record", boom)
    monkeypatch.setattr(SqliteMemoryAdapter, "delete_record", boom)
    monkeypatch.setattr(SqliteMemoryAdapter, "invalidate_derived", boom)
    monkeypatch.setattr(JsonlLogAdapter, "delete_record", boom)
    monkeypatch.setattr(VectorFixtureAdapter, "invalidate_derived", boom)

    plan = engine.plan(target_id=SOURCE_ID)
    applied = approve_and_apply(engine, plan)
    assert applied["plan_state"] == "FAILED"
    assert applied["counts"]["succeeded"] == 0
    assert applied["counts"]["failed"] == 7


def test_unexpected_exception_marks_the_plan_failed(engine, monkeypatch):
    from redacto.adapters.filesystem import FilesystemAdapter

    def boom(self, locator):
        raise RuntimeError("unexpected adapter crash")

    monkeypatch.setattr(FilesystemAdapter, "delete_record", boom)
    plan = engine.plan(target_id=SOURCE_ID)
    approval = engine.approve_plan(plan_id=plan["plan_id"], approval_ref="operator")
    with pytest.raises(RedactoError) as excinfo:
        engine.apply(
            plan_id=plan["plan_id"],
            plan_version=plan["plan_version"],
            approval_ref="operator",
            confirmation_token=approval["confirmation_token"],
        )
    assert excinfo.value.code == "apply_failed"
    assert engine.repo.get_plan(plan["plan_id"])["state"] == "FAILED"


def test_reviewing_an_item_invalidates_the_prior_approval(tmp_path):
    settings = seeded_settings(tmp_path)
    handbook = settings.workspace_root / "team-handbook.md"
    handbook.write_text("# Handbook\n\nMeridian Capital note.\n\n" + RUNBOOK, encoding="utf-8")
    engine = Engine(settings)
    plan = engine.plan(
        target_id=SOURCE_ID,
        target_kind="fact",
        target_text="Meridian Capital",
        mode="fact_revocation",
    )
    before = engine.approve_plan(plan_id=plan["plan_id"], approval_ref="before-review")
    item = _item(plan, "fs:team-handbook.md")
    engine.review_plan_item(
        plan_id=plan["plan_id"],
        item_id=item["item_id"],
        decision="approved",
        reviewer="reviewer-3",
    )
    with pytest.raises(RedactoError) as excinfo:
        engine.apply(
            plan_id=plan["plan_id"],
            plan_version=before["plan_version"],
            approval_ref="before-review",
            confirmation_token=before["confirmation_token"],
        )
    assert excinfo.value.code == "stale_plan"
