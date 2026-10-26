"""Collateral damage: does revocation remove useful context along with the trace,
and does it miss traces that are buried inside useful records?

Whole-record deletion is the intended action. These tests check that the plan
is honest about what else goes with the trace, and that a verbatim leak is
never labelled harmless.
"""

from __future__ import annotations

import pytest

from conftest import approve_and_apply
from helpers import seeded_settings
from redacto.engine import Engine
from redacto.fixtures import SOURCE_ID

RUNBOOK = "\n".join(
    f"- Runbook step {i}: rotate staging certs, restart worker pool {i}, check Grafana panel {i}."
    for i in range(60)
)
LEAKED_SENTENCE = "Meridian Capital will acquire Halcyon Robotics for $42 million in an all-cash transaction."


def _item(plan: dict, record_id: str) -> dict:
    return next(i for i in plan["items"] if i["record_id"] == record_id)


def test_confirmed_descendant_is_deleted_whole_with_its_other_content(tmp_path):
    """Pins today's policy: a confirmed descendant goes entirely, so the plan must say so."""
    settings = seeded_settings(tmp_path)
    design = settings.workspace_root / "integration-design.md"
    design.write_text("# Integration design\n\nUses the deal timeline.\n\n" + RUNBOOK, encoding="utf-8")
    engine = Engine(settings)
    engine.scan(target_id=SOURCE_ID)
    engine.record_lineage(
        source_ids=[SOURCE_ID],
        output_id="fs:integration-design.md",
        relation="DERIVED_FROM",
        evidence_type="instrumented",
        evidence_ref="pipeline-run-42",
    )
    plan = engine.plan(target_id=SOURCE_ID)
    item = _item(plan, "fs:integration-design.md")
    assert item["proposed_action"] == "DELETE_RECORD" and item["approved"] is True
    assert item["risk"] != "low"
    approve_and_apply(engine, plan)
    assert not design.exists()


def test_small_fact_in_large_record_is_held_for_review(tmp_path):
    settings = seeded_settings(tmp_path)
    (settings.workspace_root / "team-handbook.md").write_text(
        "# Team handbook\n\nInvestor note: Meridian Capital joined the board.\n\n" + RUNBOOK,
        encoding="utf-8",
    )
    plan = Engine(settings).plan(
        target_id=SOURCE_ID, target_kind="fact", target_text="Meridian Capital", mode="fact_revocation"
    )
    item = _item(plan, "fs:team-handbook.md")
    assert item["risk"] == "high" or item["proposed_action"] != "DELETE_RECORD"


def test_unrelated_records_survive_a_fact_revocation(tmp_path):
    settings = seeded_settings(tmp_path)
    keep = settings.workspace_root / "runbook.md"
    keep.write_text("# Runbook\n\n" + RUNBOOK, encoding="utf-8")
    engine = Engine(settings)
    plan = engine.plan(
        target_id=SOURCE_ID, target_kind="fact", target_text="Meridian Capital", mode="fact_revocation"
    )
    approve_and_apply(engine, plan)
    assert keep.exists()


def test_verbatim_sentence_inside_other_notes_is_never_nondisclosing(tmp_path):
    settings = seeded_settings(tmp_path)
    (settings.workspace_root / "sprint-notes.md").write_text(
        f"# Sprint notes\n\n{LEAKED_SENTENCE}\n\n{RUNBOOK}", encoding="utf-8"
    )
    plan = Engine(settings).plan(target_id=SOURCE_ID)
    item = _item(plan, "fs:sprint-notes.md")
    assert item["evidence_class"] != "RELATED_NONDISCLOSING"
    assert item["proposed_action"] in {"REVIEW_REQUIRED", "DELETE_RECORD", "REDACT_SPAN"}


def test_dry_run_shows_the_full_blast_radius_before_anything_is_lost(tmp_path):
    settings = seeded_settings(tmp_path)
    engine = Engine(settings)
    plan = engine.plan(target_id=SOURCE_ID)
    approval = engine.approve_plan(plan_id=plan["plan_id"], approval_ref="operator")
    dry = engine.apply(
        plan_id=plan["plan_id"],
        plan_version=plan["plan_version"],
        approval_ref="operator",
        confirmation_token=approval["confirmation_token"],
        dry_run=True,
    )
    would_touch = {r["record_id"] for r in dry["results"]}
    approved = {i["record_id"] for i in plan["items"] if i["approved"]}
    assert would_touch == approved
    assert all((settings.workspace_root / p).exists() for p in ("acquisition-plan.md", "generated-summary.md"))