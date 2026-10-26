"""Policy mapping and plan construction."""

from __future__ import annotations

from redacto.fixtures import SOURCE_ID
from redacto.policy import classify
from redacto.policy.plan import build_plan_items, compute_plan_hash, estimated_impact


def test_action_mapping_follows_record_capability():
    assert classify.propose_action(
        record_type="doc", capabilities={"delete": True}, evidence_class=classify.DIRECT_MATCH
    )[0] == classify.DELETE_RECORD
    assert classify.propose_action(
        record_type="index_entry", capabilities={"invalidate": True}, evidence_class=classify.DIRECT_MATCH
    )[0] == classify.INVALIDATE_INDEX
    assert classify.propose_action(
        record_type="cache_entry", capabilities={"invalidate": True}, evidence_class=classify.CONFIRMED_DESCENDANT
    )[0] == classify.INVALIDATE_CACHE
    assert classify.propose_action(
        record_type="doc", capabilities={}, evidence_class=classify.DIRECT_MATCH
    )[0] == classify.REVIEW_REQUIRED


def test_uncertain_classes_are_never_approved():
    for evidence_class in (
        classify.SUSPECTED_DERIVATIVE,
        classify.RELATED_NONDISCLOSING,
        classify.UNKNOWN,
    ):
        action, approved, risk = classify.propose_action(
            record_type="doc", capabilities={"delete": True}, evidence_class=evidence_class
        )
        assert approved is False
        assert action in {classify.REVIEW_REQUIRED, classify.SKIP_PRESERVE}
        assert risk in {"high", "none"}


def test_plan_builds_items_and_impact(engine):
    plan = engine.plan(target_id=SOURCE_ID)
    impact = plan["estimated_impact"]
    assert impact == {"delete": 5, "invalidate": 2, "review": 2, "preserve": 4, "unreachable": 0}
    assert plan["approval_required"] is True
    assert all(
        item["approved"] is False
        for item in plan["items"]
        if item["evidence_class"] in {classify.SUSPECTED_DERIVATIVE, classify.RELATED_NONDISCLOSING}
    )


def test_plan_hash_is_version_and_content_bound():
    items = [
        {
            "item_id": "item_1",
            "record_id": "fs:a.md",
            "evidence_class": classify.DIRECT_MATCH,
            "proposed_action": classify.DELETE_RECORD,
            "approved": True,
        }
    ]
    base = dict(target_id="fs:a.md", mode="source_revocation", scope={"stores": ["filesystem"]}, policy={})
    first = compute_plan_hash(version=1, items=items, **base)
    assert first == compute_plan_hash(version=1, items=items, **base)
    assert first != compute_plan_hash(version=2, items=items, **base)
    mutated = [dict(items[0], proposed_action=classify.SKIP_PRESERVE)]
    assert first != compute_plan_hash(version=1, items=mutated, **base)


def test_build_plan_items_sorts_by_severity():
    items = build_plan_items(
        [
            {
                "record_id": "b",
                "record_type": "doc",
                "capabilities": {"delete": True},
                "evidence_class": classify.RELATED_NONDISCLOSING,
                "reason_redacted": "related",
                "risk": "none",
                "approved": False,
            },
            {
                "record_id": "a",
                "record_type": "doc",
                "capabilities": {"delete": True},
                "evidence_class": classify.DIRECT_MATCH,
                "reason_redacted": "direct",
                "risk": "low",
                "approved": True,
            },
        ]
    )
    assert [item["record_id"] for item in items] == ["a", "b"]
    assert estimated_impact(items)["delete"] == 1