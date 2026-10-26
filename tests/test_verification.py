"""Verification scope, honesty and receipt redaction."""

from __future__ import annotations

import json

import pytest

from conftest import approve_and_apply
from helpers import seeded_settings
from redacto.engine import Engine
from redacto.errors import RedactoError
from redacto.fixtures import SOURCE_ID

TARGET_PHRASE = "all-cash transaction"


def _run_flow(engine: Engine) -> dict:
    plan = engine.plan(target_id=SOURCE_ID)
    applied = approve_and_apply(engine, plan)
    return engine.verify(request_id=applied["request_id"])


def test_verify_before_apply_is_rejected(engine):
    plan = engine.plan(target_id=SOURCE_ID)
    with pytest.raises(RedactoError) as excinfo:
        engine.verify(request_id=plan["request_id"])
    assert excinfo.value.code in {"plan_not_applied", "unknown_plan"}


def test_verify_reports_all_reachable_stores(engine):
    verified = _run_flow(engine)
    assert {s["store_id"] for s in verified["stores"]} == {
        "filesystem",
        "sqlite_memory",
        "jsonl_logs",
        "vector_fixture",
    }
    assert all(s["outcome"] == "verified" for s in verified["stores"])
    assert verified["counts"]["residual_matches"] == 0
    assert verified["status"] in {"VERIFIED_WITHIN_SCOPE", "NEEDS_REVIEW"}


def test_verify_rejects_stores_outside_approved_scope(engine):
    plan = engine.plan(target_id=SOURCE_ID, stores=["filesystem"])
    applied = approve_and_apply(engine, plan)
    with pytest.raises(RedactoError) as excinfo:
        engine.verify(request_id=applied["request_id"], stores=["sqlite_memory"])
    assert excinfo.value.code == "out_of_scope_store"


def test_subset_verification_is_partial_and_says_so(engine):
    plan = engine.plan(target_id=SOURCE_ID)
    applied = approve_and_apply(engine, plan)
    verified = engine.verify(request_id=applied["request_id"], stores=["filesystem"])
    assert verified["status"] == "PARTIAL"
    assert any("subset" in limitation for limitation in verified["limitations"])


def test_unreachable_store_is_reported_never_assumed_clean(tmp_path):
    settings = seeded_settings(tmp_path, vector_fixture_path=tmp_path / "missing.json")
    engine = Engine(settings)
    verified = _run_flow(engine)
    assert verified["status"] == "PARTIAL"
    assert "vector_fixture" in verified["unreachable_stores"]
    vector = next(s for s in verified["stores"] if s["store_id"] == "vector_fixture")
    assert vector["outcome"] == "unreachable"
    assert any("vector_fixture" in limitation for limitation in verified["limitations"])


def test_receipt_never_contains_target_content(engine):
    verified = _run_flow(engine)
    serialized = json.dumps(verified["receipt"])
    assert TARGET_PHRASE not in serialized
    assert "Halcyon" not in serialized
    assert verified["receipt"]["statement"].startswith(("Verified within configured scope", "Incomplete"))
    assert "Nothing" not in serialized


def test_graph_database_never_stores_target_content(engine):
    _run_flow(engine)
    raw = engine.settings.db_path.read_bytes()
    assert TARGET_PHRASE.encode() not in raw
    assert b"Meridian Capital" not in raw


def test_receipt_can_be_looked_up_by_id(engine):
    verified = _run_flow(engine)
    again = engine.verify(receipt_id=verified["receipt_id"])
    assert again["request_id"] == verified["request_id"]
    assert again["receipt"]["counts"] == verified["counts"]


def test_receipt_lists_limitations_and_scope(engine):
    verified = _run_flow(engine)
    receipt = verified["receipt"]
    assert receipt["scope"]["verified_stores"]
    assert any("backups" in limitation for limitation in receipt["limitations"])
    assert receipt["approved_by"] == "application-issued-approval"