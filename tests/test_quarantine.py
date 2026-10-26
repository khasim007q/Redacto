"""Quarantine resolution: explicit admission, rejection audit, and rechecks."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from conftest import approve_and_apply
from helpers import seeded_settings
from redacto.adapters.base import Record
from redacto.engine import Engine
from redacto.errors import RedactoError
from redacto.fixtures import SOURCE_ID

PARAPHRASE = "Kestrel deal was about $42 million, I believe."


def _revoked_engine(tmp_path: Path, **overrides) -> Engine:
    settings = seeded_settings(tmp_path, **overrides)
    engine = Engine(settings)
    plan = engine.plan(target_id=SOURCE_ID)
    applied = approve_and_apply(engine, plan)
    engine.verify(request_id=applied["request_id"])
    return engine


def _insert_memory(settings, record_id: str, content: str) -> None:
    conn = sqlite3.connect(settings.sqlite_store_path)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO memories (id, content, created_at, sensitivity) VALUES (?, ?, ?, ?)",
            (record_id, content, "2026-10-26T12:00:00+00:00", "confidential"),
        )
        conn.commit()
    finally:
        conn.close()


def _memory_ids(settings) -> set[str]:
    conn = sqlite3.connect(settings.sqlite_store_path)
    try:
        return {row[0] for row in conn.execute("SELECT id FROM memories")}
    finally:
        conn.close()


def _pending(engine: Engine, record_id: str) -> dict:
    return next(q for q in engine.quarantine()["quarantine"] if q["record_id"] == record_id)


def test_approval_admits_through_audited_path(tmp_path):
    engine = _revoked_engine(tmp_path)
    _insert_memory(engine.settings, "mem-review-me", PARAPHRASE)
    engine.reingest_stores(stores=["sqlite_memory"])
    entry = _pending(engine, "mem:mem-review-me")

    result = engine.resolve_quarantine(
        quarantine_id=entry["quarantine_id"],
        decision="approved",
        reviewer="reviewer-1",
        note="public paraphrase reviewed",
    )
    assert result["status"] == "approved"
    assert result["admitted"] is True
    assert result["audit_event_id"]
    assert engine.repo.get_record("mem:mem-review-me")["status"] == "active"

    stored = engine.repo.get_quarantine(entry["quarantine_id"])
    assert stored["status"] == "approved"
    assert stored["reviewed_by"] == "reviewer-1"
    assert stored["review_note"] == "public paraphrase reviewed"
    assert stored["admitted_at"]
    assert stored["admission_event_id"] == result["audit_event_id"]
    assert stored["recheck"]["outcome"] == "quarantined_overridden"
    assert stored["recheck"]["override_reason"] == "human_review_approved"

    events = [
        e for e in engine.repo.ingestion_events() if e["record_id"] == "mem:mem-review-me"
    ]
    assert any(e["decision"] == "admitted" and e["reason_code"] == "quarantine_approved" for e in events)


def test_rejection_preserves_decision_without_admitting(tmp_path):
    engine = _revoked_engine(tmp_path)
    _insert_memory(engine.settings, "mem-reject-me", PARAPHRASE)
    engine.reingest_stores(stores=["sqlite_memory"])
    entry = _pending(engine, "mem:mem-reject-me")

    result = engine.resolve_quarantine(
        quarantine_id=entry["quarantine_id"],
        decision="rejected",
        reviewer="reviewer-2",
        note="looks like a genuine leaked figure",
    )
    assert result["status"] == "rejected"
    assert result["admitted"] is False
    assert engine.repo.get_record("mem:mem-reject-me") is None
    # The content is still in the store: rejection does not delete anything.
    assert "mem-reject-me" in _memory_ids(engine.settings)

    stored = engine.repo.get_quarantine(entry["quarantine_id"])
    assert stored["status"] == "rejected"
    assert stored["reviewed_by"] == "reviewer-2"
    assert stored["review_note"] == "looks like a genuine leaked figure"
    assert stored["admitted_at"] is None
    assert stored["recheck"]["outcome"] == "rejected"

    events = [e for e in engine.repo.ingestion_events() if e["record_id"] == "mem:mem-reject-me"]
    assert any(e["decision"] == "rejected" for e in events)
    assert not any(e["decision"] == "admitted" for e in events)


def test_approval_rechecks_tombstones_added_after_quarantine(tmp_path):
    engine = _revoked_engine(tmp_path)
    _insert_memory(engine.settings, "mem-late-revocation", PARAPHRASE)
    engine.reingest_stores(stores=["sqlite_memory"])
    entry = _pending(engine, "mem:mem-late-revocation")

    # A later revocation now covers this exact content.
    plan = engine.plan(
        target_id=SOURCE_ID,
        target_kind="fact",
        target_text=PARAPHRASE,
        mode="fact_revocation",
    )
    applied = approve_and_apply(engine, plan)
    engine.verify(request_id=applied["request_id"])

    result = engine.resolve_quarantine(
        quarantine_id=entry["quarantine_id"],
        decision="approved",
        reviewer="reviewer-3",
        note="attempted after a later revocation",
    )
    assert result["status"] == "blocked_on_recheck"
    assert result["admitted"] is False
    assert engine.repo.get_record("mem:mem-late-revocation") is None
    stored = engine.repo.get_quarantine(entry["quarantine_id"])
    assert stored["status"] == "blocked_on_recheck"
    assert stored["recheck"]["guard"]["decision"] == "blocked"


def test_approved_record_cannot_bypass_a_later_revocation(tmp_path):
    engine = _revoked_engine(tmp_path)
    _insert_memory(engine.settings, "mem-approved", PARAPHRASE)
    engine.reingest_stores(stores=["sqlite_memory"])
    entry = _pending(engine, "mem:mem-approved")
    engine.resolve_quarantine(
        quarantine_id=entry["quarantine_id"],
        decision="approved",
        reviewer="reviewer-4",
    )
    assert engine.repo.get_record("mem:mem-approved")["status"] == "active"

    # Revoke the now-admitted record itself; approval is not immunity.
    plan = engine.plan(target_id="mem:mem-approved")
    applied = approve_and_apply(engine, plan)
    verified = engine.verify(request_id=applied["request_id"])
    assert verified["tombstone"]["target_id"] == "mem:mem-approved"

    _insert_memory(engine.settings, "mem-approved", PARAPHRASE)
    reingest = engine.reingest_stores(stores=["sqlite_memory"])
    finding = next(
        f for f in reingest["findings"] if f["record_id"] == "mem:mem-approved"
    )
    assert finding["decision"] == "blocked"
    assert finding["reason_code"] in {"same_target", "revoked_record_id", "exact_fingerprint"}


def test_strict_mode_refuses_uncertain_override(tmp_path):
    engine = _revoked_engine(tmp_path, safety_mode="strict")
    _insert_memory(engine.settings, "mem-strict", PARAPHRASE)
    engine.reingest_stores(stores=["sqlite_memory"])
    entry = _pending(engine, "mem:mem-strict")

    result = engine.resolve_quarantine(
        quarantine_id=entry["quarantine_id"],
        decision="approved",
        reviewer="reviewer-5",
    )
    assert result["status"] == "blocked_on_recheck"
    assert result["admitted"] is False
    assert result["decision_record"]["review_override_allowed"] is False
    assert engine.repo.get_record("mem:mem-strict") is None


def test_already_resolved_quarantine_is_rejected(tmp_path):
    engine = _revoked_engine(tmp_path)
    _insert_memory(engine.settings, "mem-twice", PARAPHRASE)
    engine.reingest_stores(stores=["sqlite_memory"])
    entry = _pending(engine, "mem:mem-twice")
    engine.resolve_quarantine(
        quarantine_id=entry["quarantine_id"], decision="rejected", reviewer="reviewer-6"
    )
    with pytest.raises(RedactoError) as excinfo:
        engine.resolve_quarantine(
            quarantine_id=entry["quarantine_id"], decision="approved", reviewer="reviewer-6"
        )
    assert excinfo.value.code == "quarantine_already_resolved"


def test_quarantined_new_write_requires_resubmission(tmp_path):
    engine = _revoked_engine(tmp_path)
    record = Record(
        record_id="fs:paraphrase.md",
        record_type="doc",
        store_id="filesystem",
        locator={"path": "paraphrase.md"},
        content=PARAPHRASE,
        sensitivity=["confidential"],
    )
    ingested = engine.ingest([record], store_id="filesystem", write_to_store=True)
    assert ingested["counts"]["quarantined"] == 1
    assert not (engine.settings.workspace_root / "paraphrase.md").exists()
    entry = _pending(engine, "fs:paraphrase.md")

    result = engine.resolve_quarantine(
        quarantine_id=entry["quarantine_id"], decision="approved", reviewer="reviewer-7"
    )
    assert result["status"] == "pending_review"
    assert result["admitted"] is False
    assert result["decision_record"]["outcome"] == "resubmit_required"
    assert engine.repo.get_record("fs:paraphrase.md") is None


def test_reviewer_identity_is_required(tmp_path):
    engine = _revoked_engine(tmp_path)
    _insert_memory(engine.settings, "mem-no-reviewer", PARAPHRASE)
    engine.reingest_stores(stores=["sqlite_memory"])
    entry = _pending(engine, "mem:mem-no-reviewer")
    with pytest.raises(RedactoError) as excinfo:
        engine.resolve_quarantine(
            quarantine_id=entry["quarantine_id"], decision="approved", reviewer="  "
        )
    assert excinfo.value.code == "invalid_reviewer"