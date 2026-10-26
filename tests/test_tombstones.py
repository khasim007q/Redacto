"""Revocation tombstones and the ingestion guard.

Covers the four re-ingestion attacks: restoring the original file, replaying an
old JSONL log, rebuilding a vector index, and reintroducing a paraphrased memory.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path

import pytest

from conftest import approve_and_apply
from helpers import seeded_settings
from redacto.adapters.base import Record
from redacto.engine import Engine
from redacto.fixtures import (
    ACQUISITION_PLAN,
    EVENTS,
    SOURCE_ID,
    VECTOR_CHUNKS,
)


def _revoked_engine(tmp_path: Path) -> Engine:
    settings = seeded_settings(tmp_path)
    engine = Engine(settings)
    plan = engine.plan(target_id=SOURCE_ID)
    applied = approve_and_apply(engine, plan)
    engine.verify(request_id=applied["request_id"])
    return engine


def _memories(settings) -> dict[str, str]:
    conn = sqlite3.connect(settings.sqlite_store_path)
    try:
        return {row[0]: row[1] for row in conn.execute("SELECT id, content FROM memories")}
    finally:
        conn.close()


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


def _append_jsonl(settings, event_id: str, content: str) -> None:
    with settings.jsonl_log_path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(
            json.dumps(
                {
                    "event_id": event_id,
                    "kind": "tool_output",
                    "content": content,
                    "sensitivity": "confidential",
                }
            )
            + "\n"
        )


def _append_chunk(settings, chunk_id: str, text: str) -> None:
    payload = json.loads(settings.vector_fixture_path.read_text(encoding="utf-8"))
    payload["chunks"].append({"id": chunk_id, "text": text, "metadata": {}, "sensitivity": "confidential"})
    settings.vector_fixture_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


# --------------------------------------------------------------- tombstone data


def test_verify_creates_one_active_tombstone_with_scope_and_policy(tmp_path):
    engine = _revoked_engine(tmp_path)
    tombstones = engine.tombstones()["tombstones"]
    assert len(tombstones) == 1
    tombstone = tombstones[0]
    assert tombstone["status"] == "active"
    assert tombstone["target_id"] == SOURCE_ID
    assert tombstone["target_kind"] == "source"
    assert tombstone["label_redacted"] == "acquisition-plan.md"
    assert tombstone["scope"]["stores"]
    assert tombstone["policy"]["require_approval"] is True
    assert "fs:generated-summary.md" in tombstone["related_record_ids"]
    assert tombstone["related_record_count"] >= 1


def test_tombstone_stores_no_revoked_content(tmp_path):
    engine = _revoked_engine(tmp_path)
    tombstone = engine.repo.list_tombstones()[0]
    raw = engine.settings.db_path.read_bytes()
    assert b"all-cash transaction" not in raw
    assert b"Meridian Capital" not in raw
    assert b"Halcyon Robotics" not in raw
    # Even the in-memory record keeps only derived, keyed material.
    assert re.fullmatch(r"[0-9a-f]{64}", tombstone["fingerprint"])
    for value in tombstone["shingles"] + tombstone["tokens"]:
        assert re.fullmatch(r"[0-9a-f]{64}", value)
    for value in tombstone["anchors"]:
        assert re.fullmatch(r"[12]:[0-9a-f]{64}", value)


def test_no_tombstone_before_apply(tmp_path):
    settings = seeded_settings(tmp_path)
    engine = Engine(settings)
    plan = engine.plan(target_id=SOURCE_ID)
    assert engine.tombstones()["count"] == 0
    # The guard is inert while the revocation is still only planned.
    restored = engine.reingest_stores(stores=["filesystem"])
    assert restored["counts"]["blocked"] == 0


def test_repeated_verification_does_not_duplicate_tombstones(tmp_path):
    engine = _revoked_engine(tmp_path)
    request_id = engine.repo.list_tombstones()[0]["request_id"]
    engine.verify(request_id=request_id)
    engine.verify(request_id=request_id)
    assert len(engine.repo.tombstones_for_request(request_id)) == 1


def test_tombstones_response_has_no_fingerprints(tmp_path):
    engine = _revoked_engine(tmp_path)
    payload = engine.tombstones()
    serialized = json.dumps(payload)
    assert '"fingerprint"' not in serialized
    assert not re.search(r"\b[0-9a-f]{64}\b", serialized)
    assert "all-cash" not in serialized


# ------------------------------------------------------ attack: restore original


def test_restoring_the_original_file_is_blocked(tmp_path):
    engine = _revoked_engine(tmp_path)
    target = engine.settings.workspace_root / "acquisition-plan.md"
    target.write_text(ACQUISITION_PLAN, encoding="utf-8")

    result = engine.reingest_stores(stores=["filesystem"])
    finding = next(f for f in result["findings"] if f["record_id"] == SOURCE_ID)
    assert finding["decision"] == "blocked"
    assert finding["reason_code"] == "same_target"
    assert result["counts"]["blocked"] == 1
    # Blocked means not re-admitted to the graph.
    assert engine.repo.get_record(SOURCE_ID)["status"] == "deleted"


def test_renamed_exact_copy_is_blocked_by_fingerprint(tmp_path):
    engine = _revoked_engine(tmp_path)
    copy = engine.settings.workspace_root / "innocent-notes.md"
    copy.write_text(ACQUISITION_PLAN, encoding="utf-8")

    result = engine.reingest_stores(stores=["filesystem"])
    finding = next(f for f in result["findings"] if f["record_id"] == "fs:innocent-notes.md")
    assert finding["decision"] == "blocked"
    assert finding["reason_code"] in {"exact_fingerprint", "exact_derivative_fingerprint"}
    assert "fs:innocent-notes.md" not in {r["record_id"] for r in engine.repo.list_records()}


def test_scan_also_refuses_to_readmit_a_restored_target(tmp_path):
    engine = _revoked_engine(tmp_path)
    (engine.settings.workspace_root / "acquisition-plan.md").write_text(
        ACQUISITION_PLAN, encoding="utf-8"
    )
    scan = engine.scan(target_id=SOURCE_ID)
    assert scan["guard"]["counts"]["blocked"] >= 1
    assert scan["counts"]["direct_match"] == 0
    assert engine.repo.get_record(SOURCE_ID)["status"] == "deleted"


# ----------------------------------------------------------- attack: replay log


def test_replaying_an_old_jsonl_event_is_blocked(tmp_path):
    engine = _revoked_engine(tmp_path)
    original = next(event for event in EVENTS if event["event_id"] == "evt-dup-1")
    _append_jsonl(engine.settings, "evt-replayed-999", original["content"])

    result = engine.reingest_stores(stores=["jsonl_logs"])
    finding = next(f for f in result["findings"] if f["record_id"] == "log:evt-replayed-999")
    assert finding["decision"] == "blocked"
    assert finding["reason_code"] in {"exact_fingerprint", "exact_derivative_fingerprint", "partial_copy"}
    assert engine.repo.get_record("log:evt-replayed-999") is None


def test_replayed_event_with_same_id_is_blocked(tmp_path):
    engine = _revoked_engine(tmp_path)
    original = next(event for event in EVENTS if event["event_id"] == "evt-dup-1")
    _append_jsonl(engine.settings, "evt-dup-1", original["content"])

    result = engine.reingest_stores(stores=["jsonl_logs"])
    finding = next(f for f in result["findings"] if f["record_id"] == "log:evt-dup-1")
    assert finding["decision"] == "blocked"
    assert finding["reason_code"] in {"revoked_record_id", "same_target"}


# ------------------------------------------------------- attack: rebuild vector


def test_rebuilt_vector_chunk_is_blocked(tmp_path):
    engine = _revoked_engine(tmp_path)
    _append_chunk(engine.settings, "chunk-rebuilt-1", VECTOR_CHUNKS[0]["text"])

    result = engine.reingest_stores(stores=["vector_fixture"])
    finding = next(f for f in result["findings"] if f["record_id"] == "vec:chunk-rebuilt-1")
    assert finding["decision"] == "blocked"
    assert finding["reason_code"] in {
        "exact_fingerprint",
        "exact_derivative_fingerprint",
        "partial_copy",
    }
    assert engine.repo.get_record("vec:chunk-rebuilt-1") is None


def test_rebuilt_chunk_with_edited_wording_is_blocked_as_partial_copy(tmp_path):
    engine = _revoked_engine(tmp_path)
    _append_chunk(
        engine.settings,
        "chunk-rebuilt-2",
        "Meridian Capital will acquire Halcyon Robotics for 42 million in an all cash transaction.",
    )
    result = engine.reingest_stores(stores=["vector_fixture"])
    finding = next(f for f in result["findings"] if f["record_id"] == "vec:chunk-rebuilt-2")
    assert finding["decision"] == "blocked"
    assert finding["reason_code"] in {"partial_copy", "exact_fingerprint", "exact_derivative_fingerprint"}


# ---------------------------------------------------- attack: paraphrased memory


def test_paraphrased_memory_is_quarantined_not_dropped(tmp_path):
    engine = _revoked_engine(tmp_path)
    _insert_memory(
        engine.settings,
        "mem-reintroduced-paraphrase",
        "I recall the Kestrel acquisition was valued around $42 million.",
    )

    result = engine.reingest_stores(stores=["sqlite_memory"])
    finding = next(
        f for f in result["findings"] if f["record_id"] == "mem:mem-reintroduced-paraphrase"
    )
    assert finding["decision"] == "quarantined"
    assert finding["reason_code"] in {"anchor_overlap", "similar_content"}

    quarantine = engine.quarantine()["quarantine"]
    entry = next(q for q in quarantine if q["record_id"] == "mem:mem-reintroduced-paraphrase")
    assert entry["status"] == "pending_review"
    assert entry["locator"]["id"] == "mem-reintroduced-paraphrase"
    # Quarantine is a pointer, not a copy of the content.
    assert "Kestrel acquisition" not in json.dumps(entry)
    # The record is still in the store, not silently deleted, and not in the active graph.
    assert "mem-reintroduced-paraphrase" in _memories(engine.settings)
    assert engine.repo.get_record("mem:mem-reintroduced-paraphrase") is None


def test_quarantine_can_be_reviewed(tmp_path):
    engine = _revoked_engine(tmp_path)
    _insert_memory(
        engine.settings,
        "mem-review-me",
        "Kestrel deal was about $42 million, I believe.",
    )
    engine.reingest_stores(stores=["sqlite_memory"])
    entry = next(
        q for q in engine.quarantine()["quarantine"] if q["record_id"] == "mem:mem-review-me"
    )
    resolved = engine.resolve_quarantine(quarantine_id=entry["quarantine_id"], decision="approved")
    assert resolved["status"] == "approved"
    assert "mem:mem-review-me" not in {
        q["record_id"] for q in engine.quarantine()["quarantine"]
    }
    assert "mem:mem-review-me" in {
        q["record_id"] for q in engine.quarantine(statuses=("approved",))["quarantine"]
    }


def test_unrelated_records_are_still_allowed(tmp_path):
    engine = _revoked_engine(tmp_path)
    _insert_memory(engine.settings, "mem-unrelated-new", "Rotate the staging certificates on Friday.")
    result = engine.reingest_stores(stores=["sqlite_memory"])
    assert not any(
        f["record_id"] == "mem:mem-unrelated-new" for f in result["findings"]
    )
    assert result["counts"]["allowed"] >= 1
    assert engine.repo.get_record("mem:mem-unrelated-new") is not None


# ---------------------------------------------------------- store write boundary


def test_ingest_refuses_to_write_a_blocked_record_to_a_store(tmp_path):
    engine = _revoked_engine(tmp_path)
    record = Record(
        record_id="fs:new-copy.md",
        record_type="doc",
        store_id="filesystem",
        locator={"path": "new-copy.md"},
        content=ACQUISITION_PLAN,
        sensitivity=["confidential"],
    )
    result = engine.ingest([record], store_id="filesystem", write_to_store=True)
    assert result["counts"]["blocked"] == 1
    assert not (engine.settings.workspace_root / "new-copy.md").exists()
    assert engine.repo.get_record("fs:new-copy.md") is None


def test_ingest_writes_allowed_records_and_records_them(tmp_path):
    engine = _revoked_engine(tmp_path)
    record = Record(
        record_id="fs:new-note.md",
        record_type="doc",
        store_id="filesystem",
        locator={"path": "new-note.md"},
        content="Upgrade the CI runners to the latest image.",
        sensitivity=["internal"],
    )
    result = engine.ingest([record], store_id="filesystem", write_to_store=True)
    assert result["counts"]["allowed"] == 1
    assert (engine.settings.workspace_root / "new-note.md").exists()
    assert engine.repo.get_record("fs:new-note.md")["status"] == "active"


def test_ingest_quarantined_record_is_not_written(tmp_path):
    engine = _revoked_engine(tmp_path)
    record = Record(
        record_id="fs:paraphrase.md",
        record_type="doc",
        store_id="filesystem",
        locator={"path": "paraphrase.md"},
        content="Kestrel acquisition: about $42 million.",
        sensitivity=["confidential"],
    )
    result = engine.ingest([record], store_id="filesystem", write_to_store=True)
    assert result["counts"]["quarantined"] == 1
    assert not (engine.settings.workspace_root / "paraphrase.md").exists()
    assert engine.quarantine()["count"] >= 1


# ------------------------------------------------------------- fact/secret path


def test_fact_tombstone_blocks_a_reintroduced_fact(tmp_path):
    settings = seeded_settings(tmp_path)
    engine = Engine(settings)
    fact = "retention pool covers 18 engineers"
    plan = engine.plan(target_id=SOURCE_ID, target_kind="fact", target_text=fact, mode="fact_revocation")
    applied = approve_and_apply(engine, plan)
    verified = engine.verify(request_id=applied["request_id"])
    assert verified["tombstone"]["target_kind"] == "fact"

    _insert_memory(settings, "mem-fact-copy", f"Remember that the {fact}.")
    result = engine.reingest_stores(stores=["sqlite_memory"])
    finding = next(f for f in result["findings"] if f["record_id"] == "mem:mem-fact-copy")
    assert finding["decision"] == "blocked"
    assert finding["reason_code"] == "fact_containment"


def test_secret_tombstone_never_stores_the_secret(tmp_path):
    settings = seeded_settings(tmp_path)
    engine = Engine(settings)
    secret = "sk-synthetic-TOMBSTONE-4d9a1c-NEVER-STORE"
    plan = engine.plan(target_id=SOURCE_ID, target_kind="secret", target_text=secret, mode="fact_revocation")
    applied = approve_and_apply(engine, plan)
    engine.verify(request_id=applied["request_id"])
    raw = settings.db_path.read_bytes()
    assert secret.encode() not in raw
    assert engine.tombstones()["tombstones"][0]["label_redacted"] == "<redacted secret target>"


def test_guard_uses_hmac_so_another_key_cannot_match(tmp_path):
    engine = _revoked_engine(tmp_path)
    tombstone = engine.repo.list_tombstones()[0]
    from redacto.ingestion import TombstoneGuard

    other_key = TombstoneGuard([tombstone], {1: "a-different-key"}, 1)
    decision = other_key.evaluate(record_id="fs:copy.md", content=ACQUISITION_PLAN)
    assert decision.decision == "allowed"