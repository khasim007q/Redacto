"""Embedding paraphrase detection: calibration, risk scoring, and honest limits."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from conftest import approve_and_apply
from helpers import seeded_settings
from redacto.discovery.embeddings import (
    CALIBRATION_EXAMPLES,
    CALIBRATION_TARGET,
    HashingEmbeddingProvider,
    calibrate,
    cosine,
    default_calibration,
)
from redacto.engine import Engine
from redacto.fixtures import SOURCE_ID
from redacto.ingestion import TombstoneGuard

NO_ANCHOR_PARAPHRASE = (
    "A private firm is buying the sensor maker for about 42 million in cash."
)
ANCHORED_PARAPHRASE = "Kestrel deal was about $42 million, I believe."


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


def test_calibration_separates_positives_from_negatives():
    at_candidate = default_calibration(0.25)
    at_quarantine = default_calibration(0.30)
    assert at_candidate.false_positives == 0
    assert at_candidate.false_negatives == 0
    assert at_quarantine.false_positives == 0
    assert at_quarantine.false_negatives == 0
    assert at_quarantine.true_positives == 5
    assert at_quarantine.true_negatives == 5


def test_calibration_measures_false_positives_and_misses():
    # A deliberately low threshold creates false positives; a high one misses
    # paraphrases. The report exposes both, so thresholds are chosen, not guessed.
    low = default_calibration(0.01)
    high = default_calibration(0.60)
    assert low.false_positives > 0
    assert high.false_negatives > 0
    report = default_calibration(0.30).as_dict()
    assert report["total"] == len(CALIBRATION_EXAMPLES)
    assert all("score" in row for row in report["scores"])
    # No raw target text is part of the calibration report.
    assert CALIBRATION_TARGET[:20] not in json.dumps(report)


def test_no_anchor_paraphrase_is_quarantined_by_embedding(tmp_path):
    engine = _revoked_engine(tmp_path)
    _insert_memory(engine.settings, "mem-no-anchor", NO_ANCHOR_PARAPHRASE)
    result = engine.reingest_stores(stores=["sqlite_memory"])
    finding = next(
        f for f in result["findings"] if f["record_id"] == "mem:mem-no-anchor"
    )
    assert finding["decision"] == "quarantined"
    assert finding["reason_code"] == "embedding_similarity"
    assert finding["match_score"] >= engine.settings.embedding_quarantine_threshold
    assert engine.repo.get_record("mem:mem-no-anchor") is None
    assert engine.quarantine()["count"] >= 1


def test_embedding_similarity_alone_never_blocks(tmp_path):
    engine = _revoked_engine(tmp_path)
    tombstone = engine.repo.list_tombstones()[0]
    assert tombstone["embedding"]
    guard = TombstoneGuard(
        [tombstone],
        {1: engine.settings.current_hmac_key},
        1,
        embedder=HashingEmbeddingProvider(),
        embedding_threshold=0.0,  # every record is "similar"
    )
    decision = guard.evaluate(
        record_id="mem:totally-new", content="Completely unrelated staging note."
    )
    assert decision.decision == "quarantined"
    assert decision.reason_code == "embedding_similarity"
    assert decision.decision != "blocked"


def test_scan_generates_an_embedding_review_candidate(tmp_path):
    settings = seeded_settings(tmp_path)
    _insert_memory(settings, "mem-no-anchor", NO_ANCHOR_PARAPHRASE)
    engine = Engine(settings)
    scan = engine.scan(target_id=SOURCE_ID)
    candidate = next(
        c for c in scan["candidates"] if c["record_id"] == "mem:mem-no-anchor"
    )
    assert candidate["evidence_class"] == "SUSPECTED_DERIVATIVE"
    assert candidate["approved"] is False
    assert candidate["candidate_only"] is True
    assert "Embedding similarity" in candidate["reason_redacted"]
    assert scan["embeddings"]["provider"] == "local-hashing-v1"
    assert scan["embeddings"]["candidates_generated"] >= 1
    # The unrelated engineering note is not swept up by the embedding signal.
    assert "mem:mem-unrelated-eng" not in {
        c["record_id"] for c in scan["candidates"]
    }


def test_embedding_candidate_is_not_confirmed_lineage(tmp_path):
    settings = seeded_settings(tmp_path)
    _insert_memory(settings, "mem-no-anchor", NO_ANCHOR_PARAPHRASE)
    engine = Engine(settings)
    scan = engine.scan(target_id=SOURCE_ID)
    candidate = next(
        c for c in scan["candidates"] if c["record_id"] == "mem:mem-no-anchor"
    )
    trace = engine.trace(source_id=SOURCE_ID)
    assert "mem:mem-no-anchor" not in {
        node["record_id"] for node in trace["confirmed_descendants"]
    }
    assert candidate["proposed_action"] == "REVIEW_REQUIRED"
    assert candidate["approved"] is False


def test_disabling_embeddings_leaves_the_documented_gap(tmp_path):
    engine = _revoked_engine(tmp_path, embedding_provider="none")
    _insert_memory(engine.settings, "mem-no-anchor", NO_ANCHOR_PARAPHRASE)
    result = engine.reingest_stores(stores=["sqlite_memory"])
    assert not any(
        f["record_id"] == "mem:mem-no-anchor" for f in result["findings"]
    )
    assert engine.repo.get_record("mem:mem-no-anchor")["status"] == "active"


def test_anchor_based_paraphrase_still_quarantines_before_embedding(tmp_path):
    engine = _revoked_engine(tmp_path)
    _insert_memory(engine.settings, "mem-anchored", ANCHORED_PARAPHRASE)
    result = engine.reingest_stores(stores=["sqlite_memory"])
    finding = next(f for f in result["findings"] if f["record_id"] == "mem:mem-anchored")
    assert finding["decision"] == "quarantined"
    assert finding["reason_code"] == "anchor_overlap"
    assert finding["reason_code"] != "embedding_similarity"


def test_embedding_scores_are_stable_and_bounded():
    provider = HashingEmbeddingProvider()
    first = provider.embed(NO_ANCHOR_PARAPHRASE)
    second = provider.embed(NO_ANCHOR_PARAPHRASE)
    assert first == second
    assert len(first) == 512
    assert cosine(first, first) == 1.0
    assert 0.0 <= cosine(first, provider.embed("Completely unrelated text.")) <= 1.0
    # Number-word normalization makes the spelled-out and numeric forms comparable.
    numeric = provider.embed("The deal is worth 42 million dollars.")
    words = provider.embed("The deal is worth forty-two million dollars.")
    assert cosine(numeric, words) > 0.9