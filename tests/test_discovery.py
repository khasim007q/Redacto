"""Deterministic discovery, normalization and the model-assessor boundary."""

from __future__ import annotations

import json

import httpx
import pytest

from helpers import seeded_settings
from redacto.adapters.base import Record
from redacto.discovery import relationship_assessor as ra
from redacto.discovery.exact import ExactMatcher, extract_entities, shares_entity
from redacto.discovery.normalization import fingerprint, normalize_loose
from redacto.discovery.relationship_assessor import CandidateContext, NullAssessor, minimize_snippet
from redacto.engine import Engine
from redacto.fixtures import ACQUISITION_PLAN, SOURCE_ID


def _record(content: str, record_id: str = "x:1") -> Record:
    return Record(
        record_id=record_id,
        record_type="memory",
        store_id="sqlite_memory",
        locator={"table": "memories", "id": "1"},
        content=content,
    )


def test_matcher_detects_normalized_variants():
    matcher = ExactMatcher(
        target_text=ACQUISITION_PLAN,
        target_record_id=SOURCE_ID,
        target_locator={"path": "acquisition-plan.md"},
        target_kind="source",
    )
    noisy = ACQUISITION_PLAN.replace(" ", "  ").replace("CONFIDENTIAL", "confidential").upper()
    match = matcher.match(_record(noisy))
    assert match is not None and match.kind == "normalized_content"


def test_matcher_ignores_unrelated_content():
    matcher = ExactMatcher(
        target_text=ACQUISITION_PLAN,
        target_record_id=SOURCE_ID,
        target_locator={"path": "acquisition-plan.md"},
    )
    assert matcher.match(_record("Deployed build 4271 to staging.")) is None


def test_short_secret_variant_is_not_matched():
    matcher = ExactMatcher(
        target_text="ab",
        target_record_id="secret:1",
        target_locator={"id": "1"},
        target_kind="secret",
    )
    # Below MIN_SUBSTRING_LEN nothing is eligible, so short values cannot delete text.
    assert matcher.match(_record("the prefix ab appears")) is None


def test_fact_target_matches_bounded_variant(engine):
    result = engine.scan(
        target_id=SOURCE_ID,
        target_kind="fact",
        target_text="retention pool covers 18 engineers",
    )
    ids = {c["record_id"] for c in result["candidates"] if c["evidence_class"] == "DIRECT_MATCH"}
    assert "fs:generated-summary.md" in ids
    assert SOURCE_ID in ids


def test_entity_heuristic_and_related_nondisclosing(engine):
    assert "halcyon robotics" in extract_entities(ACQUISITION_PLAN)
    assert shares_entity(ACQUISITION_PLAN, "Halcyon Robotics released a public SDK.")
    result = engine.scan(target_id=SOURCE_ID)
    classes = {c["record_id"]: c["evidence_class"] for c in result["candidates"]}
    assert classes["fs:eng-notes.md"] == "RELATED_NONDISCLOSING"
    assert "mem:mem-unrelated-eng" not in classes


def test_fingerprint_is_keyed_hmac():
    assert fingerprint("same", "key-a") != fingerprint("same", "key-b")
    assert len(fingerprint("same", "key-a")) == 64
    assert normalize_loose("A  B\nC") == "a b c"


def test_minimize_snippet_removes_values():
    snippet = minimize_snippet(
        "Contact alice@example.com with sk-test-ABCDEF123456 and $42,000,000 at https://x/y"
    )
    assert "alice@example.com" not in snippet
    assert "sk-test-ABCDEF123456" not in snippet
    assert "42,000,000" not in snippet
    assert "https://x/y" not in snippet


def test_null_assessor_never_guesses():
    outcome = NullAssessor().assess([CandidateContext("c1", "some text", "memory")])
    assert outcome.assessments == {}
    assert outcome.errors["c1"] == "model_unavailable"


def _fake_settings(tmp_path):
    return seeded_settings(
        tmp_path,
        model_provider="openai_compatible",
        model_base_url="http://127.0.0.1:9/v1",
        model_name="fake-model",
        model_timeout_seconds=0.2,
    )


def test_invalid_model_json_is_unassessed_and_non_destructive(tmp_path, monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"choices": [{"message": {"content": "this is not json"}}]}

    monkeypatch.setattr(ra.httpx, "post", lambda *a, **k: FakeResponse())
    engine = Engine(_fake_settings(tmp_path))
    result = engine.scan(target_id=SOURCE_ID)
    classes = {c["record_id"]: c["evidence_class"] for c in result["candidates"]}
    assert classes["mem:mem-candidate-paraphrase"] == "SUSPECTED_DERIVATIVE"
    assert result["model"]["used"] is True
    assert result["model"]["unassessed"] >= 1
    # No model path may ever produce confirmed lineage.
    assert all(
        c["evidence_class"] != "CONFIRMED_DESCENDANT"
        for c in result["candidates"]
        if c["record_id"] == "mem:mem-candidate-paraphrase"
    )


def test_model_timeout_is_unassessed(tmp_path, monkeypatch):
    def boom(*args, **kwargs):
        raise httpx.TimeoutException("timed out")

    monkeypatch.setattr(ra.httpx, "post", boom)
    engine = Engine(_fake_settings(tmp_path))
    result = engine.scan(target_id=SOURCE_ID)
    assert result["model"]["provider_error"] == "timeout"
    assert result["model"]["assessed"] == 0
    assert result["model"]["unassessed"] >= 1


def test_valid_model_output_stays_a_candidate(tmp_path, monkeypatch):
    payload = {
        "assessments": [
            {
                "candidate_id": "mem:mem-candidate-paraphrase",
                "relationship": "possible_derivative",
                "fact_overlap": ["valuation"],
                "evidence": ["paraphrases the [NUMBER] valuation"],
                "recommended_action": "review",
                "uncertainty": "medium",
            }
        ]
    }

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"choices": [{"message": {"content": json.dumps(payload)}}]}

    monkeypatch.setattr(ra.httpx, "post", lambda *a, **k: FakeResponse())
    engine = Engine(_fake_settings(tmp_path))
    result = engine.scan(target_id=SOURCE_ID)
    candidate = next(
        c for c in result["candidates"] if c["record_id"] == "mem:mem-candidate-paraphrase"
    )
    assert candidate["evidence_class"] == "SUSPECTED_DERIVATIVE"
    assert candidate["evidence_class"] != "CONFIRMED_DESCENDANT"
    assert candidate["approved"] is False
    assert result["model"]["assessed"] == 1