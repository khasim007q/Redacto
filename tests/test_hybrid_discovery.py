"""Complementary evidence, persisted model compatibility and merge regressions."""

import json
import math
import os
from dataclasses import replace

import pytest

from conftest import approve_and_apply
from redacto.discovery.embeddings import (
    DIMENSION, MODEL_ID, HYBRID_PREFIX, HybridEmbeddingProvider,
    build_embedder, embedding_matches, embedding_models_covered, embedding_scores,
)
from redacto.engine import Engine
from redacto.errors import RedactoError
from redacto.fixtures import SOURCE_ID
from redacto.ingestion import TombstoneGuard, TombstoneMaterial

NEURAL_ID = "sentence-transformers:synthetic/test@revision:chunk-mean-v1"
HYBRID_ID = f"{HYBRID_PREFIX}{MODEL_ID}|{NEURAL_ID}"


def _axis(x=1.0):
    return [x, math.sqrt(1 - x * x)] + [0.0] * (DIMENSION - 2)


def test_lexical_and_neural_scores_use_independent_thresholds_not_averaged_cosine():
    first = _axis() + [1.0, 0.0]
    lexical_only = _axis(0.4) + [0.0, 1.0]
    neural_only = _axis(0.0) + [0.9, math.sqrt(1 - 0.9 ** 2)]
    assert embedding_matches(first, HYBRID_ID, lexical_only, HYBRID_ID,
                             threshold=0.55, lexical_threshold=0.25) == {MODEL_ID: pytest.approx(0.4)}
    assert embedding_matches(first, HYBRID_ID, neural_only, HYBRID_ID,
                             threshold=0.55, lexical_threshold=0.25) == {NEURAL_ID: pytest.approx(0.9)}


def test_upgrading_to_hybrid_preserves_both_old_model_spaces_without_reembedding():
    vector = _axis() + [0.6, 0.8]
    assert embedding_models_covered(MODEL_ID, HYBRID_ID)
    assert embedding_models_covered(NEURAL_ID, HYBRID_ID)
    assert not embedding_models_covered(HYBRID_ID, MODEL_ID)
    assert not embedding_models_covered(HYBRID_ID, NEURAL_ID)
    assert embedding_scores(vector, HYBRID_ID, _axis(), MODEL_ID) == {MODEL_ID: pytest.approx(1.0)}
    assert embedding_scores(vector, HYBRID_ID, [0.6, 0.8], NEURAL_ID) == {NEURAL_ID: pytest.approx(1.0)}
    assert embedding_scores(vector, HYBRID_ID, [0.6, 0.8], NEURAL_ID.replace("revision", "different")) == {}


@pytest.mark.parametrize("vector", [[0.0] * DIMENSION, [float("nan")] * (DIMENSION + 2)])
def test_malformed_stored_hybrid_vectors_cannot_be_reported_as_clean(vector):
    with pytest.raises(RedactoError) as exc:
        embedding_scores(vector, HYBRID_ID, _axis() + [1.0, 0.0], HYBRID_ID)
    assert exc.value.code == "embedding_vector_invalid"


def test_dimension_mismatch_in_the_same_pinned_model_fails_closed():
    with pytest.raises(RedactoError) as exc:
        embedding_scores([1.0], NEURAL_ID, [1.0, 0.0], NEURAL_ID)
    assert exc.value.code == "embedding_dimension_mismatch"


class FixedNeural:
    model_id = NEURAL_ID

    def embed(self, text):
        return [1.0, 0.0] if "confidential" in text or "secreto" in text else [0.0, 1.0]


def test_hybrid_tombstone_roundtrip_quarantines_translation_without_blocking_or_deleting(engine):
    provider = HybridEmbeddingProvider(FixedNeural())
    material = TombstoneMaterial.build("confidential source text", engine.settings.current_hmac_key, provider)
    identity = engine.repo.add_tombstone(request_id="synthetic", target_id="fs:original.md", target_kind="source",
        label_redacted="original", fingerprint_value=material.fingerprint, shingles=material.shingles,
        anchors=material.anchors, tokens=material.tokens, related_record_ids=[], related_fingerprints=[], scope={}, policy={},
        embedding=material.embedding, embedding_model=material.embedding_model, status="active")
    assert engine.repo.get_tombstone(identity)["embedding_model"] == HYBRID_ID
    guard = TombstoneGuard.from_repo(engine.repo, keyring=engine.settings.hmac_keys, current_version=1,
                                     embedder=provider, embedding_threshold=0.60)
    assert guard.evaluate(record_id="translated", content="Un secreto completamente reformulado.").decision == "quarantined"
    assert guard.evaluate(record_id="public", content="The public SDK supports Linux.").decision == "allowed"
    assert not guard.skipped_embedding_models


def test_old_hashing_tombstones_still_protect_after_hybrid_upgrade(engine):
    plan = engine.plan(target_id=SOURCE_ID)
    approve_and_apply(engine, plan)
    updated = Engine(replace(engine.settings, embedding_provider="hybrid", embedding_candidate_threshold=0.55,
                             embedding_quarantine_threshold=0.60))
    updated._embedder = HybridEmbeddingProvider(FixedNeural())
    assert not updated.guard().skipped_embedding_models
    assert not updated.status(transport="test")["revocation"]["semantic_protection_degraded"]
    assert updated.verify(request_id=plan["request_id"])["status"] != "PARTIAL"
    # This record requires the old lexical space; it has no source identity or keyed anchors.
    decision = updated.guard().evaluate(record_id="new", content="A private firm is buying the sensor maker for about 42 million in cash.")
    assert decision.decision == "quarantined"


def test_hybrid_configuration_validates_thresholds(tmp_path, monkeypatch):
    from redacto.config import load_settings

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("REDACTO_EMBEDDING_PROVIDER", "hybrid")
    for name in ("REDACTO_EMBEDDING_CANDIDATE_THRESHOLD", "REDACTO_EMBEDDING_QUARANTINE_THRESHOLD"):
        monkeypatch.delenv(name, raising=False)
    settings = load_settings()
    assert (settings.embedding_candidate_threshold, settings.embedding_quarantine_threshold) == (0.55, 0.60)
    assert (settings.embedding_lexical_candidate_threshold, settings.embedding_lexical_quarantine_threshold) == (0.25, 0.30)
    with pytest.raises(RedactoError):
        replace(settings, embedding_lexical_quarantine_threshold=float("nan"))
    assert build_embedder("hybrid").model_id.startswith(HYBRID_PREFIX)


def test_existing_main_database_backfills_missing_secret_length(engine):
    secret = "credentialMigration1234567"
    plan = engine.plan(target_id=SOURCE_ID, target_kind="secret", target_text=secret, mode="fact_revocation")
    approve_and_apply(engine, plan)
    with engine.repo._connect() as conn:
        conn.execute("UPDATE tombstones SET normalized_len = NULL")
    reopened = Engine(engine.settings)
    assert reopened.guard().evaluate(record_id="new", content=f"KEY={secret}").decision == "blocked"
    assert reopened.repo.list_tombstones()[0]["normalized_len"] == len(secret.lower())


def test_append_after_temp_is_prepared_is_preserved_on_retry(tmp_path, monkeypatch):
    from redacto.adapters.jsonl_logs import JsonlLogAdapter
    from redacto.discovery.normalization import fingerprint

    path = tmp_path / "events.jsonl"
    path.write_text('{"event_id":"old","content":"revoke"}\n')
    adapter = JsonlLogAdapter(path, "key")
    expected = fingerprint(adapter.read_record({"event_id": "old"}).content, "key")
    chmod = os.chmod
    appended = False

    def late_append(file, mode):
        nonlocal appended
        chmod(file, mode)
        if not appended and str(file).endswith(".tmp"):
            appended = True
            with path.open("a") as handle:
                handle.write('{"event_id":"live","content":"keep"}\n')

    monkeypatch.setattr(os, "chmod", late_append)
    adapter.delete_record({"event_id": "old"}, expected_fingerprint=expected)
    assert [json.loads(line)["event_id"] for line in path.read_text().splitlines()] == ["live"]
