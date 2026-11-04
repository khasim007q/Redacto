"""Adversarial coverage, verification-key retention and embedding ownership."""

import json
from dataclasses import replace

import pytest

from conftest import approve_and_apply
from redacto.adapters.base import AdapterError, Record
from redacto.engine import Engine
from redacto.errors import RedactoError
from test_support.fixtures import SOURCE_ID
from redacto.receipts import check_receipt, sign_receipt


def test_expired_tombstone_does_not_make_receipt_key_retirable(engine):
    plan = engine.plan(target_id=SOURCE_ID)
    approve_and_apply(engine, plan)
    receipt = engine.verify(request_id=plan["request_id"])
    for tombstone in engine.repo.list_tombstones():
        engine.repo.set_tombstone_status(tombstone["tombstone_id"], "expired")
    rotated = Engine(replace(engine.settings, hmac_keys={**engine.settings.hmac_keys, 2: "new"}, hmac_key_version=2))
    report = rotated.keyring_report()
    assert report["active_tombstones"] == 0
    assert report["receipts_by_key_version"] == {1: 1}
    assert 1 not in report["retirable_versions"]
    with pytest.raises(RedactoError) as exc:
        rotated.keyring_report(retire_version=1)
    assert exc.value.code == "version_still_in_use"
    assert check_receipt(receipt["receipt"], keyring=rotated.settings.hmac_keys)["valid"]


def test_pending_plan_retains_its_original_fingerprint_key(engine):
    engine.plan(target_id=SOURCE_ID)
    rotated = Engine(replace(engine.settings, hmac_keys={**engine.settings.hmac_keys, 2: "new"}, hmac_key_version=2))
    report = rotated.keyring_report()
    assert report["requests_by_key_version"] == {1: 1}
    assert report["plan_items_by_key_version"][1] > 0
    assert 1 not in report["retirable_versions"]


def test_model_change_reports_incomplete_semantic_coverage_without_comparing_vectors(engine):
    plan = engine.plan(target_id=SOURCE_ID)
    approve_and_apply(engine, plan)
    changed = Engine(replace(engine.settings, embedding_provider="none"))
    guard = changed.guard()
    assert guard.skipped_embedding_models == ["local-hashing-v2"]
    assert guard.coverage()["semantic_protection_degraded"]
    assert changed.status(transport="test")["revocation"]["semantic_protection_degraded"]
    receipt = changed.verify(request_id=plan["request_id"])
    assert receipt["status"] == "PARTIAL"
    assert receipt["receipt"]["semantic_verification"]["status"] == "incomplete"
    assert receipt["receipt"]["semantic_verification"]["skipped_embedding_models"] == ["local-hashing-v2"]


def test_secret_anchor_and_harmless_text_are_not_blocked_by_identity_or_semantics(engine):
    plan = engine.plan(target_id=SOURCE_ID, target_kind="secret", target_text="credential9fA81bd19", mode="fact_revocation")
    approve_and_apply(engine, plan)
    guard = engine.guard()
    assert guard.evaluate(record_id=SOURCE_ID, content="The public SDK supports Linux.").decision == "allowed"
    assert guard.evaluate(record_id="new", content="KEY=credential9fA81bd19").decision == "blocked"
    assert engine.repo.list_tombstones()[0]["embedding"] == []


def test_unreadable_receipt_prevents_suggesting_key_retirement(engine):
    engine.repo.save_receipt(request_id="legacy", summary={"integrity": {"key_version": True}})
    rotated = Engine(replace(engine.settings, hmac_keys={**engine.settings.hmac_keys, 2: "new"}, hmac_key_version=2))
    assert rotated.keyring_report()["retirable_versions"] == []
    with pytest.raises(RedactoError):
        rotated.keyring_report(retire_version=1)


def test_malformed_receipt_values_return_invalid_instead_of_crashing():
    receipt = sign_receipt({"counts": {}}, key="key", key_version=1)
    receipt["counts"]["removed"] = float("nan")
    assert check_receipt(receipt, keyring={1: "key"}) == {"valid": False, "reason": "invalid_receipt"}
    receipt["integrity"]["key_version"] = True
    assert not check_receipt(receipt, keyring={1: "key"})["valid"]


def test_invalid_unicode_receipt_signature_cannot_crash_the_verifier():
    receipt = sign_receipt({"counts": {}}, key="key", key_version=1)
    receipt["integrity"]["signature"] = "\ud800" * 64
    assert not check_receipt(receipt, keyring={1: "key"})["valid"]


@pytest.mark.parametrize("kind", ["set", "zset", "stream"])
def test_redis_additional_types_include_nested_disclosures_and_stable_fingerprints(kind):
    fakeredis = pytest.importorskip("fakeredis")
    from redacto.adapters.redis_cache import RedisCacheAdapter
    from redacto.discovery.normalization import fingerprint

    client = fakeredis.FakeRedis()
    key = "cache:secret"
    if kind == "set":
        client.sadd(key, "confidential value", "public value")
    elif kind == "zset":
        client.zadd(key, {"confidential value": 2.0, "public value": 1.0})
    else:
        client.xadd(key, {"nested": json.dumps({"secret": "confidential value"})})
    adapter = RedisCacheAdapter(None, ("cache:*",), "key", client=client)
    record = adapter.read_record({"key": key})
    assert "confidential value" in record.content
    assert [r.record_id for r in adapter.list_records()] == [f"redis:{key}"]
    adapter.delete_record({"key": key}, expected_fingerprint=fingerprint(record.content, "key"))
    assert not client.exists(key)


def test_redis_unknown_type_is_a_coverage_failure_not_an_empty_clean_store(monkeypatch):
    fakeredis = pytest.importorskip("fakeredis")
    from redacto.adapters.redis_cache import RedisCacheAdapter

    client = fakeredis.FakeRedis()
    client.set("cache:unreadable", "confidential")
    monkeypatch.setattr(client, "type", lambda _: b"module-type")
    adapter = RedisCacheAdapter(None, ("cache:*",), client=client)
    with pytest.raises(AdapterError) as exc:
        list(adapter.list_records())
    assert exc.value.code == "unsupported_record_type"
    assert adapter.health()["reachable"] is False
    # The mutation reads through a WATCH pipeline, not the top-level client.
    pipeline = client.pipeline
    def unsupported_pipeline(*args, **kwargs):
        pipe = pipeline(*args, **kwargs)
        monkeypatch.setattr(pipe, "type", lambda _: b"module-type")
        return pipe
    monkeypatch.setattr(client, "pipeline", unsupported_pipeline)
    with pytest.raises(AdapterError):
        adapter.delete_record({"key": "cache:unreadable"})
    assert client.exists("cache:unreadable")


@pytest.mark.parametrize("metadata", [None, {"redacto:embedding_model": "other", "redacto:embedding_dimension": 512}])
def test_chroma_refuses_unlabelled_or_different_model_even_with_same_dimension(tmp_path, metadata):
    chromadb = pytest.importorskip("chromadb")
    from redacto.adapters.chroma_store import ChromaAdapter

    client = chromadb.PersistentClient(path=str(tmp_path))
    try:
        collection = client.create_collection("external", metadata=metadata)
        collection.add(ids=["original"], documents=["keep"], embeddings=[[1.0] + [0.0] * 511])
        adapter = ChromaAdapter(tmp_path, ("external",), client=client)
        with pytest.raises(AdapterError) as exc:
            adapter.write_record(Record(record_id="chroma:external/new", record_type="index_entry", store_id="chroma",
                                        locator={"collection": "external", "id": "new"}, content="new"))
        assert exc.value.code == "embedding_model_mismatch"
        assert collection.get()["ids"] == ["original"]
        # Read/delete compatibility does not require the writer's embedding model.
        assert list(adapter.list_records())[0].core_content == "keep"
    finally:
        client.close()


def test_advisory_model_cannot_remove_a_deterministic_review_candidate(engine, monkeypatch):
    from redacto.discovery.relationship_assessor import AssessorOutcome, CandidateAssessment

    class MisleadingAssessor:
        model_id = "untrusted-model"

        def assess(self, contexts):
            assert contexts and all(c.target_snippet_redacted for c in contexts)
            return AssessorOutcome(model_id=self.model_id, assessments={c.candidate_id: CandidateAssessment(
                candidate_id=c.candidate_id, relationship="unrelated", fact_overlap=[], evidence=[],
                recommended_action="preserve", uncertainty="low") for c in contexts})

    monkeypatch.setattr(engine, "assessor", lambda: MisleadingAssessor())
    result = engine.scan(target_id=SOURCE_ID)
    candidate = next(c for c in result["candidates"] if c["record_id"] == "mem:mem-candidate-paraphrase")
    assert candidate["evidence_class"] == "SUSPECTED_DERIVATIVE"
    assert not candidate["approved"]
    assert "mem:mem-candidate-paraphrase" in result["model"]["downgrades_held_for_review"]
