"""Real vector database (Chroma) and cache (Redis) adapters, end to end.

Chroma runs for real in a temp folder. Redis uses fakeredis, an in-process
implementation of the protocol including WATCH/MULTI; set REDACTO_TEST_REDIS_URL
to run the Redis tests against a real server too.
"""

from __future__ import annotations

import json
import os
from dataclasses import replace

import pytest

from conftest import approve_and_apply
from helpers import seeded_settings
from redacto.adapters.base import AdapterError
from redacto.engine import Engine
from redacto.fixtures import ACQUISITION_PLAN, SOURCE_ID

chromadb = pytest.importorskip("chromadb")
fakeredis = pytest.importorskip("fakeredis")

SECRET = "sk-live-REALSTORE-0123456789abcdef"
DIM = 8


def _vec(seed: int) -> list[float]:
    return [((seed * 31 + i * 7) % 17) / 17 for i in range(DIM)]


@pytest.fixture
def chroma_settings(tmp_path):
    settings = seeded_settings(tmp_path)
    path = tmp_path / "chroma"
    path.mkdir()
    client = chromadb.PersistentClient(path=str(path))
    docs = client.create_collection("agent_docs")
    docs.add(
        ids=["doc-copy", "doc-chunk-2", "eng-note"],
        documents=[
            ACQUISITION_PLAN,
            "Unrelated: the deploy pipeline runs nightly.",
            "Engineering note about the public SDK.",
        ],
        metadatas=[
            {"source": "acquisition-plan.md", "page": 1},
            {"source": "runbook.md"},
            {"source": "eng-notes.md", "auth": json.dumps({"token": SECRET})},
        ],
        embeddings=[_vec(1), _vec(2), _vec(3)],
    )
    other = client.create_collection("not_in_scope")
    other.add(ids=["x"], documents=[ACQUISITION_PLAN], embeddings=[_vec(4)])
    return replace(settings, chroma_path=path, chroma_collections=("agent_docs",))


def _chroma_items(settings, collection="agent_docs") -> dict[str, str]:
    client = chromadb.PersistentClient(path=str(settings.chroma_path))
    page = client.get_collection(collection).get(include=["documents"])
    return dict(zip(page["ids"], page["documents"]))


def test_chroma_copy_of_the_document_is_invalidated_and_verified(chroma_settings):
    engine = Engine(chroma_settings)
    plan = engine.plan(target_id=SOURCE_ID)
    item = next(i for i in plan["items"] if i["record_id"] == "chroma:agent_docs/doc-copy")
    assert item["evidence_class"] == "DIRECT_MATCH"
    assert item["proposed_action"] == "INVALIDATE_INDEX"
    assert item["approved"] is True
    applied = approve_and_apply(engine, plan)
    assert applied["counts"]["failed"] == 0, [r for r in applied["results"] if r["result"] == "failed"][0].get("message")
    remaining = _chroma_items(chroma_settings)
    assert "doc-copy" not in remaining
    assert {"doc-chunk-2", "eng-note"} <= set(remaining)
    # A collection outside the configured scope is never touched.
    assert "x" in _chroma_items(chroma_settings, "not_in_scope")
    receipt = engine.verify(request_id=applied["request_id"])
    chroma = next(s for s in receipt["stores"] if s["store_id"] == "chroma")
    assert chroma["outcome"] == "verified"


def test_chroma_secret_in_nested_metadata_is_found_and_removed(chroma_settings):
    engine = Engine(chroma_settings)
    plan = engine.plan(target_id=SOURCE_ID, target_kind="secret", target_text=SECRET, mode="fact_revocation")
    item = next(i for i in plan["items"] if i["record_id"] == "chroma:agent_docs/eng-note")
    assert item["approved"] is True
    assert item["proposed_action"] == "INVALIDATE_INDEX"  # embeddings are never edited in place
    applied = approve_and_apply(engine, plan)
    assert "eng-note" not in _chroma_items(chroma_settings)
    receipt = engine.verify(request_id=applied["request_id"])
    assert receipt["counts"]["residual_matches"] == 0
    assert SECRET not in json.dumps([plan, applied, receipt])


def test_chroma_item_changed_after_planning_is_not_deleted(chroma_settings):
    engine = Engine(chroma_settings)
    plan = engine.plan(target_id=SOURCE_ID)
    client = chromadb.PersistentClient(path=str(chroma_settings.chroma_path))
    client.get_collection("agent_docs").update(
        ids=["doc-copy"], documents=["rewritten by the agent"], embeddings=[_vec(9)]
    )
    applied = approve_and_apply(engine, plan)
    result = next(r for r in applied["results"] if r.get("record_id") == "chroma:agent_docs/doc-copy")
    assert result["error_code"] == "content_changed"
    assert "doc-copy" in _chroma_items(chroma_settings)


def test_chroma_requires_an_explicit_collection_allowlist(tmp_path):
    from redacto.adapters.chroma_store import ChromaAdapter

    with pytest.raises(AdapterError) as excinfo:
        ChromaAdapter(tmp_path, ())
    assert excinfo.value.code == "scope_unavailable"


# ------------------------------------------------------------------- Redis
@pytest.fixture
def redis_client():
    url = os.environ.get("REDACTO_TEST_REDIS_URL")
    if url:
        import redis

        client = redis.Redis.from_url(url)
        client.flushdb()
        yield client
        client.flushdb()
    else:
        yield fakeredis.FakeRedis()


@pytest.fixture
def redis_settings(tmp_path, redis_client, monkeypatch):
    import redis

    settings = seeded_settings(tmp_path)
    redis_client.set("llm-cache:q1", json.dumps({"prompt": "summarise the plan", "answer": ACQUISITION_PLAN}))
    redis_client.hset("llm-cache:q2", mapping={"prompt": "deploy?", "answer": "Nightly at 2am."})
    redis_client.set("llm-cache:q3", f"Use the key {SECRET} for the data room.")
    redis_client.set("session:abc", ACQUISITION_PLAN)  # outside the configured patterns
    monkeypatch.setattr(redis.Redis, "from_url", classmethod(lambda cls, url, **kw: redis_client))
    return replace(settings, redis_url="redis://configured", redis_key_patterns=("llm-cache:*",))


def test_redis_cached_copy_is_invalidated_and_out_of_scope_keys_are_untouched(redis_settings, redis_client):
    engine = Engine(redis_settings)
    plan = engine.plan(target_id=SOURCE_ID)
    item = next(i for i in plan["items"] if i["record_id"] == "redis:llm-cache:q1")
    assert item["evidence_class"] == "DIRECT_MATCH"
    assert item["proposed_action"] == "INVALIDATE_CACHE"
    assert not any(i["record_id"] == "redis:session:abc" for i in plan["items"])
    applied = approve_and_apply(engine, plan)
    assert applied["counts"]["failed"] == 0
    assert redis_client.exists("llm-cache:q1") == 0
    assert redis_client.exists("llm-cache:q2") == 1
    assert redis_client.exists("session:abc") == 1
    receipt = engine.verify(request_id=applied["request_id"])
    redis_store = next(s for s in receipt["stores"] if s["store_id"] == "redis_cache")
    assert redis_store["outcome"] == "verified"


def test_redis_secret_is_removed_and_never_echoed(redis_settings, redis_client):
    engine = Engine(redis_settings)
    plan = engine.plan(target_id=SOURCE_ID, target_kind="secret", target_text=SECRET, mode="fact_revocation")
    applied = approve_and_apply(engine, plan)
    assert redis_client.exists("llm-cache:q3") == 0
    receipt = engine.verify(request_id=applied["request_id"])
    assert receipt["counts"]["residual_matches"] == 0
    assert SECRET not in json.dumps([plan, applied, receipt])


def test_redis_entry_changed_after_planning_is_not_deleted(redis_settings, redis_client):
    engine = Engine(redis_settings)
    plan = engine.plan(target_id=SOURCE_ID)
    redis_client.set("llm-cache:q1", "a fresh, unrelated answer")
    applied = approve_and_apply(engine, plan)
    result = next(r for r in applied["results"] if r.get("record_id") == "redis:llm-cache:q1")
    assert result["error_code"] == "content_changed"
    assert redis_client.get("llm-cache:q1") == b"a fresh, unrelated answer"


def test_redis_rejects_a_catch_all_pattern(redis_client):
    from redacto.adapters.redis_cache import RedisCacheAdapter

    with pytest.raises(AdapterError):
        RedisCacheAdapter(None, ("*",), client=redis_client)
    adapter = RedisCacheAdapter(None, ("llm-cache:*",), client=redis_client)
    with pytest.raises(AdapterError) as excinfo:
        adapter.delete_record({"key": "session:abc"})
    assert excinfo.value.code == "out_of_scope"


def test_status_reports_real_stores_without_the_redis_url(redis_settings):
    status = Engine(redis_settings).status(transport="test")
    assert any(a["adapter_id"] == "redis_cache" and a["health"]["reachable"] for a in status["adapters"])
    assert "redis://" not in json.dumps(status)
