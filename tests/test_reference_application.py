"""Real persistent application writes, live revocation and bypass evidence."""

import json
import sqlite3

import httpx
import pytest

from conftest import approve_and_apply
from redacto.adapters.base import Record
from redacto.discovery.embeddings import HashingEmbeddingProvider
from redacto.errors import RedactoError

pytest.importorskip("chromadb")
from redacto.reference import MemoryApplication, create_app

PRIVATE = "Aster will acquire Lumen for 48 million dollars this November. The confidential agreement closes on November 14."
PUBLIC = "The public SDK supports Linux and Windows. Accessibility testing runs each Friday."


def test_live_application_revokes_across_all_stores_and_preserves_public_context(tmp_path):
    app = MemoryApplication(tmp_path)
    app.document("private", PRIVATE)
    app.document("public", PUBLIC)
    app.summarize("mixed", ["fs:private.md", "fs:public.md"])
    before = app.query("Aster Lumen acquisition")
    assert "48 million" in before["answer"]
    # Reopening the app proves persistence instead of an in-memory demo.
    app = MemoryApplication(tmp_path)
    plan = app.engine.plan(target_id="fs:private.md", depth=5)
    stores = {app.engine.repo.get_record(i["record_id"])["store_id"] for i in plan["items"] if i["approved"]}
    assert {"filesystem", "sqlite_memory", "jsonl_logs", "chroma"} <= stores
    result = approve_and_apply(app.engine, plan)
    assert result["counts"]["failed"] == 0
    after = app.query("public SDK Linux")
    assert "Linux" in after["answer"]
    assert "48 million" not in after["answer"]
    assert "Aster" not in after["answer"]
    receipt = app.engine.verify(request_id=plan["request_id"])
    assert receipt["counts"]["residual_matches"] == 0
    assert receipt["counts"]["records_regenerated"] >= 1
    assert receipt["counts"]["records_removed"] < result["counts"]["succeeded"]
    assert (tmp_path / "documents/public.md").read_text() == PUBLIC
    with sqlite3.connect(app.engine.settings.sqlite_store_path) as conn:
        summary = conn.execute("SELECT content FROM memories WHERE id = 'mixed'").fetchone()
    assert summary is not None and summary[0] == PUBLIC
    with pytest.raises(RedactoError):
        app.document("restored", PRIVATE)
    with pytest.raises(RedactoError):
        app.remember("replay", PRIVATE)
    with pytest.raises(RedactoError):
        app.summarize("rebuild", ["fs:private.md"])
    assert app.engine.guard().active_count >= 1


def test_direct_database_and_index_bypasses_are_detected_and_filtered(tmp_path):
    app = MemoryApplication(tmp_path)
    app.document("private", PRIVATE)
    plan = app.engine.plan(target_id="fs:private.md", depth=5)
    approve_and_apply(app.engine, plan)
    # Deliberately ignore the integration boundary as a legacy writer might.
    with sqlite3.connect(app.engine.settings.sqlite_store_path) as conn:
        conn.execute("INSERT INTO memories VALUES (?, ?, ?, ?)", ("bypass", PRIVATE, "", "unknown"))
    app._index.upsert(ids=["bypass"], documents=[PRIVATE], embeddings=[HashingEmbeddingProvider().embed(PRIVATE)])
    answer = app.query("Aster Lumen acquisition")
    assert answer["answer"] == ""
    report = app.reconcile()
    assert report["counts"]["blocked"] >= 2
    ids = {f["record_id"] for f in report["findings"]}
    assert {"mem:bypass", "chroma:context/bypass"} <= ids
    receipt = app.engine.verify(request_id=plan["request_id"])
    assert receipt["status"] == "PARTIAL"
    assert PRIVATE not in json.dumps(receipt)


@pytest.mark.asyncio
async def test_http_application_uses_guarded_writes_without_exposing_approval(tmp_path):
    asgi = create_app(tmp_path, token="test-token")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=asgi), base_url="http://local", headers={"Authorization": "Bearer test-token"}) as client:
        assert (await client.post("/documents", json={"id": "public", "text": PUBLIC})).status_code == 200
        assert "Linux" in (await client.get("/query", params={"q": "Linux"})).json()["answer"]
        assert (await client.post("/approve", json={})).status_code == 404
        assert (await client.post("/documents", json={"id": "../escape", "text": PUBLIC})).status_code == 409
        assert (await client.get("/query", headers={"Authorization": "Bearer invalid"})).status_code == 401


def test_metadata_secret_cannot_enter_reference_write_path(tmp_path):
    app = MemoryApplication(tmp_path)
    app.document("anchor", PUBLIC)
    secret = "credential9fA81bd19"
    plan = app.engine.plan(target_id="fs:anchor.md", target_kind="secret", target_text=secret, mode="fact_revocation")
    approve_and_apply(app.engine, plan)
    with app.engine.write_boundary(), pytest.raises(RedactoError):
        app._admit(Record(record_id="chroma:context/new", record_type="index_entry", store_id="chroma",
                          locator={"id": "new", "collection": "context"}, content="public", metadata={"token": secret}))
    assert app._index.count() == 1  # only original public anchor
