"""User JSON keys and duplicate values must not disappear from verification."""
import json
from dataclasses import replace
import pytest
from conftest import approve_and_apply
from redacto.adapters.base import AdapterError
from redacto.adapters.jsonl_logs import JsonlLogAdapter
from redacto.config import load_settings
from redacto.profiles import setup_workspace
from redacto.workspace import WorkspaceClient

SECRET = "syntheticCredential9fA81b13"


@pytest.mark.parametrize("field", ["_line_index", "_event_id", "_malformed"])
@pytest.mark.parametrize("nested", [False, True])
def test_reserved_looking_fields_remain_visible_and_removable(tmp_path, field, nested):
    notes = tmp_path / "notes"
    notes.mkdir()
    client = WorkspaceClient(setup_workspace(notes, state_dir=tmp_path / "state", managed_memory=True)["profile"])
    client.write_document("anchor.md", "Public operator notes for routine backup and support procedures.")
    payload = {"event_id": "one", "content": "public", **({"args": {field: SECRET}} if nested else {field: SECRET})}
    path = client.engine.settings.jsonl_log_path
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    record = JsonlLogAdapter(path, client.engine.settings.current_hmac_key).read_record({"event_id": "one"})
    assert SECRET in record.content and record.record_id == "log:one"
    plan = client.engine.plan(target_id="fs:anchor.md", target_kind="secret", target_text=SECRET, mode="fact_revocation")
    assert any(i["record_id"] == "log:one" for i in plan["items"])
    assert approve_and_apply(client.engine, plan)["counts"]["failed"] == 0
    assert SECRET not in path.read_text(encoding="utf-8")


def test_duplicate_json_values_are_not_discarded_during_scan_or_checked_delete(tmp_path):
    from redacto.discovery.normalization import fingerprint

    path = tmp_path / "events.jsonl"
    escaped = "".join("\\u%04x" % ord(letter) for letter in SECRET)
    path.write_text('{"event_id":"one","content":"' + escaped + '","content":"public"}\n', encoding="utf-8")
    adapter = JsonlLogAdapter(path, "key")
    record = adapter.read_record({"event_id": "one"})
    assert SECRET in record.content
    adapter.delete_record(record.locator, expected_fingerprint=fingerprint(record.content, "key"))
    assert path.read_text(encoding="utf-8") == ""


def test_excessive_json_nesting_is_a_coverage_failure(tmp_path):
    path = tmp_path / "events.jsonl"
    value = SECRET
    for _ in range(70):
        value = {"nested": value}
    path.write_text(json.dumps({"event_id": "one", "args": value}), encoding="utf-8")
    with pytest.raises(AdapterError) as error:
        list(JsonlLogAdapter(path, "key").list_records())
    assert error.value.code == "record_unverifiable"
    notes = tmp_path / "notes"
    notes.mkdir()
    client = WorkspaceClient(setup_workspace(notes, state_dir=tmp_path / "state", managed_memory=True)["profile"])
    client.write_document("anchor.md", "Public operational notes describing routine backups and support procedures.")
    client.engine.settings.jsonl_log_path.write_bytes(path.read_bytes())
    plan = client.engine.plan(target_id="fs:anchor.md", target_kind="secret", target_text=SECRET, mode="fact_revocation")
    approve_and_apply(client.engine, plan)
    assert client.engine.verify(request_id=plan["request_id"])["status"] == "PARTIAL"


def test_json_chunk_index_refuses_duplicate_json_fields(tmp_path):
    from redacto.adapters.vector_fixture import VectorFixtureAdapter

    path = tmp_path / "index.json"
    path.write_text('{"chunks":[{"id":"one","text":"hidden","text":"public"}]}', encoding="utf-8")
    with pytest.raises(AdapterError) as error:
        VectorFixtureAdapter(path, "key")
    assert error.value.code == "record_unverifiable"


def test_json_chunk_index_cannot_silently_skip_deep_values(tmp_path):
    from redacto.adapters.vector_fixture import VectorFixtureAdapter

    value = SECRET
    for _ in range(70):
        value = {"nested": value}
    path = tmp_path / "index.json"
    path.write_text(json.dumps({"chunks": [{"id": "one", "metadata": value}]}), encoding="utf-8")
    with pytest.raises(AdapterError) as error:
        list(VectorFixtureAdapter(path, "key").list_records())
    assert error.value.code == "record_unverifiable"


def test_redis_json_cannot_discard_duplicate_values():
    fakeredis = pytest.importorskip("fakeredis")
    from redacto.adapters.redis_cache import RedisCacheAdapter

    client = fakeredis.FakeRedis()
    client.set("cache:one", '{"value":"hidden","value":"public"}')
    adapter = RedisCacheAdapter(None, ("cache:*",), "key", client=client)
    with pytest.raises(AdapterError) as error:
        list(adapter.list_records())
    assert error.value.code == "record_unverifiable"
