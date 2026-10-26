"""Security properties: scope, injection, secrets and the approval boundary."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from conftest import approve_and_apply
from helpers import seeded_settings
from redacto.adapters.base import AdapterError, Record
from redacto.adapters.filesystem import FilesystemAdapter
from redacto.adapters.sqlite_store import SqliteMemoryAdapter
from redacto.engine import Engine
from redacto.errors import RedactoError
from redacto.fixtures import SOURCE_ID


def test_path_traversal_is_rejected(engine):
    adapter = FilesystemAdapter(engine.settings.workspace_root)
    outside = engine.settings.workspace_root.parent / "secret.txt"
    for locator in ({"path": "../../secret.txt"}, {"path": str(outside)}, {"path": ".."}):
        with pytest.raises(AdapterError) as excinfo:
            adapter.read_record(locator)
        assert excinfo.value.code in {"out_of_scope", "invalid_locator"}


def test_unapproved_sqlite_table_is_rejected(engine):
    adapter = SqliteMemoryAdapter(engine.settings.sqlite_store_path)
    with pytest.raises(AdapterError) as excinfo:
        adapter.delete_record({"table": "memories; DROP TABLE memories", "id": "x"})
    assert excinfo.value.code == "out_of_scope"


def test_embedded_instruction_cannot_escalate_scope(engine):
    plan = engine.plan(target_id=SOURCE_ID)
    instruction_item = next(i for i in plan["items"] if i["record_id"] == "fs:eng-notes.md")
    assert instruction_item["approved"] is False
    assert instruction_item["proposed_action"] == "SKIP_PRESERVE"

    applied = approve_and_apply(engine, plan)
    assert applied["counts"]["failed"] == 0
    assert (engine.settings.workspace_root / "eng-notes.md").exists()


def test_agent_role_has_no_approval_tool():
    from redacto.mcp.server import create_server

    server = create_server()
    names = {tool.name for tool in asyncio.run(server.list_tools())}
    assert "redacto_apply" in names
    assert not any("approve" in name for name in names)


def test_secret_target_value_is_never_persisted(tmp_path):
    settings = seeded_settings(tmp_path)
    engine = Engine(settings)
    secret = "sk-synthetic-SECRET-9f3a7c1e-NEVER-STORE"
    result = engine.scan(target_id=SOURCE_ID, target_kind="secret", target_text=secret)
    plan = engine.plan(target_id=SOURCE_ID, target_kind="secret", target_text=secret, mode="fact_revocation")

    db_bytes = Path(settings.db_path).read_bytes()
    assert secret.encode() not in db_bytes
    assert secret not in json.dumps(result)
    assert secret not in json.dumps(plan)
    for path in settings.workspace_root.rglob("*"):
        if path.is_file():
            assert secret.encode() not in path.read_bytes()


def test_short_secret_target_is_rejected(engine):
    with pytest.raises(RedactoError) as excinfo:
        engine.scan(target_id=SOURCE_ID, target_kind="secret", target_text="abc")
    assert excinfo.value.code == "invalid_target_value"


def test_scope_cannot_be_broadened_by_request(engine):
    with pytest.raises(RedactoError) as excinfo:
        engine.plan(target_id=SOURCE_ID, stores=["/etc", "filesystem"])
    assert excinfo.value.code == "out_of_scope_store"


def test_http_server_refuses_to_start_without_token(tmp_path, monkeypatch):
    monkeypatch.setenv("REDACTO_HTTP_TOKEN", "")
    monkeypatch.setenv("REDACTO_HTTP_HOST", "127.0.0.1")
    from redacto.mcp import http_server

    with pytest.raises(RuntimeError):
        http_server.build_app()


def test_unapproved_plan_cannot_be_applied_through_engine_api(engine):
    plan = engine.plan(target_id=SOURCE_ID)
    with pytest.raises(RedactoError) as excinfo:
        engine.apply(
            plan_id=plan["plan_id"],
            plan_version=plan["plan_version"],
            approval_ref="not-approved",
            confirmation_token="guess",
        )
    assert excinfo.value.code == "unauthorized_apply"


def test_oversized_ingestion_is_skipped_and_not_written(tmp_path):
    from helpers import seeded_settings

    settings = seeded_settings(tmp_path, max_record_bytes=100)
    engine = Engine(settings)
    record = Record(
        record_id="fs:oversized.md",
        record_type="doc",
        store_id="filesystem",
        locator={"path": "oversized.md"},
        content="x" * 5_000,
        sensitivity=["confidential"],
    )
    result = engine.ingest([record], store_id="filesystem", write_to_store=True)
    assert result["counts"]["skipped"] == 1
    assert result["results"][0]["reason_code"] == "oversized_record"
    assert not (settings.workspace_root / "oversized.md").exists()
    assert engine.repo.get_record("fs:oversized.md") is None


def test_oversized_scanned_records_are_reported_not_admitted(tmp_path):
    from helpers import seeded_settings

    settings = seeded_settings(tmp_path, max_record_bytes=100)
    engine = Engine(settings)
    scan = engine.scan(target_id=SOURCE_ID)
    assert scan["guard"]["counts"]["skipped"] >= 1
    assert any(
        finding["reason_code"] == "oversized_record" for finding in scan["guard"]["findings"]
    )
    # The oversized target is not classified as a candidate.
    assert scan["counts"]["direct_match"] == 0