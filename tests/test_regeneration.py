"""REGENERATE_FROM_ALLOWED_SOURCES: rebuild a derivative from the sources that remain."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import replace

import pytest

from conftest import approve_and_apply
from helpers import seeded_settings
from redacto.engine import Engine
from redacto.fixtures import ACQUISITION_PLAN, SOURCE_ID
from redacto.regeneration import RegenerationError, build_regenerator

MINUTES = (
    "# Board minutes, October\n\nThe board approved the new office lease in Austin and "
    "hired two support engineers. The quarterly offsite moves to November.\n"
)
SUMMARY_ID = "fs:generated-summary.md"


class FakeRegenerator:
    model_id = "fake-regenerator"

    def __init__(self, output: str | None = None):
        self.output = output
        self.calls: list[dict] = []

    def regenerate(self, *, record_type, current_length, sources):
        self.calls.append({"record_type": record_type, "sources": list(sources)})
        if self.output is not None:
            return self.output
        return "Summary: " + " ".join(source.strip().splitlines()[-1] for source in sources)


@pytest.fixture
def regen(tmp_path, monkeypatch):
    settings = replace(seeded_settings(tmp_path), regenerate_derivatives=True)
    (settings.workspace_root / "board-minutes.md").write_text(MINUTES, encoding="utf-8")
    engine = Engine(settings)
    engine.scan(target_id="fs:board-minutes.md")  # admit the new source into the graph
    engine.record_lineage(
        source_ids=["fs:board-minutes.md"],
        output_id=SUMMARY_ID,
        relation="SUMMARIZED_FROM",
        evidence_type="instrumented",
        evidence_ref="summariser-run-42",
    )
    fake = FakeRegenerator()
    monkeypatch.setattr(Engine, "regenerator", lambda self: fake)
    return settings, engine, fake


def _item(plan, record_id):
    return next(i for i in plan["items"] if i["record_id"] == record_id)


def test_derivative_with_other_sources_is_regenerated_not_deleted(regen):
    settings, engine, fake = regen
    plan = engine.plan(target_id=SOURCE_ID)
    item = _item(plan, SUMMARY_ID)
    assert item["proposed_action"] == "REGENERATE_FROM_ALLOWED_SOURCES"
    assert item["approved"] is True
    assert item["regen_sources"] == ["fs:board-minutes.md"]
    # A descendant whose only parents are being revoked is still deleted.
    assert _item(plan, "mem:mem-summary-paraphrase")["proposed_action"] == "DELETE_RECORD"

    applied = approve_and_apply(engine, plan)
    assert applied["counts"]["failed"] == 0
    summary = (settings.workspace_root / "generated-summary.md").read_text(encoding="utf-8")
    assert summary.startswith("Summary: ")
    assert "quarterly offsite" in summary
    assert fake.calls and fake.calls[0]["sources"][0] == MINUTES
    assert ACQUISITION_PLAN not in json.dumps(fake.calls)  # the revoked source is never sent

    receipt = engine.verify(request_id=applied["request_id"])
    assert receipt["counts"]["residual_matches"] == 0
    parents = {e["source_id"]: e["relation"] for e in engine.repo.parent_edges(SUMMARY_ID)}
    assert parents == {"fs:board-minutes.md": "REGENERATED_FROM"}
    # The regenerated record is not treated as revoked by the tombstone.
    guard = engine.reingest_stores(stores=["filesystem"])
    assert not any(f["record_id"] == SUMMARY_ID and f.get("decision") == "blocked" for f in guard["findings"])


def test_regenerated_text_that_leaks_the_target_is_never_written(regen):
    settings, engine, fake = regen
    fake.output = ACQUISITION_PLAN  # a model that just repeats what it remembers
    before = (settings.workspace_root / "generated-summary.md").read_text(encoding="utf-8")
    plan = engine.plan(target_id=SOURCE_ID)
    applied = approve_and_apply(engine, plan)
    result = next(r for r in applied["results"] if r.get("record_id") == SUMMARY_ID)
    assert result["error_code"] == "regenerate_leak"
    assert (settings.workspace_root / "generated-summary.md").read_text(encoding="utf-8") == before
    receipt = engine.verify(request_id=applied["request_id"])
    assert receipt["status"] == "PARTIAL"


def test_regeneration_is_opt_in(regen, monkeypatch):
    settings, _, _ = regen
    engine = Engine(replace(settings, regenerate_derivatives=False))
    plan = engine.plan(target_id=SOURCE_ID)
    assert _item(plan, SUMMARY_ID)["proposed_action"] == "DELETE_RECORD"


def test_no_model_means_no_regeneration(regen, monkeypatch):
    _, engine, _ = regen
    monkeypatch.setattr(Engine, "regenerator", lambda self: build_regenerator(provider="none", base_url=None, model=None))
    plan = engine.plan(target_id=SOURCE_ID)
    assert _item(plan, SUMMARY_ID)["proposed_action"] == "DELETE_RECORD"


def test_secret_revocation_never_regenerates(regen):
    _, engine, _ = regen
    plan = engine.plan(
        target_id=SOURCE_ID, target_kind="secret", target_text="sk-live-NOTHERE-0123456789", mode="fact_revocation"
    )
    assert not any(i["proposed_action"] == "REGENERATE_FROM_ALLOWED_SOURCES" for i in plan["items"])


def test_regenerated_memory_row_keeps_its_identity(tmp_path, monkeypatch):
    settings = replace(seeded_settings(tmp_path), regenerate_derivatives=True)
    conn = sqlite3.connect(settings.sqlite_store_path)
    conn.execute(
        "INSERT INTO memories (id, content, created_at, sensitivity) VALUES ('mem-prefs', 'User prefers weekly digests.', '2026-10-01', 'low')"
    )
    conn.commit()
    conn.close()
    engine = Engine(settings)
    engine.scan(target_id="mem:mem-prefs")
    engine.record_lineage(
        source_ids=["mem:mem-prefs"], output_id="mem:mem-summary-paraphrase",
        relation="DERIVED_FROM", evidence_type="instrumented", evidence_ref="memory-writer-7",
    )
    monkeypatch.setattr(Engine, "regenerator", lambda self: FakeRegenerator("User prefers weekly digests."))
    plan = engine.plan(target_id=SOURCE_ID)
    assert _item(plan, "mem:mem-summary-paraphrase")["proposed_action"] == "REGENERATE_FROM_ALLOWED_SOURCES"
    applied = approve_and_apply(engine, plan)
    assert applied["counts"]["failed"] == 0
    row = sqlite3.connect(settings.sqlite_store_path).execute(
        "SELECT content, created_at FROM memories WHERE id = 'mem-summary-paraphrase'"
    ).fetchone()
    assert row[0] == "User prefers weekly digests."


def test_plan_hash_binds_the_regeneration_sources(regen):
    settings, engine, _ = regen
    plan = engine.plan(target_id=SOURCE_ID)
    item = _item(plan, SUMMARY_ID)
    conn = sqlite3.connect(settings.db_path)
    conn.execute(
        "UPDATE revocation_plan_items SET regen_sources_json = ? WHERE item_id = ?",
        (json.dumps([SOURCE_ID]), item["item_id"]),
    )
    conn.commit()
    conn.close()
    from redacto.errors import RedactoError

    with pytest.raises(RedactoError):
        approve_and_apply(engine, plan)


def test_openai_compatible_regenerator_reports_failures(monkeypatch):
    import httpx

    from redacto import regeneration

    def boom(*args, **kwargs):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(regeneration.httpx, "post", boom)
    regenerator = build_regenerator(provider="ollama", base_url="http://127.0.0.1:1/v1", model="m")
    with pytest.raises(RegenerationError):
        regenerator.regenerate(record_type="doc", current_length=100, sources=["x"])
