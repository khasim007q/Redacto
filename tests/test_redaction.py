"""REDACT_SPAN: remove a secret from a large useful record without deleting it."""

from __future__ import annotations

import json
import sqlite3

import pytest

from conftest import approve_and_apply
from helpers import seeded_settings
from redacto.adapters.base import REDACTION_MARK, redact_spans
from redacto.discovery.normalization import fingerprint
from redacto.engine import Engine
from redacto.fixtures import SOURCE_ID

SECRET = "sk-live-REDACT-0123456789abcdef"
FILLER = " ".join(f"Useful handbook sentence number {n} about deployments." for n in range(60))


def _plan(engine: Engine) -> dict:
    return engine.plan(
        target_id=SOURCE_ID, target_kind="secret", target_text=SECRET, mode="fact_revocation"
    )


def _item(plan: dict, record_id: str) -> dict:
    return next(i for i in plan["items"] if i["record_id"] == record_id)


def test_redact_spans_replaces_every_occurrence_by_fingerprint_only():
    spans = [{"hmac": fingerprint(SECRET, "k"), "length": len(SECRET)}]
    text, count = redact_spans(f"a {SECRET} b {SECRET}.", spans, "k")
    assert count == 2
    assert text == f"a {REDACTION_MARK} b {REDACTION_MARK}."


def test_secret_in_a_large_file_is_redacted_not_deleted(tmp_path):
    settings = seeded_settings(tmp_path)
    handbook = settings.workspace_root / "handbook.md"
    handbook.write_text(f"{FILLER}\nStaging key: {SECRET}\n{FILLER}\n", encoding="utf-8")
    engine = Engine(settings)
    plan = _plan(engine)
    item = _item(plan, "fs:handbook.md")
    assert item["proposed_action"] == "REDACT_SPAN"
    assert item["approved"] is True
    assert item["risk"] == "low"
    assert SECRET not in json.dumps(plan)
    applied = approve_and_apply(engine, plan)
    assert applied["counts"]["failed"] == 0
    text = handbook.read_text(encoding="utf-8")
    assert SECRET not in text
    assert f"Staging key: {REDACTION_MARK}" in text
    assert text.count("Useful handbook sentence") == 120
    receipt = engine.verify(request_id=applied["request_id"])
    assert receipt["counts"]["residual_matches"] == 0


def test_secret_in_a_large_memory_row_is_redacted(tmp_path):
    settings = seeded_settings(tmp_path)
    conn = sqlite3.connect(settings.sqlite_store_path)
    conn.execute(
        "INSERT INTO memories (id, content, created_at, sensitivity) VALUES (?, ?, ?, ?)",
        ("mem-long", f"{FILLER} the key is {SECRET} ok", "2026-10-01", "internal"),
    )
    conn.commit()
    conn.close()
    engine = Engine(settings)
    plan = _plan(engine)
    assert _item(plan, "mem:mem-long")["proposed_action"] == "REDACT_SPAN"
    applied = approve_and_apply(engine, plan)
    assert applied["counts"]["failed"] == 0
    row = sqlite3.connect(settings.sqlite_store_path).execute(
        "SELECT content, created_at FROM memories WHERE id = 'mem-long'"
    ).fetchone()
    assert row[0].endswith(f"the key is {REDACTION_MARK} ok")
    assert row[1] == "2026-10-01"
    assert engine.verify(request_id=applied["request_id"])["counts"]["residual_matches"] == 0


def test_secret_in_a_large_log_event_is_redacted_and_json_stays_valid(tmp_path):
    settings = seeded_settings(tmp_path)
    with settings.jsonl_log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"event_id": "e-long", "content": f"{FILLER} key={SECRET}"}) + "\n")
    engine = Engine(settings)
    plan = _plan(engine)
    assert _item(plan, "log:e-long")["proposed_action"] == "REDACT_SPAN"
    applied = approve_and_apply(engine, plan)
    assert applied["counts"]["failed"] == 0
    lines = settings.jsonl_log_path.read_text(encoding="utf-8").splitlines()
    event = next(json.loads(line) for line in lines if '"e-long"' in line)
    assert event["content"].endswith(f"key={REDACTION_MARK}")
    assert engine.verify(request_id=applied["request_id"])["counts"]["residual_matches"] == 0


def test_spaced_secret_in_a_large_record_still_goes_to_review(tmp_path):
    settings = seeded_settings(tmp_path)
    spaced = " ".join(SECRET)
    (settings.workspace_root / "handbook.md").write_text(f"{FILLER}\n{spaced}\n", encoding="utf-8")
    plan = _plan(Engine(settings))
    item = _item(plan, "fs:handbook.md")
    assert item["proposed_action"] == "REVIEW_REQUIRED"
    assert item["approved"] is False


def test_record_changed_after_planning_is_not_redacted(tmp_path):
    settings = seeded_settings(tmp_path)
    handbook = settings.workspace_root / "handbook.md"
    handbook.write_text(f"{FILLER}\nkey: {SECRET}\n", encoding="utf-8")
    engine = Engine(settings)
    plan = _plan(engine)
    handbook.write_text(f"{FILLER}\nkey: {SECRET}\nnew line added later\n", encoding="utf-8")
    applied = approve_and_apply(engine, plan)
    failed = [r for r in applied["results"] if r.get("record_id") == "fs:handbook.md"]
    assert failed and failed[0]["error_code"] == "content_changed"
    assert SECRET in handbook.read_text(encoding="utf-8")


def test_vector_chunks_are_invalidated_not_redacted(tmp_path):
    settings = seeded_settings(tmp_path)
    payload = json.loads(settings.vector_fixture_path.read_text(encoding="utf-8"))
    payload["chunks"].append({"id": "c-long", "text": f"{FILLER} {SECRET}"})
    settings.vector_fixture_path.write_text(json.dumps(payload), encoding="utf-8")
    plan = _plan(Engine(settings))
    # An embedding of the old text would survive a text edit, so a chunk is never
    # redacted in place.
    assert _item(plan, "vec:c-long")["proposed_action"] != "REDACT_SPAN"


@pytest.mark.parametrize("tamper", ["drop_spans", "swap_action"])
def test_redaction_spans_are_bound_by_the_plan_hash(tmp_path, tamper):
    settings = seeded_settings(tmp_path)
    (settings.workspace_root / "handbook.md").write_text(f"{FILLER}\nkey: {SECRET}\n", encoding="utf-8")
    engine = Engine(settings)
    plan = _plan(engine)
    item = _item(plan, "fs:handbook.md")
    conn = sqlite3.connect(settings.db_path)
    if tamper == "drop_spans":
        conn.execute("UPDATE revocation_plan_items SET redact_spans_json = '[]' WHERE item_id = ?", (item["item_id"],))
    else:
        conn.execute(
            "UPDATE revocation_plan_items SET proposed_action = 'DELETE_RECORD' WHERE item_id = ?",
            (item["item_id"],),
        )
    conn.commit()
    conn.close()
    from redacto.errors import RedactoError

    with pytest.raises(RedactoError):
        approve_and_apply(engine, plan)
    assert (settings.workspace_root / "handbook.md").exists()
