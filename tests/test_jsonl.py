"""JSONL identity and malformed-line handling.

These pin the two high-severity log bugs: deleting the wrong event when a line has
no event_id, and reporting a malformed line that holds a secret as already absent.
"""

from __future__ import annotations

import json
from pathlib import Path

from conftest import approve_and_apply
from helpers import seeded_settings
from redacto.adapters.jsonl_logs import JsonlLogAdapter
from redacto.engine import Engine
from redacto.fixtures import ACQUISITION_PLAN, SOURCE_ID


def _records(path: Path):
    adapter = JsonlLogAdapter(path, "test-key")
    return adapter, list(adapter.list_records())


def test_event_without_event_id_is_deleted_by_content_identity(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(
        "\n".join(
            [
                json.dumps({"content": "first event"}),
                json.dumps({"content": "SECRET middle event"}),
                json.dumps({"content": "third event"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    adapter, records = _records(path)
    target = next(r for r in records if "SECRET" in r.content)
    adapter.delete_record(target.locator)
    remaining = path.read_text(encoding="utf-8")
    assert "SECRET" not in remaining
    assert "first event" in remaining
    assert "third event" in remaining


def test_malformed_line_holding_a_secret_is_deleted_not_reported_absent(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(
        '{"event_id":"keep","content":"keep me"}\nRAW SECRET not-json line\n',
        encoding="utf-8",
    )
    adapter, records = _records(path)
    target = next(r for r in records if "SECRET" in r.content)
    adapter.delete_record(target.locator)  # must not raise not_found
    remaining = path.read_text(encoding="utf-8")
    assert "SECRET" not in remaining
    assert "keep me" in remaining


def test_plan_apply_deletes_a_malformed_copy_and_counts_it_as_success(tmp_path):
    settings = seeded_settings(tmp_path)
    malformed = ACQUISITION_PLAN.replace("\n", " ").strip()
    with settings.jsonl_log_path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(malformed + "\n")

    engine = Engine(settings)
    plan = engine.plan(target_id=SOURCE_ID)
    item = next(
        item
        for item in plan["items"]
        if item["record_id"].startswith("log:sha-") and item["approved"]
    )
    applied = approve_and_apply(engine, plan)
    result = next(r for r in applied["results"] if r["item_id"] == item["item_id"])
    assert result["result"] == "success"
    assert "Meridian Capital" not in settings.jsonl_log_path.read_text(encoding="utf-8")