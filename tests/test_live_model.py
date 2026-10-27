"""Opt-in check against a real model endpoint.

Skipped unless REDACTO_LIVE_MODEL_URL and REDACTO_LIVE_MODEL_NAME are set, e.g.
REDACTO_LIVE_MODEL_URL=http://127.0.0.1:11434/v1 REDACTO_LIVE_MODEL_NAME=llama3.
Whatever the model says, it may only move candidates between review and
preserve: the approved, destructive part of the plan must not change.
"""

from __future__ import annotations

import os
from dataclasses import replace

import pytest

from helpers import seeded_settings
from redacto.engine import Engine
from redacto.fixtures import SOURCE_ID

URL = os.environ.get("REDACTO_LIVE_MODEL_URL")
NAME = os.environ.get("REDACTO_LIVE_MODEL_NAME")

pytestmark = pytest.mark.skipif(not (URL and NAME), reason="no live model configured")


def _approved(scan: dict) -> dict[str, str]:
    return {c["record_id"]: c["proposed_action"] for c in scan["candidates"] if c["approved"]}


def test_live_model_never_changes_the_destructive_plan(tmp_path):
    settings = seeded_settings(tmp_path)
    baseline = Engine(settings).scan(target_id=SOURCE_ID, use_model=False)
    live = replace(
        settings,
        model_provider="openai_compatible",
        model_base_url=URL,
        model_name=NAME,
        model_timeout_seconds=float(os.environ.get("REDACTO_LIVE_MODEL_TIMEOUT", "180")),
    )
    assessed = Engine(live).scan(target_id=SOURCE_ID)
    assert assessed["model"]["used"] is True
    assert assessed["model"]["provider_error"] is None
    assert _approved(assessed) == _approved(baseline)
    never_touch = {"mem:mem-unrelated-eng", "cache:cache-unrelated-1", "log:evt-unrelated", "vec:chunk-0003"}
    assert not never_touch & set(_approved(assessed))


def test_live_model_regenerates_a_summary_without_the_revoked_source(tmp_path):
    from conftest import approve_and_apply

    settings = replace(
        seeded_settings(tmp_path),
        model_provider="openai_compatible",
        model_base_url=URL,
        model_name=NAME,
        model_timeout_seconds=float(os.environ.get("REDACTO_LIVE_MODEL_TIMEOUT", "180")),
        regenerate_derivatives=True,
    )
    minutes = (
        "# Board minutes, October\n\nThe board approved the new office lease in Austin and "
        "hired two support engineers. The quarterly offsite moves to November.\n"
    )
    (settings.workspace_root / "board-minutes.md").write_text(minutes, encoding="utf-8")
    engine = Engine(settings)
    engine.scan(target_id="fs:board-minutes.md", use_model=False)
    engine.record_lineage(
        source_ids=["fs:board-minutes.md"], output_id="fs:generated-summary.md",
        relation="SUMMARIZED_FROM", evidence_type="instrumented", evidence_ref="live-test",
    )
    plan = engine.plan(target_id=SOURCE_ID, use_model=False)
    item = next(i for i in plan["items"] if i["record_id"] == "fs:generated-summary.md")
    assert item["proposed_action"] == "REGENERATE_FROM_ALLOWED_SOURCES"
    applied = approve_and_apply(engine, plan)
    result = next(r for r in applied["results"] if r.get("record_id") == "fs:generated-summary.md")
    # Either the model's rewrite passed the leak check and was written, or it was
    # refused and the original was left alone. Never a silent leak.
    receipt = engine.verify(request_id=applied["request_id"])
    if result["result"] == "success":
        assert receipt["counts"]["residual_matches"] == 0
    else:
        assert result["error_code"] in {"regenerate_leak", "regenerate_failed"}
        assert receipt["status"] == "PARTIAL"
