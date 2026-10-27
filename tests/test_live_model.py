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
