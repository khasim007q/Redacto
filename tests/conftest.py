"""Shared fixtures."""

from __future__ import annotations

from helpers import seeded_settings
from pathlib import Path

import pytest

from redacto.engine import Engine


@pytest.fixture
def settings(tmp_path: Path):
    return seeded_settings(tmp_path)


@pytest.fixture
def engine(settings):
    return Engine(settings)


def approve_and_apply(engine: Engine, plan: dict, *, dry_run: bool = False) -> dict:
    approval = engine.approve_plan(plan_id=plan["plan_id"], approval_ref="test-operator-approval")
    return engine.apply(
        plan_id=plan["plan_id"],
        plan_version=plan["plan_version"],
        approval_ref="test-operator-approval",
        confirmation_token=approval["confirmation_token"],
        dry_run=dry_run,
    )