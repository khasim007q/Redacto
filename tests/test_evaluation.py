"""Fixture-level evaluation metrics."""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import approve_and_apply
from helpers import seeded_settings
from redacto.engine import Engine
from redacto.errors import RedactoError
from redacto.evaluation import evaluate_fixture
from redacto.fixtures import SOURCE_ID


def test_evaluation_reports_full_fixture_coverage(tmp_path: Path):
    engine = Engine(seeded_settings(tmp_path))
    report = evaluate_fixture(engine)
    assert report["direct_match"]["precision"] == 1.0
    assert report["direct_match"]["recall"] == 1.0
    assert report["direct_match"]["true_positives"] == 2
    assert report["confirmed_descendants"]["coverage"] == 1.0
    assert report["confirmed_descendants"]["found"] == 5
    assert report["semantic_candidates"]["precision"] == 1.0
    assert report["semantic_candidates"]["recall"] == 1.0
    assert report["preserved_related"]["recall"] == 1.0
    assert report["unrelated_touched"] == []
    assert report["destructive_actions_blocked_by_policy"] >= 2
    assert report["model_schema_validity"].startswith("not_measured")


def test_evaluation_refuses_a_mutated_fixture(tmp_path: Path):
    engine = Engine(seeded_settings(tmp_path))
    plan = engine.plan(target_id=SOURCE_ID)
    approve_and_apply(engine, plan)
    with pytest.raises(RedactoError) as excinfo:
        evaluate_fixture(engine)
    assert excinfo.value.code == "fixture_not_pristine"