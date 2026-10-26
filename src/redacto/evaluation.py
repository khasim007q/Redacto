"""Evaluation report over the seeded synthetic fixture.

Reports counts rather than a single accuracy score, per the specification:
direct-match precision/recall, confirmed-descendant coverage, semantic candidate
precision/recall, preserved-related recall, unrelated records touched, and the
number of destructive actions kept out of the plan by policy.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from redacto.engine import Engine
from redacto.errors import RedactoError


def _prf(tp: int, fp: int, fn: int) -> dict[str, Any]:
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
    }


def evaluate_fixture(engine: Engine) -> dict[str, Any]:
    expected_path = engine.settings.workspace_root.parent / "expected_results.json"
    if not expected_path.is_file():
        raise RedactoError(
            "fixture_missing",
            "Run `redacto seed` before evaluating; expected_results.json is missing.",
            {"path": str(expected_path)},
        )
    expected = json.loads(expected_path.read_text(encoding="utf-8"))

    # Evaluation is only meaningful on the pristine seeded fixture. Refuse instead of
    # reporting misleading 0.0 coverage after a revocation/demo has mutated it.
    target = engine.repo.get_record(expected["target_id"])
    if target is None or target["status"] != "active":
        raise RedactoError(
            "fixture_not_pristine",
            "Run `redacto seed` before evaluating; the seeded target is deleted or missing.",
            {"target_id": expected["target_id"], "status": target["status"] if target else None},
        )
    inactive = [
        record_id
        for record_id in expected["confirmed_descendants"]
        if (engine.repo.get_record(record_id) or {}).get("status") != "active"
    ]
    if inactive:
        raise RedactoError(
            "fixture_not_pristine",
            "Run `redacto seed` before evaluating; seeded descendants are missing or deleted.",
            {"inactive_records": inactive},
        )

    scan = engine.scan(target_id=expected["target_id"])
    candidates = scan["candidates"]

    def ids_for(evidence_class: str) -> set[str]:
        return {
            candidate["record_id"]
            for candidate in candidates
            if candidate["evidence_class"] == evidence_class
        }

    predicted_direct = ids_for("DIRECT_MATCH")
    expected_direct = set(expected["direct_matches"])
    direct = _prf(
        len(predicted_direct & expected_direct),
        len(predicted_direct - expected_direct),
        len(expected_direct - predicted_direct),
    )

    predicted_confirmed = ids_for("CONFIRMED_DESCENDANT")
    expected_confirmed = set(expected["confirmed_descendants"])
    confirmed_found = len(predicted_confirmed & expected_confirmed)
    confirmed_coverage = (
        confirmed_found / len(expected_confirmed) if expected_confirmed else 1.0
    )

    predicted_suspected = ids_for("SUSPECTED_DERIVATIVE")
    expected_suspected = set(expected["suspected_derivatives"])
    suspected = _prf(
        len(predicted_suspected & expected_suspected),
        len(predicted_suspected - expected_suspected),
        len(expected_suspected - predicted_suspected),
    )

    predicted_related = ids_for("RELATED_NONDISCLOSING")
    expected_related = set(expected["preserved_related"])
    related_found = len(predicted_related & expected_related)
    related_recall = related_found / len(expected_related) if expected_related else 1.0

    plan = engine.plan(target_id=expected["target_id"])
    approved_items = {
        item["record_id"] for item in plan["items"] if item["approved"]
    }
    must_never_touch = set(expected["must_never_touch"])
    unrelated_touched = sorted(approved_items & must_never_touch)
    blocked_by_policy = sum(
        1
        for item in plan["items"]
        if not item["approved"]
        and item["proposed_action"] in {"REVIEW_REQUIRED", "UNREACHABLE"}
    )

    return {
        "target_id": expected["target_id"],
        "fixture": str(expected_path),
        "direct_match": direct,
        "confirmed_descendants": {
            "expected": len(expected_confirmed),
            "found": confirmed_found,
            "coverage": round(confirmed_coverage, 4),
        },
        "semantic_candidates": suspected,
        "preserved_related": {
            "expected": len(expected_related),
            "found": related_found,
            "recall": round(related_recall, 4),
        },
        "unrelated_touched": unrelated_touched,
        "destructive_actions_blocked_by_policy": blocked_by_policy,
        "scan_counts": scan["counts"],
        "embedding_candidates_generated": scan["embeddings"]["candidates_generated"],
        "model_schema_validity": "not_measured (runtime model provider disabled)",
        "notes": [
            "Metrics are fixture-level engineering targets, not production accuracy claims.",
            "Semantic candidates are compared against the labelled synthetic positives only.",
            "A confirmed-descendant coverage of 1.0 means every seeded confirmed edge was traversed.",
        ],
    }