"""Graph traversal and lineage semantics."""

from __future__ import annotations

import pytest

from redacto.errors import RedactoError
from redacto.fixtures import SOURCE_ID

CONFIRMED = {
    "fs:generated-summary.md",
    "mem:mem-summary-paraphrase",
    "vec:chunk-0001",
    "cache:cache-response-1",
    "log:evt-summary-gen",
}


def test_finds_every_confirmed_descendant(engine):
    trace = engine.trace(source_id=SOURCE_ID, depth=3)
    found = {node["record_id"] for node in trace["confirmed_descendants"]}
    assert found == CONFIRMED
    assert all(node["depth"] >= 1 for node in trace["confirmed_descendants"])
    assert all(node["via"] for node in trace["confirmed_descendants"])


def test_read_from_is_exposure_only(engine):
    trace = engine.trace(source_id=SOURCE_ID, depth=3)
    exposure = {node["record_id"] for node in trace["weak_exposure"]}
    descendants = {node["record_id"] for node in trace["confirmed_descendants"]}
    assert "log:evt-read-1" in exposure
    assert "log:evt-read-1" not in descendants


def test_read_only_exposure_never_becomes_an_executable_item(engine):
    plan = engine.plan(target_id=SOURCE_ID)
    exposure_items = [i for i in plan["items"] if i["record_id"] == "log:evt-read-1"]
    # A READ_FROM link may be absent from the plan entirely, but it must never be an
    # approved destructive action.
    assert all(item["approved"] is False for item in exposure_items)


def test_candidates_are_separate_from_lineage(engine):
    trace = engine.trace(source_id=SOURCE_ID, depth=3)
    candidates = {edge["record_id"]: edge for edge in trace["candidate_relationships"]}
    assert candidates["mem:mem-candidate-paraphrase"]["status"] == "candidate"
    assert candidates["mem:mem-candidate-paraphrase"]["status"] != "confirmed"
    descendants = {node["record_id"] for node in trace["confirmed_descendants"]}
    assert "mem:mem-candidate-paraphrase" not in descendants


def test_depth_bound_limits_traversal(engine):
    trace = engine.trace(source_id=SOURCE_ID, depth=1)
    found = {node["record_id"] for node in trace["confirmed_descendants"]}
    assert found == CONFIRMED - {"mem:mem-summary-paraphrase"}
    assert all(node["depth"] == 1 for node in trace["confirmed_descendants"])


def test_record_lineage_hook_confirms_instrumented_edges(engine):
    result = engine.record_lineage(
        source_ids=[SOURCE_ID],
        output_id="mem:mem-unrelated-eng",
        relation="DERIVED_FROM",
        evidence_type="instrumented",
        evidence_ref="test-ingestion-hook",
    )
    assert result["status"] == "confirmed"
    trace = engine.trace(source_id=SOURCE_ID)
    assert "mem:mem-unrelated-eng" in {
        node["record_id"] for node in trace["confirmed_descendants"]
    }


def test_record_lineage_hook_keeps_model_claims_as_candidates(engine):
    result = engine.record_lineage(
        source_ids=[SOURCE_ID],
        output_id="mem:mem-unrelated-eng",
        relation="DERIVED_FROM",
        evidence_type="model_inferred",
        confidence=0.9,
    )
    assert result["status"] == "candidate"
    trace = engine.trace(source_id=SOURCE_ID)
    assert "mem:mem-unrelated-eng" not in {
        node["record_id"] for node in trace["confirmed_descendants"]
    }
    assert "mem:mem-unrelated-eng" in {
        edge["record_id"] for edge in trace["candidate_relationships"]
    }


def test_record_lineage_hook_requires_trustworthy_evidence(engine):
    with pytest.raises(RedactoError) as excinfo:
        engine.record_lineage(
            source_ids=[SOURCE_ID],
            output_id="mem:mem-unrelated-eng",
            relation="INVENTED_RELATION",
            evidence_type="instrumented",
            evidence_ref="x",
        )
    assert excinfo.value.code == "invalid_relation"

    with pytest.raises(RedactoError) as excinfo:
        engine.record_lineage(
            source_ids=[SOURCE_ID],
            output_id="mem:mem-unrelated-eng",
            relation="DERIVED_FROM",
            evidence_type="agent_says_so",
            evidence_ref="x",
        )
    assert excinfo.value.code == "invalid_evidence_type"

    with pytest.raises(RedactoError) as excinfo:
        engine.record_lineage(
            source_ids=[SOURCE_ID],
            output_id="mem:mem-unrelated-eng",
            relation="DERIVED_FROM",
            evidence_type="instrumented",
        )
    assert excinfo.value.code == "missing_evidence_ref"

    with pytest.raises(RedactoError) as excinfo:
        engine.record_lineage(
            source_ids=[SOURCE_ID],
            output_id="mem:mem-unrelated-eng",
            relation="DERIVED_FROM",
            evidence_type="human_verified",
        )
    assert excinfo.value.code == "missing_verifier"


def test_node_types_follow_the_spec_vocabulary(engine):
    scan = engine.scan(target_id=SOURCE_ID)
    assert scan["target"]["node_type"] == "SOURCE"
    memory = next(
        c for c in scan["candidates"] if c["record_id"] == "mem:mem-candidate-paraphrase"
    )
    assert memory["node_type"] == "MEMORY"
    trace = engine.trace(source_id=SOURCE_ID)
    assert trace["source"]["node_type"] == "SOURCE"