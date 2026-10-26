"""Graph traversal and lineage semantics."""

from __future__ import annotations

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