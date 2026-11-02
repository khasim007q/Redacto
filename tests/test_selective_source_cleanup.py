"""Reviewed source-passage edits preserve public context and never fake absence."""

import json

import pytest

from conftest import approve_and_apply
from redacto.adapters.base import AdapterError, REDACTION_MARK
from redacto.engine import Engine
from redacto.local import local_settings
from redacto.selective import passage_offer

PRIVATE = 'The private flight named "Azure Finch" launches after confidential clearance on Tuesday morning.'
PUBLIC = "The public support guide explains log rotation and backup recovery for all operators."


def _workspace(tmp_path):
    settings = local_settings(tmp_path, hmac_key="test-key")
    settings.workspace_root.mkdir()
    (settings.workspace_root / "private.md").write_text(PRIVATE, encoding="utf-8")
    return settings, Engine(settings)


@pytest.mark.parametrize("confirmed", [False, True])
def test_reviewed_source_redaction_preserves_other_content_and_lineage_class(tmp_path, confirmed):
    settings, engine = _workspace(tmp_path)
    (settings.workspace_root / "public.md").write_text(PUBLIC, encoding="utf-8")
    mixed = settings.workspace_root / "mixed.md"
    mixed.write_text(PRIVATE + "\n\n" + PUBLIC, encoding="utf-8")
    if confirmed:
        engine.scan(target_id="fs:private.md", stores=["filesystem"])
        engine.record_lineage(source_ids=["fs:private.md", "fs:public.md"], output_id="fs:mixed.md",
                              relation="DERIVED_FROM", evidence_type="instrumented", evidence_ref="test-writer")
    plan = engine.plan(target_id="fs:private.md", stores=["filesystem"])
    item = next(i for i in plan["items"] if i["record_id"] == "fs:mixed.md")
    assert item["proposed_action"] == "REVIEW_REQUIRED" and not item["approved"]
    assert item["redact_spans"] and "REDACT_SPAN" in item["review_actions"]
    assert PRIVATE not in json.dumps(plan)
    approve_and_apply(engine, plan)
    assert PRIVATE in mixed.read_text(encoding="utf-8")  # no implicit approval
    reviewed = engine.review_plan_item(plan_id=plan["plan_id"], item_id=item["item_id"],
                                       decision="approved", reviewer="operator")
    assert reviewed["selected_action"] == "REDACT_SPAN"
    assert engine.repo.get_plan_item(item["item_id"])["evidence_class"] == ("CONFIRMED_DESCENDANT" if confirmed else "SUSPECTED_DERIVATIVE")
    assert approve_and_apply(engine, reviewed)["counts"]["failed"] == 0
    remaining = mixed.read_text(encoding="utf-8")
    assert PRIVATE not in remaining and PUBLIC in remaining and REDACTION_MARK in remaining
    assert engine.repo.get_record("fs:mixed.md")["status"] == "active"
    receipt = engine.verify(request_id=plan["request_id"])
    assert receipt["counts"]["records_redacted"] == 1
    assert receipt["counts"]["records_removed"] == 1


def test_operator_can_still_choose_whole_record_removal_explicitly(tmp_path):
    settings, engine = _workspace(tmp_path)
    mixed = settings.workspace_root / "mixed.md"
    mixed.write_text(PRIVATE + "\n" + PUBLIC, encoding="utf-8")
    plan = engine.plan(target_id="fs:private.md", stores=["filesystem"])
    item = next(i for i in plan["items"] if i["record_id"] == "fs:mixed.md")
    reviewed = engine.review_plan_item(plan_id=plan["plan_id"], item_id=item["item_id"],
                                       decision="approved", action="delete", reviewer="operator")
    assert reviewed["selected_action"] == "DELETE_RECORD"
    approve_and_apply(engine, reviewed)
    assert not mixed.exists()


def test_changed_public_context_is_not_overwritten_by_an_old_redaction_plan(tmp_path):
    settings, engine = _workspace(tmp_path)
    mixed = settings.workspace_root / "mixed.md"
    mixed.write_text(PRIVATE + "\n" + PUBLIC, encoding="utf-8")
    plan = engine.plan(target_id="fs:private.md", stores=["filesystem"])
    item = next(i for i in plan["items"] if i["record_id"] == "fs:mixed.md")
    reviewed = engine.review_plan_item(plan_id=plan["plan_id"], item_id=item["item_id"],
                                       decision="approved", action="redact", reviewer="operator")
    changed = PRIVATE + "\n" + PUBLIC + " New public release instructions."
    mixed.write_text(changed, encoding="utf-8")
    result = approve_and_apply(engine, reviewed)
    outcome = next(r for r in result["results"] if r.get("record_id") == "fs:mixed.md")
    assert outcome["error_code"] == "content_changed"
    assert mixed.read_text(encoding="utf-8") == changed


def test_jsonl_selective_redaction_handles_escaped_quotes_and_nested_values(tmp_path):
    settings, engine = _workspace(tmp_path)
    event = {"event_id": "mixed", "content": PUBLIC, "tool_args": {"message": PRIVATE}, "keep": [1, True, "public"]}
    settings.jsonl_log_path.write_text(json.dumps(event) + "\n", encoding="utf-8")
    plan = engine.plan(target_id="fs:private.md", stores=["filesystem", "jsonl_logs"])
    item = next(i for i in plan["items"] if i["record_id"] == "log:mixed")
    assert item["redact_spans"]
    reviewed = engine.review_plan_item(plan_id=plan["plan_id"], item_id=item["item_id"],
                                       decision="approved", action="redact", reviewer="operator")
    assert approve_and_apply(engine, reviewed)["counts"]["failed"] == 0
    remaining = json.loads(settings.jsonl_log_path.read_text(encoding="utf-8"))
    assert remaining["event_id"] == "mixed" and remaining["content"] == PUBLIC
    assert remaining["tool_args"]["message"] == REDACTION_MARK
    assert remaining["keep"] == event["keep"]


def test_a_missing_span_is_not_reported_as_an_absent_record(tmp_path, monkeypatch):
    from redacto.adapters.filesystem import FilesystemAdapter

    settings, engine = _workspace(tmp_path)
    mixed = settings.workspace_root / "mixed.md"
    mixed.write_text(PRIVATE + "\n" + PUBLIC, encoding="utf-8")
    plan = engine.plan(target_id="fs:private.md", stores=["filesystem"])
    item = next(i for i in plan["items"] if i["record_id"] == "fs:mixed.md")
    reviewed = engine.review_plan_item(plan_id=plan["plan_id"], item_id=item["item_id"],
                                       decision="approved", action="redact", reviewer="operator")
    def no_edit(*args, **kwargs):
        raise AdapterError("no matching span", code="not_found")
    monkeypatch.setattr(FilesystemAdapter, "redact_record", no_edit)
    result = approve_and_apply(engine, reviewed)
    outcome = next(r for r in result["results"] if r.get("record_id") == "fs:mixed.md")
    assert outcome["error_code"] == "action_not_applied"
    assert mixed.exists() and PRIVATE in mixed.read_text(encoding="utf-8")
    assert engine.verify(request_id=plan["request_id"])["status"] == "PARTIAL"


def test_offer_captures_whitespace_variants_without_storing_plaintext():
    from redacto.adapters.base import redact_spans

    content = PRIVATE + "\n" + PRIVATE.upper().replace(" ", "  ") + "\n" + PUBLIC
    offer = passage_offer(PRIVATE, content, "key", max_bytes=256000)
    assert offer is not None
    assert len({s["length"] for s in offer.spans}) >= 2
    assert PRIVATE not in json.dumps(offer.spans)
    updated, count = redact_spans(content, offer.spans, "key")
    assert count == 2 and PUBLIC in updated and "Azure Finch" not in updated


def test_short_shared_phrases_do_not_create_a_redaction_offer():
    assert passage_offer("Keep public notes.", "Keep public notes. " + PUBLIC, "key", max_bytes=256000) is None
    assert passage_offer(PRIVATE, PRIVATE, "key", max_bytes=256000) is None


def test_large_passages_exceeding_the_window_hash_budget_are_held_without_an_offer():
    source = " ".join(f"privateword{index}" for index in range(1000)) + "."
    assert passage_offer(source, source + "\n" + PUBLIC * 100, "key", max_bytes=256000) is None


@pytest.mark.parametrize("ambiguous", ["duplicates", "key_collision", "event_identity"])
def test_jsonl_ambiguous_selective_edits_leave_original_untouched(tmp_path, ambiguous):
    from redacto.adapters.jsonl_logs import JsonlLogAdapter
    from redacto.discovery.normalization import fingerprint

    other = "Another private launch scheduled after confidential approval occurs on Wednesday evening."
    if ambiguous == "duplicates":
        raw = '{"event_id":"one","message":"old","message":' + json.dumps(PRIVATE) + '}\n'
        event_id = "one"
    elif ambiguous == "key_collision":
        raw = json.dumps({"event_id": "one", PRIVATE: "first", other: "second"}) + "\n"
        event_id = "one"
    else:
        raw = json.dumps({"event_id": PRIVATE, "content": PUBLIC}) + "\n"
        event_id = PRIVATE
    path = tmp_path / "events.jsonl"
    path.write_text(raw, encoding="utf-8")
    adapter = JsonlLogAdapter(path, "key")
    spans = [{"hmac": fingerprint(value, "key"), "length": len(value)} for value in (PRIVATE, other)]
    with pytest.raises(AdapterError) as error:
        adapter.redact_record({"event_id": event_id}, spans)
    assert error.value.code == "unsupported_operation"
    assert path.read_text(encoding="utf-8") == raw
