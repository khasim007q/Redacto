"""Review risk holds survive replay, recovery and key rotation without escalating deletion."""

import json
from dataclasses import replace

from conftest import approve_and_apply
from redacto.discovery.normalization import fingerprint
from redacto.engine import Engine
from redacto.fixtures import SOURCE_ID
from redacto.ingestion import TombstoneGuard

PAYLOAD = "A private firm is buying the sensor maker for about 42 million in cash."


def test_review_only_payload_stays_held_then_becomes_blocked_only_after_approved_removal(engine):
    engine = Engine(replace(engine.settings, embedding_quarantine_threshold=0.99))
    path = engine.settings.workspace_root / "held.md"
    path.write_text(PAYLOAD, encoding="utf-8")
    plan = engine.plan(target_id=SOURCE_ID)
    item = next(i for i in plan["items"] if i["record_id"] == "fs:held.md")
    assert item["proposed_action"] == "REVIEW_REQUIRED" and not item["approved"]
    approve_and_apply(engine, plan)
    first = engine.repo.list_tombstones()[0]
    assert path.exists()
    decision = engine.guard().evaluate(record_id="replayed", content=PAYLOAD)
    assert (decision.decision, decision.reason_code) == ("quarantined", "pending_review_fingerprint")
    shown = engine.tombstones()
    assert "review_fingerprints" not in json.dumps(shown)
    assert PAYLOAD not in json.dumps(shown)
    receipt = engine.verify(request_id=plan["request_id"])
    assert any(f["record_id"] == "fs:held.md" for f in receipt["receipt"]["semantic_verification"]["findings"])
    reviewed = engine.review_plan_item(plan_id=plan["plan_id"], item_id=item["item_id"],
                                       decision="approved", reviewer="independent-reviewer")
    # Review alone does not remove or classify this payload as a confirmed deletion.
    assert path.exists()
    assert engine.guard().evaluate(record_id="replayed", content=PAYLOAD).decision == "quarantined"
    result = approve_and_apply(engine, reviewed)
    assert result["counts"]["failed"] == 0
    assert not path.exists()
    second = engine.repo.list_tombstones()[0]
    assert second["tombstone_id"] == first["tombstone_id"]
    assert set(first["related_record_ids"]).issubset(second["related_record_ids"])
    decision = engine.guard().evaluate(record_id="renamed", content=PAYLOAD)
    assert (decision.decision, decision.reason_code) == ("blocked", "exact_derivative_fingerprint")


def test_review_fingerprint_key_versions_are_required_by_guard_status_and_keyring(engine):
    engine.repo.add_tombstone(request_id="manual", target_id="source", target_kind="source", label_redacted="source",
        fingerprint_value=fingerprint("original", engine.settings.current_hmac_key), shingles=[], anchors=[], tokens=[],
        related_record_ids=[], related_fingerprints=[], scope={}, status="active", key_version=1,
        policy={"review_fingerprints": [{"version": 9, "fingerprint": fingerprint(PAYLOAD, "missing-key")} ]})
    guard = engine.guard()
    assert guard.missing_versions == [9]
    assert guard.evaluate(record_id="public", content="public").reason_code == "key_unavailable_fail_closed"
    assert engine.keyring_report()["missing_key_versions"] == [9]
    assert engine.status(transport="test")["revocation"]["missing_key_versions"] == [9]


def test_review_holds_do_not_weaken_exact_or_partial_copy_blocks():
    from redacto.ingestion import TombstoneMaterial

    original = "Private acquisition terms remain confidential and must never enter the public release notes."
    material = TombstoneMaterial.build(original, "key")
    tombstone = {"status": "active", "tombstone_id": "t", "target_id": "source", "target_kind": "source",
        "label_redacted": "source", "key_version": 1, "fingerprint": material.fingerprint, "shingles": material.shingles,
        "anchors": [], "tokens": [], "related_record_ids": [], "related_fingerprints": [],
        "policy": {"review_fingerprints": [{"version": 1, "fingerprint": material.fingerprint}]}}
    guard = TombstoneGuard([tombstone], {1: "key"}, 1)
    assert guard.evaluate(record_id="renamed", content=original).decision == "blocked"


def test_review_hold_uses_its_own_key_during_rotation(engine):
    engine.repo.add_tombstone(request_id="manual", target_id="source", target_kind="source", label_redacted="source",
        fingerprint_value=fingerprint("original", "new-key"), shingles=[], anchors=[], tokens=[],
        related_record_ids=[], related_fingerprints=[], scope={}, status="active", key_version=2,
        policy={"review_fingerprints": [{"version": 1, "fingerprint": fingerprint(PAYLOAD, engine.settings.current_hmac_key)}]})
    rotated = Engine(replace(engine.settings, hmac_keys={**engine.settings.hmac_keys, 2: "new-key"}, hmac_key_version=2))
    decision = rotated.guard().evaluate(record_id="copy", content=PAYLOAD)
    assert (decision.decision, decision.reason_code) == ("quarantined", "pending_review_fingerprint")
    assert rotated.keyring_report()["in_use_key_versions"] == [1, 2]


def test_runtime_threshold_change_cannot_weaken_previously_revoked_source(engine):
    plan = engine.plan(target_id=SOURCE_ID)
    approve_and_apply(engine, plan)
    stricter_runtime = Engine(replace(engine.settings, embedding_quarantine_threshold=0.99))
    decision = stricter_runtime.guard().evaluate(record_id="unseen", content=PAYLOAD)
    assert (decision.decision, decision.reason_code) == ("quarantined", "embedding_similarity")


def test_item_review_waits_for_the_same_write_boundary_as_apply(engine):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    plan = engine.plan(target_id=SOURCE_ID)
    item = next(i for i in plan["items"] if i["proposed_action"] == "REVIEW_REQUIRED")
    started = threading.Event()

    def review():
        started.set()
        return engine.review_plan_item(plan_id=plan["plan_id"], item_id=item["item_id"], decision="approved", reviewer="operator")

    with ThreadPoolExecutor(1) as pool:
        with engine.write_boundary():
            future = pool.submit(review)
            assert started.wait(5)
            assert not future.done()
            assert engine.repo.get_plan(plan["plan_id"])["version"] == 1
        assert future.result(timeout=10)["plan_version"] == 2
