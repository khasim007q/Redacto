"""Versioned HMAC key rotation: old tombstones stay enforceable, missing keys fail closed."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from conftest import approve_and_apply
from helpers import seeded_settings
from redacto.engine import Engine
from redacto.errors import RedactoError
from redacto.fixtures import ACQUISITION_PLAN, SOURCE_ID

OLD_KEY = "unit-test-fixture-key"
NEW_KEY = "rotated-key-v2-not-a-secret"


def _revoked(tmp_path: Path) -> tuple[Engine, dict]:
    settings = seeded_settings(tmp_path)
    engine = Engine(settings)
    plan = engine.plan(target_id=SOURCE_ID)
    applied = approve_and_apply(engine, plan)
    engine.verify(request_id=applied["request_id"])
    return engine, applied


def _rotate(settings, keys: dict[int, str], current: int):
    return replace(settings, hmac_keys=keys, hmac_key_version=current, keyring_error=None)


def test_tombstone_records_key_version(tmp_path):
    engine, _ = _revoked(tmp_path)
    tombstone = engine.repo.list_tombstones()[0]
    assert tombstone["key_version"] == 1


def test_old_tombstone_still_enforced_during_rotation(tmp_path):
    engine, _ = _revoked(tmp_path)
    rotated = _rotate(engine.settings, {1: OLD_KEY, 2: NEW_KEY}, 2)
    engine_v2 = Engine(rotated)

    (rotated.workspace_root / "acquisition-plan.md").write_text(
        ACQUISITION_PLAN, encoding="utf-8"
    )
    result = engine_v2.reingest_stores(stores=["filesystem"])
    finding = next(f for f in result["findings"] if f["record_id"] == SOURCE_ID)
    assert finding["decision"] == "blocked"
    assert finding["reason_code"] == "same_target"
    assert result["guard"]["active_tombstones"] == 1


def test_new_revocations_use_the_current_version_and_coexist(tmp_path):
    engine, _ = _revoked(tmp_path)
    rotated = _rotate(engine.settings, {1: OLD_KEY, 2: NEW_KEY}, 2)
    engine_v2 = Engine(rotated)

    plan = engine_v2.plan(
        target_id=SOURCE_ID,
        target_kind="fact",
        target_text="retention pool covers 18 engineers",
        mode="fact_revocation",
    )
    applied = approve_and_apply(engine_v2, plan)
    engine_v2.verify(request_id=applied["request_id"])

    versions = {t["key_version"] for t in engine_v2.repo.list_tombstones()}
    assert versions == {1, 2}

    report = engine_v2.keyring_report()
    assert report["tombstones_by_key_version"] == {1: 1, 2: 1}
    assert report["missing_key_versions"] == []
    assert report["protection_degraded"] is False


def test_missing_old_key_fails_closed_for_all_ingestion(tmp_path):
    engine, _ = _revoked(tmp_path)
    # The v1 tombstone is active, but the v1 key is gone.
    rotated = _rotate(engine.settings, {2: NEW_KEY}, 2)
    engine_v2 = Engine(rotated)

    result = engine_v2.reingest_stores()
    assert result["counts"]["allowed"] == 0
    assert result["counts"]["blocked"] > 0
    assert all(
        finding["reason_code"] == "key_unavailable_fail_closed"
        for finding in result["findings"]
    )
    report = engine_v2.keyring_report()
    assert report["protection_degraded"] is True
    assert report["missing_key_versions"] == [1]
    assert report["retirable_versions"] == [2]

    status = engine_v2.status(transport="test")
    assert status["revocation"]["protection_degraded"] is True
    assert status["revocation"]["missing_key_versions"] == [1]


def test_missing_current_key_refuses_new_work(tmp_path):
    settings = seeded_settings(tmp_path)
    broken = _rotate(settings, {1: OLD_KEY}, 2)  # version 2 is current but absent
    engine = Engine(broken)

    with pytest.raises(RedactoError) as excinfo:
        engine.guard()
    assert excinfo.value.code == "current_key_unavailable"

    report = engine.keyring_report()
    assert report["protection_degraded"] is True
    assert report["current_key_version"] == 2
    assert report["configured_versions"] == [1]


def test_invalid_keyring_fails_closed(tmp_path):
    settings = seeded_settings(tmp_path)
    broken = replace(settings, keyring_error="REDACTO_HMAC_KEYS must be valid JSON")
    engine = Engine(broken)
    with pytest.raises(RedactoError) as excinfo:
        engine.guard()
    assert excinfo.value.code == "keyring_invalid"
    assert engine.keyring_report()["protection_degraded"] is True


def test_retirement_refuses_while_version_is_in_use(tmp_path):
    engine, _ = _revoked(tmp_path)
    report = engine.keyring_report()
    assert report["retirable_versions"] == []
    with pytest.raises(RedactoError) as excinfo:
        engine.keyring_report(retire_version=1)
    assert excinfo.value.code == "version_still_in_use"


def test_unused_version_is_reported_retirable(tmp_path):
    settings = seeded_settings(tmp_path)
    engine = Engine(settings)  # nothing revoked yet
    report = engine.keyring_report(retire_version=1)
    assert report["retirable_versions"] == [1]
    assert report["retirement"]["safe"] is True


def test_verification_uses_the_target_key_version_after_rotation(tmp_path):
    engine, applied = _revoked(tmp_path)
    rotated = _rotate(engine.settings, {1: OLD_KEY, 2: NEW_KEY}, 2)
    engine_v2 = Engine(rotated)
    verified = engine_v2.verify(request_id=applied["request_id"])
    assert verified["counts"]["residual_matches"] == 0
    assert verified["status"] in {"VERIFIED_WITHIN_SCOPE", "NEEDS_REVIEW"}


def test_verification_degrades_honestly_when_target_key_is_missing(tmp_path):
    engine, applied = _revoked(tmp_path)
    rotated = _rotate(engine.settings, {2: NEW_KEY}, 2)
    engine_v2 = Engine(rotated)
    verified = engine_v2.verify(request_id=applied["request_id"])
    assert verified["status"] == "PARTIAL"
    assert "vector_fixture" not in verified["unreachable_stores"]
    assert any("HMAC key version" in limitation for limitation in verified["limitations"])