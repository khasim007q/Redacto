"""Executable regressions for concrete weaknesses found during the audit."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from conftest import approve_and_apply
from redacto.adapters.base import AdapterError, Record
from redacto.adapters.filesystem import FilesystemAdapter
from redacto.adapters.jsonl_logs import JsonlLogAdapter
from redacto.adapters.vector_fixture import VectorFixtureAdapter
from redacto.discovery.normalization import fingerprint
from redacto.fixtures import SOURCE_ID, ACQUISITION_PLAN
from redacto.ingestion import TombstoneGuard
from redacto.regeneration import RegenerationError, validate_regeneration


def _link(path, target, *, directory=False):
    try:
        path.symlink_to(target, target_is_directory=directory)
    except OSError:
        pytest.skip("symlink privilege unavailable")


@pytest.mark.parametrize("operation", ["read_record", "delete_record", "write_record", "replace_content"])
def test_in_root_symlink_is_rejected_without_touching_target(tmp_path, operation):
    root = tmp_path / "root"
    root.mkdir()
    target = root / "keep.md"
    target.write_text("valuable content", encoding="utf-8")
    _link(root / "alias.md", target)
    adapter = FilesystemAdapter(root)
    with pytest.raises(AdapterError, match="links"):
        if operation == "write_record":
            adapter.write_record(Record(record_id="fs:alias.md", record_type="doc", store_id="filesystem", locator={"path": "alias.md"}, content="overwrite"))
        elif operation == "replace_content":
            adapter.replace_content({"path": "alias.md"}, "overwrite")
        else:
            getattr(adapter, operation)({"path": "alias.md"})
    assert target.read_text(encoding="utf-8") == "valuable content"


def test_parent_directory_link_is_rejected(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    other = tmp_path / "outside"
    other.mkdir()
    (other / "private.md").write_text("private", encoding="utf-8")
    _link(root / "linked", other, directory=True)
    adapter = FilesystemAdapter(root)
    with pytest.raises(AdapterError):
        adapter.read_record({"path": "linked/private.md"})
    assert list(adapter.list_records()) == []


def test_rewrite_checks_again_after_preparing_temp(tmp_path, monkeypatch):
    path = tmp_path / "note.md"
    path.write_text("old confidential content", encoding="utf-8")
    adapter = FilesystemAdapter(tmp_path, "key")
    expected = fingerprint(path.read_text(), "key")
    chmod = os.chmod

    def race(file, mode):
        chmod(file, mode)
        if str(file).endswith(".tmp"):
            path.write_text("new unrelated content", encoding="utf-8")

    monkeypatch.setattr(os, "chmod", race)
    with pytest.raises(AdapterError) as exc:
        adapter.replace_content({"path": "note.md"}, "replacement", expected_fingerprint=expected)
    assert exc.value.code == "content_changed"
    assert path.read_text() == "new unrelated content"
    assert not list(tmp_path.glob("*.tmp"))


def test_jsonl_retry_rechecks_fingerprint(tmp_path, monkeypatch):
    path = tmp_path / "events.jsonl"
    path.write_text('{"event_id":"x","content":"old secret"}\n', encoding="utf-8")
    adapter = JsonlLogAdapter(path, "key")
    expected = fingerprint(adapter.read_record({"event_id": "x"}).content, "key")
    rewrite = adapter._rewrite_line

    def race(*args, **kwargs):
        path.write_text('{"event_id":"x","content":"new permitted text"}\n', encoding="utf-8")
        return rewrite(*args, **kwargs)

    monkeypatch.setattr(adapter, "_rewrite_line", race)
    with pytest.raises(AdapterError) as exc:
        adapter.delete_record({"event_id": "x"}, expected_fingerprint=expected)
    assert exc.value.code == "content_changed"
    assert "new permitted text" in path.read_text()


def test_vector_rewrite_detects_concurrent_change_and_keeps_top_level_metadata(tmp_path, monkeypatch):
    path = tmp_path / "chunks.json"
    path.write_text(json.dumps({"schema": "keep", "chunks": [{"id": "x", "text": "old"}]}))
    adapter = VectorFixtureAdapter(path)
    save = adapter._save

    def race(chunks):
        path.write_text(json.dumps({"schema": "keep", "chunks": [{"id": "x", "text": "new"}]}))
        save(chunks)

    monkeypatch.setattr(adapter, "_save", race)
    with pytest.raises(AdapterError) as exc:
        adapter.delete_record({"id": "x"})
    assert exc.value.code == "content_changed"
    assert "new" in path.read_text()
    monkeypatch.setattr(adapter, "_save", save)
    adapter.delete_record({"id": "x"})
    assert json.loads(path.read_text()) == {"schema": "keep", "chunks": []}


def test_all_active_tombstones_are_enforced(engine):
    # The earliest tombstone must still protect data after 200 newer requests.
    for i in range(205):
        engine.repo.add_tombstone(request_id=f"r{i}", target_id=f"target{i}", target_kind="source", label_redacted="target",
                                  fingerprint_value=fingerprint(f"unique revoked value {i}", engine.settings.hmac_key),
                                  shingles=[], anchors=[], tokens=[], related_record_ids=[], related_fingerprints=[], scope={}, policy={}, status="active")
    guard = engine.guard()
    assert guard.active_count == 205
    assert guard.evaluate(record_id="new", content="unique revoked value 0").blocked


@pytest.mark.parametrize("template", ["KEY={}", "prefix{}suffix", "?token={}"])
def test_single_token_secret_is_blocked_immediately_after_apply(engine, template):
    secret = "opaqueCredentialA19387bd9"
    plan = engine.plan(target_id=SOURCE_ID, target_kind="secret", target_text=secret, mode="fact_revocation")
    approve_and_apply(engine, plan)
    record = Record(record_id="fs:replay.md", record_type="doc", store_id="filesystem", locator={"path": "replay.md"}, content=template.format(secret))
    result = engine.ingest([record], store_id="filesystem", write_to_store=True)
    assert result["counts"]["blocked"] == 1
    assert not (engine.settings.workspace_root / "replay.md").exists()


def test_semantic_residual_written_after_planning_requires_review(engine):
    plan = engine.plan(target_id=SOURCE_ID)
    applied = approve_and_apply(engine, plan)
    path = engine.settings.workspace_root / "late-memory.md"
    path.write_text("Meridian is buying Halcyon for about forty-two million dollars in November.", encoding="utf-8")
    verified = engine.verify(request_id=applied["request_id"])
    semantic = verified["receipt"]["semantic_verification"]
    assert any(f["record_id"] == "fs:late-memory.md" for f in semantic["findings"])
    assert semantic["proves_semantic_absence"] is False
    assert verified["status"] in {"NEEDS_REVIEW", "PARTIAL"}
    assert "forty-two million" not in json.dumps(verified)
    assert path.exists()  # a finding does not authorize a mutation


def test_oversized_survivor_cannot_be_claimed_verified(engine):
    plan = engine.plan(target_id=SOURCE_ID)
    approve_and_apply(engine, plan)
    (engine.settings.workspace_root / "huge.md").write_text("x" * (engine.settings.max_record_bytes + 1))
    verified = engine.verify(request_id=plan["request_id"])
    assert verified["status"] == "PARTIAL"
    assert next(s for s in verified["stores"] if s["store_id"] == "filesystem")["oversized_records_skipped"] == 1


@pytest.mark.parametrize("output,code", [
    ("Invented customer revenue doubled.", "regenerate_ungrounded"),
    ("The office lease was cancelled.", "regenerate_ungrounded"),
    ("", "regenerate_ungrounded"),
    ("Austin.", "regenerate_low_retention"),
])
def test_regeneration_rejects_hallucination_contradiction_and_useless_output(output, code):
    with pytest.raises(RegenerationError) as exc:
        validate_regeneration(output, ["The office lease was approved in Austin. The public SDK supports Linux and Windows."])
    assert exc.value.code == code


def test_regeneration_preserves_all_allowed_sources_across_repeated_runs():
    sources = ["The public SDK supports Linux and Windows.", "The office lease was approved in Austin."]
    output = "Summary: " + " ".join(sources)
    for _ in range(4):
        report = validate_regeneration(output, sources)
        assert report["minimum_source_word_retention"] == 1.0
    with pytest.raises(RegenerationError, match="discards"):
        validate_regeneration(sources[0], sources)


def test_receipt_integrity_detects_tampering_and_requires_original_key(engine):
    from copy import deepcopy
    from redacto.receipts import check_receipt

    plan = engine.plan(target_id=SOURCE_ID)
    approve_and_apply(engine, plan)
    receipt = engine.verify(request_id=plan["request_id"])["receipt"]
    assert check_receipt(receipt, keyring=engine.settings.hmac_keys)["valid"]
    altered = deepcopy(receipt)
    altered["counts"]["failed"] = 999
    assert check_receipt(altered, keyring=engine.settings.hmac_keys)["reason"] == "signature_mismatch"
    assert check_receipt(receipt, keyring={})["reason"] == "key_unavailable"


def test_guard_checks_metadata_and_does_not_echo_identity_secret(engine):
    secret = "opaqueCredentialB98379cbd"
    plan = engine.plan(target_id=SOURCE_ID, target_kind="secret", target_text=secret, mode="fact_revocation")
    approve_and_apply(engine, plan)
    record = Record(record_id=f"fs:{secret}.md", record_type="doc", store_id="filesystem",
                    locator={"path": f"{secret}.md"}, content="Public information.", metadata={"token": secret})
    result = engine.ingest([record], store_id="filesystem", write_to_store=True)
    assert result["counts"]["blocked"] == 1
    assert secret not in json.dumps(result)
    assert secret.encode() not in engine.settings.db_path.read_bytes()


def test_quantity_scaling_does_not_confuse_decimals_with_whole_numbers():
    from redacto.discovery.embeddings import HashingEmbeddingProvider, cosine

    embedder = HashingEmbeddingProvider()
    assert cosine(embedder.embed("1.2 thousand parts"), embedder.embed("1200 parts")) > 0.99
    assert cosine(embedder.embed("48 crore rupees"), embedder.embed("480 million rupees")) > 0.99
    assert cosine(embedder.embed("1.2 thousand parts"), embedder.embed("12 thousand parts")) < 0.99


def test_jsonl_append_while_preparing_temp_is_never_overwritten(tmp_path, monkeypatch):
    path = tmp_path / "events.jsonl"
    path.write_text('{"event_id":"old","content":"secret"}\n')
    adapter = JsonlLogAdapter(path, "key")
    chmod = os.chmod

    def race(file, mode):
        chmod(file, mode)
        if str(file).endswith(".tmp"):
            with path.open("a") as handle:
                handle.write('{"event_id":"new","content":"valuable"}\n')

    monkeypatch.setattr(os, "chmod", race)
    with pytest.raises(AdapterError) as exc:
        adapter.delete_record({"event_id": "old"})
    assert exc.value.code == "delete_conflict"
    assert "valuable" in path.read_text()
    assert "secret" in path.read_text()
    assert not list(tmp_path.glob("*.tmp"))


def test_misspelled_dry_run_cannot_enable_real_mutations(monkeypatch):
    from redacto.config import _env_bool
    from redacto.errors import RedactoError

    monkeypatch.setenv("REDACTO_DRY_RUN", "treu")
    with pytest.raises(RedactoError) as exc:
        _env_bool("REDACTO_DRY_RUN", True)
    assert exc.value.code == "invalid_configuration"


@pytest.mark.parametrize("change", [{"max_scan_records": 0}, {"safety_mode": "strcit"}, {"embedding_candidate_threshold": float("nan")}])
def test_invalid_limits_and_safety_settings_fail_closed(engine, change):
    from dataclasses import replace
    from redacto.errors import RedactoError

    with pytest.raises(RedactoError) as exc:
        replace(engine.settings, **change)
    assert exc.value.code == "invalid_configuration"


def test_seed_can_be_repeated_after_adapter_lock_sidecars_are_created(settings):
    from redacto.fixtures import seed_workspace

    result = seed_workspace(settings)
    assert result["records_seeded"] > 0


def test_transport_diagnostics_never_echo_unexpected_exception_content(capsys):
    from redacto.mcp.server import _guard

    secret = "sensitive-provider-payload-a8f13"
    def fail():
        raise RuntimeError(secret)

    result = _guard(fail)
    assert secret not in json.dumps(result)
    assert secret not in capsys.readouterr().err
    assert "no action was taken" not in result["error"]["message"]


def test_embedding_versions_are_not_compared():
    from redacto.discovery.embeddings import HashingEmbeddingProvider

    provider = HashingEmbeddingProvider()
    content = "An entirely unrelated public deployment checklist."
    tombstone = dict(tombstone_id="t", status="active", target_id="source", target_kind="source", label_redacted="source",
                     fingerprint=fingerprint("revoked private source", "key"), key_version=1,
                     shingles=[], anchors=[], tokens=[], related_record_ids=[], related_fingerprints=[],
                     embedding=provider.embed(content), embedding_model="incompatible-model")
    guard = TombstoneGuard([tombstone], {1: "key"}, 1, embedder=provider)
    assert guard.evaluate(record_id="unrelated", content=content).decision == "allowed"


def test_verification_does_not_echo_secret_in_new_post_plan_filename(engine):
    secret = "credentialPostPlan7cf29"
    plan = engine.plan(target_id=SOURCE_ID, target_kind="secret", target_text=secret, mode="fact_revocation")
    approve_and_apply(engine, plan)
    (engine.settings.workspace_root / f"{secret}.md").write_text(f"KEY={secret}")
    receipt = engine.verify(request_id=plan["request_id"])
    assert receipt["status"] == "PARTIAL"
    assert secret not in json.dumps(receipt)


def test_approval_token_remains_a_cli_value_when_random_suffix_starts_with_dash(engine, monkeypatch):
    from redacto.policy import authorization
    from redacto.cli import build_parser

    plan = engine.plan(target_id=SOURCE_ID)
    monkeypatch.setattr(authorization.secrets, "token_urlsafe", lambda _: "-random-suffix-with-full-entropy-in-production")
    approval = engine.approve_plan(plan_id=plan["plan_id"], approval_ref="operator-token-test")
    args = build_parser().parse_args(["apply", "--plan-id", plan["plan_id"], "--version", "1",
                                      "--ref", approval["approval_ref"], "--token", approval["confirmation_token"], "--dry-run"])
    assert args.token == approval["confirmation_token"]


def test_transient_windows_replace_failure_retries_without_data_loss(tmp_path, monkeypatch):
    from redacto.adapters.base import checked_replace

    path = tmp_path / "record"
    temp = tmp_path / "replacement"
    path.write_text("old")
    temp.write_text("new")
    replace = os.replace
    attempts = []

    def transient(src, dst):
        attempts.append(1)
        if len(attempts) == 1:
            error = PermissionError("transient sharing violation")
            error.winerror = 5
            raise error
        replace(src, dst)

    monkeypatch.setattr(os, "replace", transient)
    checked_replace(str(temp), path, lambda: path.read_text() == "old")
    assert path.read_text() == "new" and len(attempts) == 2


def test_retry_never_overwrites_content_changed_while_waiting(tmp_path, monkeypatch):
    from redacto.adapters.base import checked_replace

    path = tmp_path / "record"
    temp = tmp_path / "replacement"
    path.write_text("old")
    temp.write_text("stale replacement")

    def conflict(src, dst):
        path.write_text("valuable concurrent edit")
        error = PermissionError("transient sharing violation")
        error.winerror = 32
        raise error

    monkeypatch.setattr(os, "replace", conflict)
    with pytest.raises(AdapterError) as exc:
        checked_replace(str(temp), path, lambda: path.read_text() == "old")
    assert exc.value.code == "content_changed"
    assert path.read_text() == "valuable concurrent edit"
