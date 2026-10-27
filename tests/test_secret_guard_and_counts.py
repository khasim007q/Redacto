"""Secret re-ingestion, redaction counts, approval error codes and concurrent log appends."""

from __future__ import annotations

import pytest

from conftest import approve_and_apply
from helpers import seeded_settings
from redacto.engine import Engine
from redacto.errors import RedactoError

SECRET = "sk-synthetic-PR3-GUARD-1234567890"
NOTES = (
    "# Team notes\n\nDeploy checklist: run migrations, then restart the workers.\n"
    "Payments config: STRIPE_KEY={s} (rotate monthly).\n"
    "On-call rota is Alice this week, Bob next week. Retro is Friday at 3pm.\n"
)


def _forget_secret(settings) -> tuple[Engine, dict]:
    (settings.workspace_root / "leaked-key.txt").write_text(SECRET + "\n", encoding="utf-8")
    engine = Engine(settings)
    plan = engine.plan(
        target_id="fs:leaked-key.txt", target_kind="secret", target_text=SECRET, mode="fact_revocation"
    )
    applied = approve_and_apply(engine, plan)
    engine.verify(request_id=applied["request_id"])
    return engine, plan



def test_restored_file_with_revoked_secret_is_not_admitted(tmp_path):
    settings = seeded_settings(tmp_path)
    engine, _ = _forget_secret(settings)
    (settings.workspace_root / "notes-restored.md").write_text(NOTES.format(s=SECRET), encoding="utf-8")
    guard = engine.reingest_stores()
    finding = next(f for f in guard["findings"] if f["record_id"] == "fs:notes-restored.md")
    assert (finding["decision"], finding["reason_code"]) == ("blocked", "value_containment")


def test_verify_still_catches_the_restored_secret(tmp_path):
    settings = seeded_settings(tmp_path)
    engine, plan = _forget_secret(settings)
    (settings.workspace_root / "notes-restored.md").write_text(NOTES.format(s=SECRET), encoding="utf-8")
    verified = engine.verify(request_id=plan["request_id"])
    assert verified["status"] == "PARTIAL"
    assert verified["counts"]["residual_matches"] >= 1


def test_partial_redaction_keeps_the_rest_of_the_file(tmp_path):
    settings = seeded_settings(tmp_path)
    notes = settings.workspace_root / "team-notes.md"
    notes.write_text(NOTES.format(s=SECRET), encoding="utf-8")
    _forget_secret(settings)
    text = notes.read_text(encoding="utf-8")
    assert SECRET not in text
    assert "STRIPE_KEY=[REDACTED]" in text
    assert "Retro is Friday at 3pm." in text



def test_estimated_impact_counts_redactions(tmp_path):
    settings = seeded_settings(tmp_path)
    (settings.workspace_root / "team-notes.md").write_text(NOTES.format(s=SECRET), encoding="utf-8")
    (settings.workspace_root / "leaked-key.txt").write_text(SECRET + "\n", encoding="utf-8")
    plan = Engine(settings).plan(
        target_id="fs:leaked-key.txt", target_kind="secret", target_text=SECRET, mode="fact_revocation"
    )
    assert plan["estimated_impact"]["delete"] == 1
    assert plan["estimated_impact"]["redact"] == 1


def test_receipt_counts_redacted_records_separately(tmp_path):
    settings = seeded_settings(tmp_path)
    (settings.workspace_root / "team-notes.md").write_text(NOTES.format(s=SECRET), encoding="utf-8")
    engine, plan = _forget_secret(settings)
    counts = engine.verify(request_id=plan["request_id"])["counts"]
    assert counts["records_removed"] == 1
    assert counts["records_redacted"] == 1
    assert counts["records_regenerated"] == 0


def test_log_line_appended_during_delete_is_kept(tmp_path, monkeypatch):
    from redacto.adapters.jsonl_logs import JsonlLogAdapter

    settings = seeded_settings(tmp_path)
    engine = Engine(settings)
    plan = engine.plan(target_id="fs:acquisition-plan.md")
    real_write = JsonlLogAdapter._atomic_write

    def agent_appends_first(self, content, *args, **kwargs):
        with settings.jsonl_log_path.open("a", encoding="utf-8") as handle:
            handle.write('{"event_id": "evt-live", "content": "build 812 passed"}\n')
        return real_write(self, content, *args, **kwargs)

    monkeypatch.setattr(JsonlLogAdapter, "_atomic_write", agent_appends_first)
    approve_and_apply(engine, plan)
    text = settings.jsonl_log_path.read_text(encoding="utf-8")
    assert "evt-live" in text
    assert "evt-dup-1" not in text



def test_approval_ref_error_code_is_machine_readable(tmp_path):
    settings = seeded_settings(tmp_path)
    engine = Engine(settings)
    plan = engine.plan(target_id="fs:acquisition-plan.md")
    with pytest.raises(RedactoError) as excinfo:
        engine.approve_plan(plan_id=plan["plan_id"], approval_ref="ab")
    assert excinfo.value.code == "invalid_approval_ref"


def test_regenerate_without_a_model_warns(tmp_path):
    settings = seeded_settings(tmp_path, regenerate_derivatives=True)
    plan = Engine(settings).plan(target_id="fs:acquisition-plan.md")
    assert any("no model is configured" in w for w in plan["warnings"])
    assert not any(i["proposed_action"] == "REGENERATE_FROM_ALLOWED_SOURCES" for i in plan["items"])
