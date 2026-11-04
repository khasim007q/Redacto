"""Explicit opt-in integration: actual pinned multilingual weights on CPU."""

import os

import pytest

from conftest import approve_and_apply
from redacto.discovery.embeddings import build_embedder, cosine
from test_support.local import local_settings
from redacto.engine import Engine
from dataclasses import replace

pytestmark = pytest.mark.skipif(os.environ.get("REDACTO_TEST_NEURAL") != "1", reason="set REDACTO_TEST_NEURAL=1 to load pinned local neural weights")


@pytest.mark.parametrize("provider", ["sentence_transformers", "hybrid"])
def test_real_multilingual_discovery_review_and_replay_guard(tmp_path, provider):
    settings = replace(local_settings(tmp_path, hmac_key="synthetic-test"), embedding_provider=provider,
                       embedding_candidate_threshold=0.55, embedding_quarantine_threshold=0.60)
    settings.workspace_root.mkdir()
    source = "The company will acquire the robotics business for forty-two million dollars."
    translation = "La empresa comprará el negocio de robótica por cuarenta y dos millones de dólares."
    public = "The public SDK supports Linux and Windows."
    (settings.workspace_root / "source.md").write_text(source, encoding="utf-8")
    (settings.workspace_root / "translation.md").write_text(translation, encoding="utf-8")
    (settings.workspace_root / "public.md").write_text(public, encoding="utf-8")
    engine = Engine(settings)
    plan = engine.plan(target_id="fs:source.md", stores=["filesystem"], use_model=False)
    item = next(i for i in plan["items"] if i["record_id"] == "fs:translation.md")
    assert item["evidence_class"] == "SUSPECTED_DERIVATIVE" and not item["approved"]
    approve_and_apply(engine, plan)
    assert engine.guard().evaluate(record_id="replayed", content=translation).decision == "quarantined"
    # An unseen reformulation must be found by semantic comparison, not by the
    # new exact fingerprint hold for previously reviewed candidate payloads.
    unseen = "La adquisición del negocio robótico costará cuarenta y dos millones de dólares."
    decision = engine.guard().evaluate(record_id="unseen", content=unseen)
    assert decision.decision == "quarantined"
    assert decision.reason_code == "embedding_similarity"
    assert engine.guard().evaluate(record_id="public", content=public).decision == "allowed"
    receipt = engine.verify(request_id=plan["request_id"])
    assert receipt["status"] == "NEEDS_REVIEW"
    assert any(f["record_id"] == "fs:translation.md" for f in receipt["receipt"]["semantic_verification"]["findings"])
    # Old tombstones from another model are not compared with these vectors.
    assert len(engine.embedder().embed(source)) == (896 if provider == "hybrid" else 384)
