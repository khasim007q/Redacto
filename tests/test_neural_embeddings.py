"""Neural provider safety/compatibility without downloading weights in unit tests."""

import math
import sys
from dataclasses import replace
from types import SimpleNamespace

import pytest

from redacto.discovery import neural
from redacto.discovery.embeddings import build_embedder
from redacto.errors import RedactoError


class Tokenizer:
    def encode(self, text, **kwargs):
        return [ord(char) for char in text]

    def decode(self, tokens, **kwargs):
        return "".join(chr(token) for token in tokens)

    def num_special_tokens_to_add(self, **kwargs):
        return 2


class FakeModel:
    tokenizer = Tokenizer()
    max_seq_length = 16

    def __init__(self):
        self.chunks = []

    def get_embedding_dimension(self):
        return 2

    def encode(self, chunks, **kwargs):
        self.chunks.extend(chunks)
        return [[0.6, 0.8] for _ in chunks]


def test_neural_provider_pins_revision_cpu_and_safe_weights(monkeypatch):
    captured = {}

    def constructor(name, **kwargs):
        captured.update(name=name, **kwargs)
        return FakeModel()

    neural._load_model.cache_clear()
    monkeypatch.setitem(sys.modules, "sentence_transformers", SimpleNamespace(SentenceTransformer=constructor))
    monkeypatch.setitem(sys.modules, "huggingface_hub", SimpleNamespace(snapshot_download=lambda **kwargs: "pinned-cache-path"))
    try:
        provider = neural.SentenceTransformerEmbeddingProvider(local_files_only=True)
        vector = provider.embed("text")
        assert math.isclose(sum(v * v for v in vector), 1)
        assert captured["trust_remote_code"] is False
        assert captured["model_kwargs"] == {"use_safetensors": True}
        assert captured["device"] == "cpu" and captured["local_files_only"]
        assert captured["revision"] == neural.DEFAULT_REVISION
        assert captured["name"] == "pinned-cache-path"
        assert neural.DEFAULT_REVISION in provider.model_id
    finally:
        neural._load_model.cache_clear()


def test_long_record_tail_is_embedded_and_cache_does_not_keep_plaintext(monkeypatch):
    model = FakeModel()
    monkeypatch.setattr(neural, "_load_model", lambda *args: model)
    provider = neural.SentenceTransformerEmbeddingProvider()
    text = "public " * 100 + "SECRETTAIL"
    provider.embed(text)
    assert model.chunks[-1].endswith("TAIL")
    count = len(model.chunks)
    provider.embed(text)
    assert len(model.chunks) == count
    assert all(len(key) == 64 and "public" not in key for key in provider._cache)


@pytest.mark.parametrize("result", [[[float("nan"), 0]], [[0, 0]], [[1]], [[float("inf"), 0]]])
def test_malformed_embeddings_fail_closed(monkeypatch, result):
    model = FakeModel()
    model.encode = lambda *args, **kwargs: result
    monkeypatch.setattr(neural, "_load_model", lambda *args: model)
    with pytest.raises(RedactoError) as exc:
        neural.SentenceTransformerEmbeddingProvider().embed("secret")
    assert exc.value.code == "embedding_inference_failed"
    assert "secret" not in str(exc.value)


def test_window_budget_failure_cannot_be_reported_as_clean(monkeypatch):
    monkeypatch.setattr(neural, "_load_model", lambda *args: FakeModel())
    with pytest.raises(RedactoError) as exc:
        neural.SentenceTransformerEmbeddingProvider().embed("x" * 5000)
    assert exc.value.code == "embedding_input_too_large"


def test_model_failure_does_not_silently_switch_to_hashing(monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("confidential provider diagnostics")

    neural._load_model.cache_clear()
    monkeypatch.setitem(sys.modules, "sentence_transformers", SimpleNamespace(SentenceTransformer=broken))
    monkeypatch.setitem(sys.modules, "huggingface_hub", SimpleNamespace(snapshot_download=lambda **kwargs: "pinned-cache-path"))
    try:
        with pytest.raises(RedactoError) as exc:
            neural.SentenceTransformerEmbeddingProvider().embed("secret")
        assert exc.value.code == "embedding_model_unavailable"
        assert "confidential" not in str(exc.value)
    finally:
        neural._load_model.cache_clear()


def test_custom_models_require_immutable_revision(settings):
    with pytest.raises(RedactoError):
        replace(settings, embedding_provider="sentence_transformers", embedding_model="custom/model")
    with pytest.raises(RedactoError):
        build_embedder("sentence_transformers", revision="main")
    other = build_embedder("sentence_transformers", model="custom/model", revision="a" * 40)
    assert other.model_id != build_embedder("sentence_transformers").model_id
    with pytest.raises(RedactoError):
        build_embedder("sentence_transformers", model="C:/local/model", revision="a" * 40)


def test_dependency_initialization_errors_are_structured(monkeypatch):
    class BrokenDependencies:
        def __getattr__(self, name):
            raise RuntimeError("sensitive dependency diagnostic")

    neural._load_model.cache_clear()
    monkeypatch.setitem(sys.modules, "sentence_transformers", BrokenDependencies())
    try:
        with pytest.raises(RedactoError) as exc:
            neural.SentenceTransformerEmbeddingProvider().embed("private")
        assert exc.value.code == "embedding_dependency_unavailable"
        assert "sensitive" not in str(exc.value)
    finally:
        neural._load_model.cache_clear()


def test_secret_revocation_does_not_require_neural_weights(engine, monkeypatch):
    from conftest import approve_and_apply
    from redacto.engine import Engine
    from test_support.fixtures import SOURCE_ID

    def must_not_load(*args):
        pytest.fail("Credentials must not be assessed with an embedding model")

    monkeypatch.setattr(neural, "_load_model", must_not_load)
    engine = Engine(replace(engine.settings, embedding_provider="sentence_transformers"))
    plan = engine.plan(target_id=SOURCE_ID, target_kind="secret", target_text="credential123456789", mode="fact_revocation")
    approve_and_apply(engine, plan)
    assert engine.guard().evaluate(record_id="new", content="KEY=credential123456789").decision == "blocked"


def test_neural_configuration_uses_separate_threshold_defaults(tmp_path, monkeypatch):
    from redacto.config import load_settings

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("REDACTO_EMBEDDING_PROVIDER", "sentence_transformers")
    monkeypatch.delenv("REDACTO_EMBEDDING_CANDIDATE_THRESHOLD", raising=False)
    monkeypatch.delenv("REDACTO_EMBEDDING_QUARANTINE_THRESHOLD", raising=False)
    monkeypatch.setenv("REDACTO_WORKSPACE_ROOT", str(tmp_path))
    settings = load_settings()
    assert settings.embedding_candidate_threshold == 0.55
    assert settings.embedding_quarantine_threshold == 0.60
