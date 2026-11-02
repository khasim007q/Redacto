"""Regeneration of a derivative from its remaining allowed sources.

A summary or memory built from several sources does not have to be deleted when
one of them is revoked: it can be rewritten from the sources that remain. The
regenerator is a replaceable interface; the bundled one calls an
OpenAI-compatible chat endpoint (a local Ollama, for example) configured with
REDACTO_MODEL_*.

The model never decides whether its output is safe. The engine checks every
regenerated text against the revoked target's keyed material before writing it,
and refuses the write when the text still resembles the target.
"""

from __future__ import annotations

from typing import Protocol, Sequence
import re

import httpx
from redacto.discovery.normalization import normalize_loose

MAX_SOURCE_CHARS = 12_000
MAX_OUTPUT_CHARS = 8_000


def validate_regeneration(text: str, sources: Sequence[str]) -> dict:
    """Conservative grounding/retention gate, independent of the generator.

    Every emitted sentence must be extractive from one allowed source. This
    deliberately rejects fluent unsupported paraphrases too: word overlap alone
    cannot validate factual consistency or prevent a model recalling a secret.
    Each nonempty allowed source must retain at least a quarter of its distinct
    words. This is a bounded usefulness floor, not a completeness guarantee.
    """
    if not isinstance(text, str) or not text.strip() or len(text) > MAX_OUTPUT_CHARS:
        raise RegenerationError("regenerated output is empty or oversized", code="regenerate_ungrounded")
    body = re.sub(r"^\s*(?:summary|rewritten summary)\s*:\s*", "", text, flags=re.IGNORECASE)
    normalized_sources = [normalize_loose(source) for source in sources if source.strip()]
    sentences = [normalize_loose(s) for s in re.split(r"[.!?]+(?:\s+|$)|\n+", body) if normalize_loose(s)]
    if not sentences or any(not any(sentence in source for source in normalized_sources) for sentence in sentences):
        raise RegenerationError("output contains a statement not grounded in allowed sources", code="regenerate_ungrounded")
    output_words = set(normalize_loose(body).split())
    retention = [len(output_words & set(source.split())) / max(1, len(set(source.split()))) for source in normalized_sources]
    if not retention or min(retention) < 0.25:
        raise RegenerationError("output discards too much allowed-source information", code="regenerate_low_retention")
    return {"method": "extractive_sentence_grounding", "minimum_source_word_retention": round(min(retention), 4)}


class RegenerationError(RuntimeError):
    def __init__(self, message: str, *, code: str = "regenerate_failed"):
        super().__init__(message)
        self.code = code


class Regenerator(Protocol):
    model_id: str

    def regenerate(self, *, record_type: str, current_length: int, sources: Sequence[str]) -> str:
        """Rewrite a record of `record_type` using only `sources`."""


class NullRegenerator:
    model_id = "none"

    def regenerate(self, *, record_type: str, current_length: int, sources: Sequence[str]) -> str:
        raise RegenerationError("no regeneration model is configured", code="regenerate_unavailable")


class ExtractiveRegenerator:
    """Deterministic reference implementation; keeps all allowed source text."""
    model_id = "extractive-v1"

    def regenerate(self, *, record_type: str, current_length: int, sources: Sequence[str]) -> str:
        text = "\n".join(sources).strip()
        if not text or len(text) > MAX_OUTPUT_CHARS:
            raise RegenerationError("allowed sources cannot fit safely into an extractive rewrite")
        return text


_PROMPT = (
    "You rewrite one {record_type} that an AI agent keeps. Write it again using ONLY "
    "the facts in the sources below. Do not add, guess or recall any other information, "
    "even if you think the original contained it. Keep it about {length} characters. "
    "Reply with the rewritten text only, no preamble.\n\n{sources}"
)


class OpenAICompatibleRegenerator:
    def __init__(self, *, base_url: str, model: str, timeout: float = 60.0):
        self._url = base_url.rstrip("/") + "/chat/completions"
        self.model_id = model
        self._timeout = timeout

    def regenerate(self, *, record_type: str, current_length: int, sources: Sequence[str]) -> str:
        joined = "\n\n".join(
            f"Source {index + 1}:\n{text[:MAX_SOURCE_CHARS]}" for index, text in enumerate(sources)
        )
        body = {
            "model": self.model_id,
            "temperature": 0,
            "messages": [
                {
                    "role": "user",
                    "content": _PROMPT.format(
                        record_type=record_type, length=max(80, current_length), sources=joined
                    ),
                }
            ],
        }
        try:
            response = httpx.post(self._url, json=body, timeout=self._timeout)
            response.raise_for_status()
            text = response.json()["choices"][0]["message"]["content"]
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
            raise RegenerationError(f"regeneration model failed: {type(exc).__name__}") from exc
        if not isinstance(text, str):
            raise RegenerationError("regeneration model returned a non-text response")
        text = text.strip()
        if not text:
            raise RegenerationError("regeneration model returned nothing")
        if len(text) > MAX_OUTPUT_CHARS:
            raise RegenerationError("regeneration model output exceeds the size limit")
        return text


def build_regenerator(
    *, provider: str, base_url: str | None, model: str | None, timeout: float = 60.0
) -> Regenerator:
    if provider == "extractive":
        return ExtractiveRegenerator()
    if provider in {"openai_compatible", "openai-compatible", "ollama"} and base_url and model:
        if base_url.lower().startswith(("http://", "https://")):
            return OpenAICompatibleRegenerator(base_url=base_url, model=model, timeout=timeout)
    return NullRegenerator()
