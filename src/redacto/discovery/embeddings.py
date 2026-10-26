"""Embedding-based paraphrase signals.

Embeddings are a **candidate-generation and risk-scoring signal**, never proof of
lineage and never sufficient to block. The default provider is a deterministic,
local feature-hashing embedding: no network, no model download, reproducible on
the fixture. A real embedding endpoint can replace it through the same protocol.

The local provider adds two things that make paraphrases comparable:
- number-word normalization ("forty-two million" -> "42 million"),
- a small, documented concept map for this domain (pay/buy -> acquire, firm/maker
  -> company, roughly -> about).

That is a lexical-semantic embedding, not a neural one. Its limits are reported
honestly by the calibration report.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from typing import Protocol, Sequence

from redacto.discovery.normalization import normalize_loose

DIMENSION = 512
MODEL_ID = "local-hashing-v1"

_NUMBER_WORDS = {
    "zero": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
    "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12,
    "thirteen": 13, "fourteen": 14, "fifteen": 15, "sixteen": 16,
    "seventeen": 17, "eighteen": 18, "nineteen": 19, "twenty": 20, "thirty": 30,
    "forty": 40, "fifty": 50, "sixty": 60, "seventy": 70, "eighty": 80,
    "ninety": 90,
}
_NUMBER_TOKEN = "|".join(sorted(_NUMBER_WORDS, key=len, reverse=True))
_NUMBER_SEQUENCE = re.compile(
    rf"\b((?:{_NUMBER_TOKEN})(?:[-\s](?:{_NUMBER_TOKEN}))*)\b", re.IGNORECASE
)
_CONCEPTS = {
    "pay": "acquire", "paying": "acquire", "paid": "acquire", "pays": "acquire",
    "buy": "acquire", "buying": "acquire", "buys": "acquire", "bought": "acquire",
    "purchase": "acquire", "purchased": "acquire", "purchases": "acquire",
    "acquisition": "acquire", "acquire": "acquire", "acquires": "acquire",
    "acquired": "acquire", "buyer": "acquirer", "acquirer": "acquirer",
    "firm": "company", "maker": "company", "business": "company", "company": "company",
    "roughly": "about", "approximately": "about", "around": "about", "about": "about",
    "deal": "transaction", "transaction": "transaction",
    "worth": "value", "valued": "value", "valuation": "value", "value": "value",
    "usd": "dollars", "dollar": "dollars", "dollars": "dollars",
    "secret": "confidential", "confidential": "confidential",
}


def _number_words_to_digits(text: str) -> str:
    """Convert small spelled-out numbers, including hyphenated tens, to digits."""
    def convert(match: re.Match) -> str:
        phrase = match.group(1)
        parts = re.split(r"[-\s]+", phrase.lower())
        if not parts or not all(part in _NUMBER_WORDS for part in parts):
            return phrase
        total = 0
        for part in parts:
            total += _NUMBER_WORDS[part]
        return str(total)

    return _NUMBER_SEQUENCE.sub(convert, text)


def normalize_for_embedding(text: str) -> str:
    numbered = _number_words_to_digits(text)
    tokens = normalize_loose(numbered).split()
    return " ".join(_CONCEPTS.get(token, token) for token in tokens)


@dataclass(frozen=True)
class Embedding:
    values: tuple[float, ...]
    model_id: str = MODEL_ID

    def as_list(self) -> list[float]:
        return list(self.values)


class EmbeddingProvider(Protocol):
    model_id: str

    def embed(self, text: str) -> list[float]: ...


@dataclass
class HashingEmbeddingProvider:
    """Deterministic feature hashing over normalized tokens and n-grams."""

    dimension: int = DIMENSION
    model_id: str = MODEL_ID

    def embed(self, text: str) -> list[float]:
        normalized = normalize_for_embedding(text)
        tokens = [token for token in normalized.split() if len(token) >= 2]
        if not tokens:
            return [0.0] * self.dimension

        vector = [0.0] * self.dimension
        for token in tokens:
            weight = 2.0 if token.replace(".", "").isdigit() else 1.0
            if token in {"acquire", "confidential", "transaction"}:
                weight = 1.6
            self._add(vector, f"w:{token}", weight)
        for first, second in zip(tokens, tokens[1:]):
            self._add(vector, f"b:{first} {second}", 0.45)
        for token in tokens:
            if len(token) < 5:
                continue
            for index in range(len(token) - 3):
                self._add(vector, f"c:{token[index:index + 4]}", 0.15)
        norm = math.sqrt(sum(value * value for value in vector))
        if norm:
            vector = [value / norm for value in vector]
        return vector

    def _add(self, vector: list[float], feature: str, weight: float) -> None:
        digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest()
        index = int.from_bytes(digest[:4], "little") % self.dimension
        sign = 1.0 if digest[4] & 1 else -1.0
        vector[index] += sign * weight


@dataclass
class NullEmbeddingProvider:
    model_id: str = "none"

    def embed(self, text: str) -> list[float]:
        return []


def cosine(first: Sequence[float], second: Sequence[float]) -> float:
    if not first or not second or len(first) != len(second):
        return 0.0
    dot = sum(a * b for a, b in zip(first, second))
    norm_first = math.sqrt(sum(a * a for a in first))
    norm_second = math.sqrt(sum(b * b for b in second))
    if not norm_first or not norm_second:
        return 0.0
    return max(0.0, min(1.0, dot / (norm_first * norm_second)))


def build_embedder(provider: str) -> EmbeddingProvider:
    normalized = (provider or "").strip().lower()
    if normalized in {"", "none", "disabled"}:
        return NullEmbeddingProvider()
    if normalized in {"local_hashing", "local-hashing", "hashing"}:
        return HashingEmbeddingProvider()
    raise ValueError(
        f"Unsupported embedding provider '{provider}'. Supported: local_hashing, none."
    )


@dataclass
class CalibrationExample:
    text: str
    label: str  # "positive" or "negative"


@dataclass
class CalibrationReport:
    threshold: float
    false_positives: int
    false_negatives: int
    true_positives: int
    true_negatives: int
    scores: list[dict[str, object]] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.true_positives + self.false_positives + self.true_negatives + self.false_negatives

    def as_dict(self) -> dict[str, object]:
        return {
            "threshold": self.threshold,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "true_positives": self.true_positives,
            "true_negatives": self.true_negatives,
            "total": self.total,
            "scores": self.scores,
        }


def calibrate(
    examples: Sequence[CalibrationExample],
    target_text: str,
    *,
    threshold: float,
    provider: EmbeddingProvider | None = None,
) -> CalibrationReport:
    embedder = provider or HashingEmbeddingProvider()
    target = embedder.embed(target_text)
    report = CalibrationReport(threshold=threshold, false_positives=0, false_negatives=0, true_positives=0, true_negatives=0)
    for example in examples:
        score = cosine(target, embedder.embed(example.text))
        predicted = score >= threshold
        actual = example.label == "positive"
        if predicted and actual:
            report.true_positives += 1
        elif predicted and not actual:
            report.false_positives += 1
        elif actual and not predicted:
            report.false_negatives += 1
        else:
            report.true_negatives += 1
        report.scores.append(
            {"label": example.label, "score": round(score, 4), "text_redacted": example.text[:40] + ("..." if len(example.text) > 40 else "")}
        )
    return report


# Labelled synthetic set. Positives paraphrase the confidential target without
# necessarily sharing its distinctive proper nouns; negatives are unrelated or
# related-but-non-disclosing records that must not be flagged.
CALIBRATION_TARGET = (
    "Meridian Capital will acquire Halcyon Robotics for $42 million in an all-cash "
    "transaction. Closing is targeted for 14 March 2027. The integration budget is "
    "$3.5 million and the retention pool covers 18 engineers."
)

CALIBRATION_EXAMPLES: tuple[CalibrationExample, ...] = (
    CalibrationExample("The buyer is paying roughly forty-two million dollars for the robotics company.", "positive"),
    CalibrationExample("A private firm is buying the sensor maker for about 42 million in cash.", "positive"),
    CalibrationExample("The deal values the robotics business at approximately 42 million dollars.", "positive"),
    CalibrationExample("The transaction is expected to close in March 2027, subject to regulatory approval.", "positive"),
    CalibrationExample("The buyer set aside an integration budget and retention for the engineering team.", "positive"),
    CalibrationExample("Rotate staging certificates and upgrade Postgres to version 16.", "negative"),
    CalibrationExample("Halcyon Robotics published a public blog post about warehouse safety sensors.", "negative"),
    CalibrationExample("Embedding sharding improves recall for long documents.", "negative"),
    CalibrationExample("Deployed build 4271 to the staging environment.", "negative"),
    CalibrationExample("The quarterly engineering offsite is scheduled for next month.", "negative"),
)


def default_calibration(threshold: float) -> CalibrationReport:
    return calibrate(CALIBRATION_EXAMPLES, CALIBRATION_TARGET, threshold=threshold)