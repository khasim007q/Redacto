"""Deterministic exact and normalized discovery.

Whole-document matching is used for source revocation. Substring matching is
reserved for narrowly scoped fact/secret targets with a minimum length, so a
short value cannot delete unrelated text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from redacto.adapters.base import Record
from redacto.discovery.normalization import normalize_loose, variants

MIN_SUBSTRING_LEN = 8

_ENTITY_PHRASE = re.compile(r"\b[A-Z][a-zA-Z0-9&'\-]*(?:\s+[A-Z][a-zA-Z0-9&'\-]*){1,3}\b")
_ENTITY_STOPWORDS = {
    "the",
    "this",
    "that",
    "closing",
    "integration",
    "executive",
    "ignore",
    "delete",
    "do",
    "summary",
    "public",
    "upgrade",
}


@dataclass(frozen=True)
class ExactMatch:
    kind: str
    detail: str
    matched_chars: int = 0
    record_chars: int = 0

    @property
    def is_partial(self) -> bool:
        return self.kind == "normalized_variant" and self.record_chars > 0


class ExactMatcher:
    def __init__(
        self,
        *,
        target_text: str,
        target_record_id: str,
        target_locator: dict[str, str],
        target_kind: str = "source",
    ):
        self._target_id = target_record_id
        self._target_locator = target_locator
        self._target_kind = target_kind
        self._target_loose = normalize_loose(target_text)
        self._variants = [
            value
            for value in variants(target_text)
            if len(normalize_loose(value)) >= MIN_SUBSTRING_LEN
        ]

    def match(self, record: Record) -> ExactMatch | None:
        length = len(record.content)
        if record.record_id == self._target_id:
            return ExactMatch("record_id", "Record is the revocation target.", length, length)
        if record.locator == self._target_locator:
            return ExactMatch("locator", "Same adapter locator as the target.", length, length)
        loose = normalize_loose(record.content)
        if self._target_loose and loose == self._target_loose:
            return ExactMatch(
                "normalized_content", "Normalized whole-content copy of the target.", length, length
            )
        if self._target_kind in {"secret", "fact"}:
            for variant in self._variants:
                if normalize_loose(variant) in loose:
                    return ExactMatch(
                        "normalized_variant",
                        "Contains a bounded normalized variant of the target value.",
                        len(variant),
                        length,
                    )
        return None


def extract_entities(text: str) -> set[str]:
    """Distinctive multi-word named entities used only as a weak signal."""
    entities: set[str] = set()
    for match in _ENTITY_PHRASE.finditer(text):
        phrase = match.group(0).strip()
        words = phrase.split()
        if len(words) < 2:
            continue
        if any(word.casefold() in _ENTITY_STOPWORDS for word in words):
            continue
        entities.add(phrase.casefold())
    return entities


def shares_entity(target_text: str, record_text: str) -> bool:
    lowered = record_text.casefold()
    return any(entity in lowered for entity in extract_entities(target_text))
