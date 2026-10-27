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
MIN_COMPACT_SECRET_LEN = 12
_COMPACT_SEPARATORS = re.compile(r"[\s\-_.]+")

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
        return self.kind in {"normalized_variant", "compact_variant"} and self.record_chars > 0


class ExactMatcher:
    def __init__(
        self,
        *,
        target_text: str,
        target_record_id: str,
        target_locator: dict[str, str],
        target_kind: str = "source",
        include_target_identity: bool = True,
    ):
        self._target_id = target_record_id
        self._target_locator = target_locator
        self._include_identity = include_target_identity
        self._target_kind = target_kind
        self._target_loose = normalize_loose(target_text)
        self._variants = [
            value
            for value in variants(target_text)
            if len(normalize_loose(value)) >= MIN_SUBSTRING_LEN
        ]
        compact = _COMPACT_SEPARATORS.sub("", target_text).casefold()
        self._compact = compact if len(compact) >= MIN_COMPACT_SECRET_LEN else ""

    def match(self, record: Record) -> ExactMatch | None:
        length = len(record.content)
        if self._include_identity and record.record_id == self._target_id:
            return ExactMatch("record_id", "Record is the revocation target.", length, length)
        if self._include_identity and record.locator == self._target_locator:
            return ExactMatch("locator", "Same adapter locator as the target.", length, length)
        loose = normalize_loose(record.content)
        # Whole-copy equality is checked against the record's primary text, because
        # `content` also carries metadata fields that do not change the document.
        core = record.core_content if record.core_content is not None else record.content
        loose_core = normalize_loose(core)
        if self._target_loose and (
            loose_core == self._target_loose or loose == self._target_loose
        ):
            core_len = len(core)
            return ExactMatch(
                "normalized_content",
                "Normalized whole-content copy of the target.",
                core_len,
                core_len,
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
        if self._target_kind == "secret" and self._compact:
            compact_record = _COMPACT_SEPARATORS.sub("", record.content).casefold()
            if self._compact in compact_record:
                return ExactMatch(
                    "compact_variant",
                    "Contains a separator-insensitive variant of the secret.",
                    len(self._compact),
                    length,
                )
        return None

    def value_in(self, text: str) -> bool:
        """True when a fact/secret value occurs in `text` (normalized or compact)."""
        loose = normalize_loose(text)
        if any(normalize_loose(variant) in loose for variant in self._variants):
            return True
        if self._target_kind == "secret" and self._compact:
            return self._compact in _COMPACT_SEPARATORS.sub("", text).casefold()
        return False


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
