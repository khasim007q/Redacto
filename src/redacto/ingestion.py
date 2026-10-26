"""Ingestion guard backed by revocation tombstones.

A tombstone retains only:
- a keyed HMAC fingerprint of the revoked content,
- keyed HMACs of normalized 5-word shingles and distinctive anchors,
- keyed HMACs of normalized tokens (for fact/secret targets),
- scope, policy and status.

It never retains the revoked content. At ingestion, a candidate record is
compared against active tombstones and resolved to `allowed`, `quarantined` or
`blocked`. Uncertain matches are quarantined for review, never silently dropped
and never auto-deleted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from redacto.discovery.normalization import fingerprint, normalize_loose

SHINGLE_SIZE = 5
MAX_SHINGLES = 400
MAX_ANCHORS = 64
MAX_TOKENS = 64

# A record must contain enough shingles before a containment ratio is trusted,
# so a tiny record that happens to share one phrase is not blocked.
MIN_SHINGLES_FOR_BLOCK = 4
MIN_SHINGLES_FOR_REVIEW = 3
PARTIAL_COPY_BLOCK_RATIO = 0.5
SIMILAR_CONTENT_REVIEW_RATIO = 0.2
MIN_ANCHOR_SCORE_FOR_REVIEW = 3
MIN_FACT_TOKENS = 3

ALLOWED = "allowed"
QUARANTINED = "quarantined"
BLOCKED = "blocked"

_SEVERITY = {ALLOWED: 0, QUARANTINED: 1, BLOCKED: 2}

_ANCHOR_PHRASE = re.compile(r"\b[A-Z][a-zA-Z0-9&'\-]*(?:\s+[A-Z][a-zA-Z0-9&'\-]*){1,3}\b")
_ANCHOR_WORD = re.compile(r"\b[A-Z][a-z][a-zA-Z0-9&'\-]{2,}\b")
_ANCHOR_NUMBER = re.compile(
    r"\b\d[\d,]*(?:\.\d+)?\s*(?:million|billion|thousand|percent|%|dollars?)?\b",
    re.IGNORECASE,
)
_ANCHOR_STOPWORDS = {
    "the",
    "this",
    "that",
    "and",
    "for",
    "with",
    "from",
    "closing",
    "integration",
    "executive",
    "ignore",
    "delete",
    "summary",
    "public",
    "upgrade",
    "project",
    "capital",
    "company",
    "group",
    "plan",
    "note",
    "notes",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
    "january",
    "february",
}


def _hmac(value: str, key: str) -> str:
    return fingerprint(value, key)


def shingles(text: str, *, size: int = SHINGLE_SIZE) -> list[str]:
    words = normalize_loose(text).split()
    if len(words) < size:
        return []
    seen: list[str] = []
    for index in range(len(words) - size + 1):
        shingle = " ".join(words[index : index + size])
        if shingle not in seen:
            seen.append(shingle)
        if len(seen) >= MAX_SHINGLES:
            break
    return seen


def anchor_items(text: str) -> list[tuple[str, int]]:
    """Distinctive anchor words, each with a weight.

    Proper-noun words weigh 1; numeric amounts weigh 2 because they are far more
    distinctive. Weights let the guard quarantine a paraphrase that reuses a name
    and an amount without also flagging a note that only shares a company name.
    """
    weighted: dict[str, int] = {}
    for match in _ANCHOR_WORD.finditer(text):
        word = normalize_loose(match.group(0))
        if len(word) < 4 or word in _ANCHOR_STOPWORDS or word.isdigit():
            continue
        weighted[word] = max(weighted.get(word, 0), 1)
    for match in _ANCHOR_PHRASE.finditer(text):
        for word in normalize_loose(match.group(0)).split():
            if len(word) < 3 or word in _ANCHOR_STOPWORDS or word.isdigit():
                continue
            weighted[word] = max(weighted.get(word, 0), 1)
    for match in _ANCHOR_NUMBER.finditer(text):
        number = normalize_loose(match.group(0))
        if number:
            weighted[number] = max(weighted.get(number, 0), 2)
    return list(weighted.items())[:MAX_ANCHORS]


def anchors(text: str) -> list[str]:
    """Anchor values only; weights are applied by the tombstone builder."""
    return [value for value, _weight in anchor_items(text)]


def tokens(text: str) -> list[str]:
    """Normalized tokens used only for fact/secret containment checks."""
    found: list[str] = []
    for word in normalize_loose(text).split():
        if len(word) < 2:
            continue
        if word not in found:
            found.append(word)
    return found[:MAX_TOKENS]


@dataclass(frozen=True)
class TombstoneMaterial:
    """Everything a tombstone needs, derived so the content is not recoverable."""

    fingerprint: str
    shingles: tuple[str, ...]
    anchors: tuple[str, ...]
    tokens: tuple[str, ...]

    @classmethod
    def build(cls, content: str, key: str) -> "TombstoneMaterial":
        return cls(
            fingerprint=_hmac(content, key),
            shingles=tuple(_hmac(item, key) for item in shingles(content)),
            anchors=tuple(
                f"{weight}:{_hmac(value, key)}" for value, weight in anchor_items(content)
            ),
            tokens=tuple(_hmac(item, key) for item in tokens(content)),
        )


def _anchor_weights(stored: Iterable[str]) -> dict[str, int]:
    """Map stored `weight:hash` anchors to weights; values are never recoverable."""
    weights: dict[str, int] = {}
    for encoded in stored:
        weight_text, _, digest = encoded.partition(":")
        try:
            weights[digest] = int(weight_text)
        except ValueError:
            continue
    return weights


@dataclass(frozen=True)
class GuardDecision:
    decision: str
    reason_code: str
    match_score: float
    tombstone_id: str | None = None
    target_id: str | None = None
    target_kind: str | None = None
    label_redacted: str | None = None

    @property
    def blocked(self) -> bool:
        return self.decision == BLOCKED

    @property
    def quarantined(self) -> bool:
        return self.decision == QUARANTINED

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reason_code": self.reason_code,
            "match_score": round(self.match_score, 4),
            "tombstone_id": self.tombstone_id,
            "target_id": self.target_id,
            "target_kind": self.target_kind,
            "label_redacted": self.label_redacted,
        }


def _allowed() -> GuardDecision:
    return GuardDecision(decision=ALLOWED, reason_code="no_match", match_score=0.0)


class TombstoneGuard:
    """Evaluate records against active tombstones before admission."""

    def __init__(self, tombstones: Iterable[dict[str, Any]], key: str):
        self._tombstones = [t for t in tombstones if t.get("status") == "active"]
        self._key = key

    @classmethod
    def from_repo(cls, repo, key: str) -> "TombstoneGuard":
        return cls(repo.list_tombstones(statuses=("active",)), key)

    @property
    def active_count(self) -> int:
        return len(self._tombstones)

    def evaluate(self, *, record_id: str, content: str) -> GuardDecision:
        if not self._tombstones:
            return _allowed()

        record_fingerprint = _hmac(content, self._key)
        record_shingles = {_hmac(item, self._key) for item in shingles(content)}
        record_anchors = {_hmac(item, self._key) for item in anchors(content)}
        record_tokens = {_hmac(item, self._key) for item in tokens(content)}

        best = _allowed()
        for tombstone in self._tombstones:
            decision = self._evaluate_one(
                tombstone,
                record_id=record_id,
                record_fingerprint=record_fingerprint,
                record_shingles=record_shingles,
                record_anchors=record_anchors,
                record_tokens=record_tokens,
            )
            if _SEVERITY[decision.decision] > _SEVERITY[best.decision] or (
                decision.decision == best.decision and decision.match_score > best.match_score
            ):
                best = decision
            if best.decision == BLOCKED and best.reason_code in {
                "same_target",
                "revoked_record_id",
                "exact_fingerprint",
            }:
                break
        return best

    def _evaluate_one(
        self,
        tombstone: dict[str, Any],
        *,
        record_id: str,
        record_fingerprint: str,
        record_shingles: set[str],
        record_anchors: set[str],
        record_tokens: set[str],
    ) -> GuardDecision:
        base = {
            "tombstone_id": tombstone["tombstone_id"],
            "target_id": tombstone["target_id"],
            "target_kind": tombstone["target_kind"],
            "label_redacted": tombstone["label_redacted"],
        }

        # 1. The revoked record reappearing under its original identity.
        if record_id == tombstone["target_id"]:
            return GuardDecision(BLOCKED, "same_target", 1.0, **base)
        if record_id in set(tombstone["related_record_ids"]):
            return GuardDecision(BLOCKED, "revoked_record_id", 1.0, **base)

        # 2. Byte-for-byte (normalized) copy of the target or a removed derivative.
        if record_fingerprint == tombstone["fingerprint"]:
            return GuardDecision(BLOCKED, "exact_fingerprint", 1.0, **base)
        if record_fingerprint in set(tombstone["related_fingerprints"]):
            return GuardDecision(BLOCKED, "exact_derivative_fingerprint", 1.0, **base)

        # 3. Substantial partial copy, e.g. a rebuilt index chunk.
        tombstone_shingles = set(tombstone["shingles"])
        if record_shingles and len(record_shingles) >= MIN_SHINGLES_FOR_BLOCK:
            containment = len(record_shingles & tombstone_shingles) / len(record_shingles)
            if containment >= PARTIAL_COPY_BLOCK_RATIO:
                return GuardDecision(BLOCKED, "partial_copy", containment, **base)
        else:
            containment = 0.0

        # 4. Fact/secret targets: all distinctive tokens present.
        if tombstone["target_kind"] in {"fact", "secret"}:
            tombstone_tokens = set(tombstone["tokens"])
            if len(tombstone_tokens) >= MIN_FACT_TOKENS and tombstone_tokens.issubset(record_tokens):
                return GuardDecision(BLOCKED, "fact_containment", 1.0, **base)

        # 5. Weighted distinctive anchors: uncertain, hold for review.
        weights = _anchor_weights(tombstone["anchors"])
        anchor_score = sum(weight for anchor, weight in weights.items() if anchor in record_anchors)
        if anchor_score >= MIN_ANCHOR_SCORE_FOR_REVIEW:
            return GuardDecision(
                QUARANTINED,
                "anchor_overlap",
                min(1.0, anchor_score / max(1, sum(weights.values()))),
                **base,
            )

        # 6. Weaker content overlap: still uncertain, never destructive.
        if record_shingles and len(record_shingles) >= MIN_SHINGLES_FOR_REVIEW:
            similarity = len(record_shingles & tombstone_shingles) / len(record_shingles)
            if similarity >= SIMILAR_CONTENT_REVIEW_RATIO:
                return GuardDecision(QUARANTINED, "similar_content", similarity, **base)

        return _allowed()


def summarize_guard_findings(findings: Sequence[dict[str, Any]]) -> dict[str, int]:
    return {
        "blocked": sum(1 for item in findings if item["decision"] == BLOCKED),
        "quarantined": sum(1 for item in findings if item["decision"] == QUARANTINED),
        "allowed": sum(1 for item in findings if item["decision"] == ALLOWED),
    }