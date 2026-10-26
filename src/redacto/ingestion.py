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
from typing import Any, Iterable, Mapping, Sequence

from redacto.discovery.embeddings import EmbeddingProvider, cosine
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


def token_set(text: str) -> set[str]:
    """All normalized tokens, uncapped, for verification scans."""
    return {word for word in normalize_loose(text).split() if len(word) >= 2}


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
    embedding: tuple[float, ...] = ()
    embedding_model: str = ""

    @classmethod
    def build(
        cls, content: str, key: str, embedder: EmbeddingProvider | None = None
    ) -> "TombstoneMaterial":
        embedding: tuple[float, ...] = ()
        model = ""
        if embedder is not None and getattr(embedder, "model_id", "none") != "none":
            values = embedder.embed(content)
            if values:
                embedding = tuple(values)
                model = embedder.model_id
        return cls(
            fingerprint=_hmac(content, key),
            shingles=tuple(_hmac(item, key) for item in shingles(content)),
            anchors=tuple(
                f"{weight}:{_hmac(value, key)}" for value, weight in anchor_items(content)
            ),
            tokens=tuple(_hmac(item, key) for item in tokens(content)),
            embedding=embedding,
            embedding_model=model,
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
    degraded: bool = False

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
            "degraded": self.degraded,
        }


def _allowed() -> GuardDecision:
    return GuardDecision(decision=ALLOWED, reason_code="no_match", match_score=0.0)


class TombstoneGuard:
    """Evaluate records against active tombstones before admission.

    Tombstones are grouped by the key version that produced their material. During
    rotation every active version must remain in the key ring. If any active
    tombstone references a missing key, the guard fails closed: ingestion is blocked
    rather than silently claiming protection it cannot provide.
    """

    def __init__(
        self,
        tombstones: Iterable[dict[str, Any]],
        keyring: Mapping[int, str],
        current_version: int,
        embedder: EmbeddingProvider | None = None,
        embedding_threshold: float = 0.30,
    ):
        self._tombstones = [t for t in tombstones if t.get("status") == "active"]
        self._keyring = {int(version): key for version, key in keyring.items()}
        self._current = int(current_version)
        self._embedder = embedder
        self._embedding_threshold = embedding_threshold
        required_versions: set[int] = set()
        for tombstone in self._tombstones:
            required_versions.add(int(tombstone.get("key_version") or 1))
            for entry in tombstone.get("related_fingerprints", []):
                if isinstance(entry, dict) and entry.get("version"):
                    required_versions.add(int(entry["version"]))
        self._missing_versions = sorted(v for v in required_versions if v not in self._keyring)

    @classmethod
    def from_repo(
        cls,
        repo,
        *,
        keyring: Mapping[int, str],
        current_version: int,
        embedder: EmbeddingProvider | None = None,
        embedding_threshold: float = 0.30,
    ) -> "TombstoneGuard":
        return cls(
            repo.list_tombstones(statuses=("active",)),
            keyring,
            current_version,
            embedder=embedder,
            embedding_threshold=embedding_threshold,
        )

    @property
    def active_count(self) -> int:
        return len(self._tombstones)

    @property
    def protection_degraded(self) -> bool:
        return bool(self._missing_versions)

    @property
    def missing_versions(self) -> list[int]:
        return list(self._missing_versions)

    def evaluate(self, *, record_id: str, content: str) -> GuardDecision:
        if not self._tombstones:
            return _allowed()
        if self._missing_versions:
            return GuardDecision(
                decision=BLOCKED,
                reason_code="key_unavailable_fail_closed",
                match_score=1.0,
                degraded=True,
            )

        versions: set[int] = {
            int(tombstone.get("key_version") or 1) for tombstone in self._tombstones
        }
        for tombstone in self._tombstones:
            for entry in tombstone.get("related_fingerprints", []):
                if isinstance(entry, dict) and entry.get("version"):
                    versions.add(int(entry["version"]))
        materials: dict[int, tuple[str, set[str], set[str], set[str]]] = {}
        for version in versions:
            key = self._keyring[version]
            materials[version] = (
                _hmac(content, key),
                {_hmac(item, key) for item in shingles(content)},
                {_hmac(item, key) for item in anchors(content)},
                {_hmac(item, key) for item in tokens(content)},
            )

        record_embedding: list[float] = []
        if self._embedder is not None and any(t.get("embedding") for t in self._tombstones):
            record_embedding = self._embedder.embed(content)

        best = _allowed()
        for tombstone in self._tombstones:
            version = int(tombstone.get("key_version") or 1)
            decision = self._evaluate_one(
                tombstone,
                record_id,
                *materials[version],
                record_embedding=record_embedding,
                fingerprints_by_version={v: material[0] for v, material in materials.items()},
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
        record_id: str,
        record_fingerprint: str,
        record_shingles: set[str],
        record_anchors: set[str],
        record_tokens: set[str],
        record_embedding: list[float] | None = None,
        fingerprints_by_version: dict[int, str] | None = None,
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
        for entry in tombstone.get("related_fingerprints", []):
            if isinstance(entry, dict):
                version = int(entry.get("version") or tombstone.get("key_version") or 1)
                expected = entry.get("fingerprint")
                if expected and (fingerprints_by_version or {}).get(version) == expected:
                    return GuardDecision(BLOCKED, "exact_derivative_fingerprint", 1.0, **base)
            elif entry == record_fingerprint:
                return GuardDecision(BLOCKED, "exact_derivative_fingerprint", 1.0, **base)

        # 3. Substantial partial copy, e.g. a rebuilt index chunk.
        tombstone_shingles = set(tombstone["shingles"])
        if record_shingles and len(record_shingles) >= MIN_SHINGLES_FOR_BLOCK:
            containment = len(record_shingles & tombstone_shingles) / len(record_shingles)
            if containment >= PARTIAL_COPY_BLOCK_RATIO:
                return GuardDecision(BLOCKED, "partial_copy", containment, **base)

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

        # 7. Embedding similarity: a risk signal, never proof. It can only
        #    quarantine; exact copies and shared content are handled above.
        tombstone_embedding = tombstone.get("embedding") or []
        if record_embedding and tombstone_embedding:
            similarity = cosine(record_embedding, tombstone_embedding)
            if similarity >= self._embedding_threshold:
                return GuardDecision(QUARANTINED, "embedding_similarity", similarity, **base)

        return _allowed()


def overlap_ratio(target_text: str, record_text: str) -> float:
    """Share of the record's 5-word shingles that also occur in the target."""
    record_shingles = set(shingles(record_text))
    if not record_shingles:
        return 0.0
    target_shingles = set(shingles(target_text))
    return len(record_shingles & target_shingles) / len(record_shingles)


def contains_verbatim_passage(
    target_text: str, record_text: str, *, size: int = 8
) -> bool:
    """True when the record contains a verbatim run of target words.

    Used to catch a confidential sentence quoted inside a larger, useful record.
    The whole-record copy case is handled earlier by the exact matcher.
    """
    target_shingles = set(shingles(target_text, size=size))
    if not target_shingles:
        return False
    return bool(target_shingles & set(shingles(record_text, size=size)))


def summarize_guard_findings(findings: Sequence[dict[str, Any]]) -> dict[str, int]:
    return {
        "blocked": sum(1 for item in findings if item["decision"] == BLOCKED),
        "quarantined": sum(1 for item in findings if item["decision"] == QUARANTINED),
        "skipped": sum(1 for item in findings if item["decision"] == "skipped"),
        "allowed": sum(1 for item in findings if item["decision"] == ALLOWED),
    }