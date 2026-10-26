"""Evidence classes and the conservative default action policy."""

from __future__ import annotations

import re
from typing import Any

from redacto.discovery.relationship_assessor import minimize_snippet

DIRECT_MATCH = "DIRECT_MATCH"
CONFIRMED_DESCENDANT = "CONFIRMED_DESCENDANT"
SUSPECTED_DERIVATIVE = "SUSPECTED_DERIVATIVE"
RELATED_NONDISCLOSING = "RELATED_NONDISCLOSING"
UNKNOWN = "UNKNOWN"

EVIDENCE_CLASSES = (
    DIRECT_MATCH,
    CONFIRMED_DESCENDANT,
    SUSPECTED_DERIVATIVE,
    RELATED_NONDISCLOSING,
    UNKNOWN,
)

DELETE_RECORD = "DELETE_RECORD"
REDACT_SPAN = "REDACT_SPAN"
INVALIDATE_INDEX = "INVALIDATE_INDEX"
INVALIDATE_CACHE = "INVALIDATE_CACHE"
REGENERATE = "REGENERATE_FROM_ALLOWED_SOURCES"
REVIEW_REQUIRED = "REVIEW_REQUIRED"
SKIP_PRESERVE = "SKIP_PRESERVE"
UNREACHABLE = "UNREACHABLE"

ACTIONABLE = {DELETE_RECORD, REDACT_SPAN, INVALIDATE_INDEX, INVALIDATE_CACHE, REGENERATE}

# Below this share of the record, a substring match is held for review. Above it,
# the record is mostly the target value and the normal delete path still applies.
PARTIAL_DELETE_MIN_RATIO = 0.5

_QUOTES = re.compile(r"[\"'`]")


def redacted_reason(text: str, *, limit: int = 180) -> str:
    """Bound and minimize a human/model reason before it is persisted."""
    cleaned = _QUOTES.sub("", minimize_snippet(text, limit=limit * 2))
    return cleaned[:limit].strip()


def propose_action(
    *,
    record_type: str,
    capabilities: dict[str, bool],
    evidence_class: str,
    unreachable: bool = False,
    partial_match: bool = False,
    content_overlap: float = 1.0,
) -> tuple[str, bool, str]:
    """Return (action, approved_for_plan, collateral_risk).

    Only deterministic evidence classes become approved plan items. Candidate
    classes stay review/preserve regardless of model confidence.
    """
    if unreachable:
        return UNREACHABLE, False, "high"
    if evidence_class == RELATED_NONDISCLOSING:
        return SKIP_PRESERVE, False, "none"
    if evidence_class in {SUSPECTED_DERIVATIVE, UNKNOWN}:
        return REVIEW_REQUIRED, False, "high"
    if evidence_class not in {DIRECT_MATCH, CONFIRMED_DESCENDANT}:
        return REVIEW_REQUIRED, False, "high"

    # A substring match inside a larger, useful record is not a safe automatic
    # delete: hold it for review so the reviewer sees the collateral damage.
    if (
        partial_match
        and evidence_class == DIRECT_MATCH
        and content_overlap < PARTIAL_DELETE_MIN_RATIO
    ):
        return REVIEW_REQUIRED, False, "high"

    risk = "low" if evidence_class == DIRECT_MATCH else "medium"
    if record_type == "index_entry" and capabilities.get("invalidate"):
        return INVALIDATE_INDEX, True, risk
    if record_type == "cache_entry" and capabilities.get("invalidate"):
        return INVALIDATE_CACHE, True, risk
    if capabilities.get("delete"):
        return DELETE_RECORD, True, risk
    if capabilities.get("redact"):
        return REDACT_SPAN, True, risk
    return REVIEW_REQUIRED, False, "high"


def override_action(
    *, record_type: str, capabilities: dict[str, bool]
) -> str | None:
    """Action for a reviewer-approved review item, or None if unsupported."""
    if record_type == "index_entry" and capabilities.get("invalidate"):
        return INVALIDATE_INDEX
    if record_type == "cache_entry" and capabilities.get("invalidate"):
        return INVALIDATE_CACHE
    if capabilities.get("delete"):
        return DELETE_RECORD
    if capabilities.get("redact"):
        return REDACT_SPAN
    return None


def collateral_risk(action: str, base_risk: str, content_overlap: float) -> str:
    """Raise risk when an approved action would remove mostly unrelated content."""
    if action in ACTIONABLE and content_overlap < 0.34:
        return "high"
    return base_risk


def _clean(text: str, *, limit: int = 200) -> str:
    """Bound deterministic reason text without masking structural numbers."""
    return _QUOTES.sub("", re.sub(r"\s+", " ", text)).strip()[:limit]


def explain(
    *,
    evidence_class: str,
    record_type: str,
    action: str,
    match_detail: str | None = None,
    relation: str | None = None,
    evidence_type: str | None = None,
    depth: int | None = None,
    candidate_evidence: str | None = None,
    unknown_reason: str | None = None,
) -> str:
    if evidence_class == DIRECT_MATCH:
        detail = (match_detail or "exact identifier match").rstrip(".")
        return _clean(f"Deterministic match: {detail}.")
    if evidence_class == CONFIRMED_DESCENDANT:
        bits = [f"Confirmed {relation or 'lineage'} edge"]
        if evidence_type:
            bits.append(f"({evidence_type})")
        if depth is not None:
            bits.append(f"at depth {depth}")
        return _clean(" ".join(bits) + ".")
    if evidence_class == SUSPECTED_DERIVATIVE:
        return redacted_reason(
            "Candidate relationship only; not authoritative. "
            + (candidate_evidence or "Requires human review before any action.")
        )
    if evidence_class == RELATED_NONDISCLOSING:
        return redacted_reason(
            "Related but no disclosure evidence; preserved by policy. " + (candidate_evidence or "")
        )
    return redacted_reason(
        "Not assessable: " + (unknown_reason or "insufficient evidence; no action taken.")
    )


def severity(evidence_class: str) -> int:
    return {
        DIRECT_MATCH: 0,
        CONFIRMED_DESCENDANT: 1,
        SUSPECTED_DERIVATIVE: 2,
        UNKNOWN: 3,
        RELATED_NONDISCLOSING: 4,
    }.get(evidence_class, 5)


def summarize_candidate(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_id": item["record_id"],
        "store_id": item.get("store_id"),
        "record_type": item.get("record_type"),
        "node_type": item.get("node_type"),
        "capabilities": item.get("capabilities", {}),
        "evidence_class": item["evidence_class"],
        "proposed_action": item["proposed_action"],
        "reason_redacted": item["reason_redacted"],
        "risk": item["risk"],
        "approved": item["approved"],
        "depth": item.get("depth"),
        "unreachable": item.get("unreachable", False),
        "size_bytes": item.get("size_bytes", 0),
        "matched_bytes": item.get("matched_bytes", 0),
        "match_ratio": item.get("match_ratio", 1.0),
        "match_kind": item.get("match_kind"),
        "partial_match": item.get("partial_match", False),
        "collateral_note": item.get("collateral_note", ""),
        "expected_fingerprint": item.get("expected_fingerprint"),
        "fingerprint_key_version": item.get("fingerprint_key_version"),
    }
