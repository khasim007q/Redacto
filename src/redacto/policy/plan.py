"""Plan item construction and version-bound plan hashing."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Sequence

from redacto.graph.repository import new_id
from redacto.policy import classify


def build_plan_items(candidates: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Turn scan candidates into plan items. Approved flags come only from policy."""
    items: list[dict[str, Any]] = []
    for candidate in sorted(
        candidates,
        key=lambda c: (classify.severity(c["evidence_class"]), c["record_id"]),
    ):
        action, approved, base_risk = classify.propose_action(
            record_type=candidate.get("record_type", "unknown"),
            capabilities=candidate.get("capabilities", {}),
            evidence_class=candidate["evidence_class"],
            unreachable=bool(candidate.get("unreachable")),
            partial_match=bool(candidate.get("partial_match")),
            content_overlap=float(candidate.get("match_ratio", 1.0)),
            redactable=bool(candidate.get("redact_spans")),
        )
        risk = classify.collateral_risk(
            action, base_risk, float(candidate.get("match_ratio", 1.0))
        )
        if action == classify.REDACT_SPAN:
            risk = "low"  # only the value goes; the rest of the record stays
        items.append(
            {
                "item_id": new_id("item"),
                "record_id": candidate["record_id"],
                "store_id": candidate.get("store_id"),
                "record_type": candidate.get("record_type", "unknown"),
                "node_type": candidate.get("node_type", "ARTIFACT"),
                "evidence_class": candidate["evidence_class"],
                "proposed_action": action,
                "reason_redacted": candidate["reason_redacted"],
                "risk": risk,
                "approved": approved,
                "expected_fingerprint": candidate.get("expected_fingerprint"),
                "fingerprint_key_version": candidate.get("fingerprint_key_version"),
                "depth": candidate.get("depth"),
                "unreachable": bool(candidate.get("unreachable")),
                "size_bytes": int(candidate.get("size_bytes", 0)),
                "matched_bytes": int(candidate.get("matched_bytes", 0)),
                "match_ratio": float(candidate.get("match_ratio", 1.0)),
                "match_kind": candidate.get("match_kind"),
                "partial_match": bool(candidate.get("partial_match")),
                "collateral_note": candidate.get("collateral_note", ""),
                # Keyed fingerprints + lengths of the value's exact forms, never the value.
                "redact_spans": (
                    list(candidate.get("redact_spans") or [])
                    if action == classify.REDACT_SPAN
                    else []
                ),
            }
        )
    return items


def compute_plan_hash(
    *,
    target_id: str,
    mode: str,
    scope: dict[str, Any],
    policy: dict[str, Any],
    version: int,
    items: Sequence[dict[str, Any]],
) -> str:
    canonical = {
        "target_id": target_id,
        "mode": mode,
        "scope": scope,
        "policy": policy,
        "version": version,
        "items": [
            {
                "item_id": item["item_id"],
                "record_id": item["record_id"],
                "evidence_class": item["evidence_class"],
                "proposed_action": item["proposed_action"],
                "approved": bool(item["approved"]),
                "expected_fingerprint": item.get("expected_fingerprint"),
                "fingerprint_key_version": item.get("fingerprint_key_version"),
                "redact_spans": item.get("redact_spans") or [],
            }
            for item in sorted(items, key=lambda i: i["item_id"])
        ],
    }
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def estimated_impact(items: Sequence[dict[str, Any]]) -> dict[str, int]:
    impact = {
        "delete": 0,
        "invalidate": 0,
        "review": 0,
        "preserve": 0,
        "unreachable": 0,
    }
    for item in items:
        action = item["proposed_action"]
        if action == classify.DELETE_RECORD:
            impact["delete"] += 1
        elif action in {classify.INVALIDATE_INDEX, classify.INVALIDATE_CACHE}:
            impact["invalidate"] += 1
        elif action == classify.REVIEW_REQUIRED:
            impact["review"] += 1
        elif action == classify.SKIP_PRESERVE:
            impact["preserve"] += 1
        elif action == classify.UNREACHABLE:
            impact["unreachable"] += 1
    return impact
