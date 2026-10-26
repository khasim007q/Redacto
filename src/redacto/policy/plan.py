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
        action, approved, risk = classify.propose_action(
            record_type=candidate.get("record_type", "unknown"),
            capabilities=candidate.get("capabilities", {}),
            evidence_class=candidate["evidence_class"],
        )
        items.append(
            {
                "item_id": new_id("item"),
                "record_id": candidate["record_id"],
                "store_id": candidate.get("store_id"),
                "record_type": candidate.get("record_type", "unknown"),
                "evidence_class": candidate["evidence_class"],
                "proposed_action": action,
                "reason_redacted": candidate["reason_redacted"],
                "risk": risk,
                "approved": approved,
                "depth": candidate.get("depth"),
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
    return impact
