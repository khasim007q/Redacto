"""Receipt rendering. Receipts contain counts and scope, never record content."""

from __future__ import annotations

import json
import hashlib
import hmac
from typing import Any


def _canonical(summary: dict[str, Any]) -> bytes:
    unsigned = {k: v for k, v in summary.items() if k != "integrity"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sign_receipt(summary: dict[str, Any], *, key: str, key_version: int) -> dict[str, Any]:
    signature = hmac.new(key.encode(), b"redacto-receipt-v1\0" + _canonical(summary), hashlib.sha256).hexdigest()
    return {**summary, "integrity": {"algorithm": "hmac-sha256-v1", "key_version": key_version, "signature": signature}}


def check_receipt(summary: dict[str, Any], *, keyring: dict[int, str]) -> dict[str, Any]:
    integrity = summary.get("integrity")
    if not isinstance(integrity, dict) or integrity.get("algorithm") != "hmac-sha256-v1":
        return {"valid": False, "reason": "unsigned_or_unsupported"}
    version = integrity.get("key_version")
    if type(version) is not int or version not in keyring:
        return {"valid": False, "reason": "key_unavailable"}
    signature = integrity.get("signature")
    if not isinstance(signature, str) or len(signature) != 64 or any(char not in "0123456789abcdef" for char in signature):
        return {"valid": False, "reason": "signature_mismatch", "key_version": version}
    try:
        expected = sign_receipt(summary, key=keyring[version], key_version=version)["integrity"]["signature"]
    except (TypeError, ValueError, OverflowError):
        return {"valid": False, "reason": "invalid_receipt"}
    valid = isinstance(signature, str) and hmac.compare_digest(signature.encode("utf-8"), expected.encode("utf-8"))
    return {"valid": valid, "reason": "ok" if valid else "signature_mismatch", "key_version": version}


def to_json(summary: dict[str, Any]) -> str:
    return json.dumps(summary, indent=2, sort_keys=True) + "\n"


def to_markdown(summary: dict[str, Any]) -> str:
    counts = summary.get("counts", {})
    lines = [
        "# Redacto verification receipt",
        "",
        f"- Receipt version: `{summary.get('receipt_version')}`",
        f"- Request: `{summary.get('request_id')}` (plan `{summary.get('plan_id')}` v{summary.get('plan_version')})",
        f"- Mode: `{summary.get('mode')}`",
        f"- Status: **{summary.get('status')}**",
        f"- Checked at: {summary.get('checked_at')}",
        f"- Integrity: {summary.get('integrity', {}).get('algorithm', 'unsigned')}",
        "",
        "## Counts",
        "",
    ]
    for key, value in counts.items():
        lines.append(f"- {key}: {value}")
    lines += ["", "## Stores", ""]
    for store in summary.get("stores", []):
        residual = store.get("residual_count", 0)
        lines.append(
            f"- `{store.get('store_id')}`: {store.get('outcome')} (residuals: {residual})"
        )
    semantic = summary.get("semantic_verification", {})
    if semantic:
        lines += ["", "## Semantic residual assessment", "",
                  f"- Status: {semantic.get('status')}",
                  f"- Surviving records checked: {semantic.get('records_checked', 0)}",
                  "- This assessment does not prove semantic absence."]
        for finding in semantic.get("findings", []):
            lines.append(f"- `{finding['record_id']}`: {finding['reason_code']} (review required)")
    lines += ["", "## Scope", ""]
    scope = summary.get("scope", {})
    lines.append(f"- Configured plan scope: {', '.join(scope.get('stores', [])) or 'none'}")
    lines.append(f"- Verified stores: {', '.join(scope.get('verified_stores', [])) or 'none'}")
    lines += ["", "## Limitations", ""]
    for limitation in summary.get("limitations", []):
        lines.append(f"- {limitation}")
    lines += ["", "## Statement", "", summary.get("statement", "")]
    return "\n".join(lines) + "\n"
