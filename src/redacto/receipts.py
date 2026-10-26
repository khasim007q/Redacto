"""Receipt rendering. Receipts contain counts and scope, never record content."""

from __future__ import annotations

import json
from typing import Any


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
    lines += ["", "## Scope", ""]
    scope = summary.get("scope", {})
    lines.append(f"- Configured plan scope: {', '.join(scope.get('stores', [])) or 'none'}")
    lines.append(f"- Verified stores: {', '.join(scope.get('verified_stores', [])) or 'none'}")
    lines += ["", "## Limitations", ""]
    for limitation in summary.get("limitations", []):
        lines.append(f"- {limitation}")
    lines += ["", "## Statement", "", summary.get("statement", "")]
    return "\n".join(lines) + "\n"