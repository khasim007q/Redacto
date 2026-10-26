"""Application-issued approval tokens.

The agent can request a plan but cannot approve it. Approval is issued by the
application (CLI/dashboard), bound to a plan ID + version, and stored only as a
hash with a short expiry and single use.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timezone

from redacto.graph.repository import Repository

MIN_APPROVAL_REF_LEN = 3
MAX_APPROVAL_REF_LEN = 500


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_approval(
    repo: Repository,
    *,
    plan_id: str,
    approval_ref: str,
    ttl_seconds: int = 600,
) -> dict[str, object]:
    plan = repo.get_plan(plan_id)
    if plan is None:
        raise ValueError("plan_not_found")
    # EXECUTING is recoverable: a crashed apply may be re-approved with a new
    # single-use token. Per-action idempotency prevents duplicate work.
    if plan["state"] not in {"READY_FOR_APPROVAL", "APPROVED", "EXECUTING"}:
        raise ValueError("plan_not_approvable")
    ref = approval_ref.strip()
    if not (MIN_APPROVAL_REF_LEN <= len(ref) <= MAX_APPROVAL_REF_LEN):
        raise ValueError("invalid_approval_ref")

    token = secrets.token_urlsafe(32)
    approval_id, expires_at = repo.create_approval(
        plan_id=plan_id,
        plan_version=int(plan["version"]),
        approval_ref=ref,
        token_hash=_hash(token),
        ttl_seconds=ttl_seconds,
    )
    repo.set_plan_state(
        plan_id,
        "APPROVED",
        approved_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        approved_by="application-issued-approval",
    )
    repo.set_request_state(plan["request_id"], "APPROVED")
    return {
        "approval_id": approval_id,
        "plan_id": plan_id,
        "plan_version": int(plan["version"]),
        "approval_ref": ref,
        "confirmation_token": token,
        "expires_at": expires_at,
        "single_use": True,
    }


def verify_approval(
    repo: Repository,
    *,
    plan_id: str,
    plan_version: int,
    approval_ref: str,
    confirmation_token: str,
) -> tuple[bool, str, dict | None]:
    approval = repo.find_approval(
        plan_id=plan_id, plan_version=plan_version, approval_ref=approval_ref.strip()
    )
    if approval is None:
        return False, "approval_not_found", None
    if approval["used_at"]:
        return False, "approval_already_used", approval
    try:
        expires = datetime.fromisoformat(approval["expires_at"])
    except ValueError:
        return False, "approval_expired", approval
    if expires <= datetime.now(timezone.utc):
        return False, "approval_expired", approval
    if not hmac.compare_digest(approval["token_hash"], _hash(confirmation_token)):
        return False, "invalid_confirmation_token", approval
    return True, "ok", approval
