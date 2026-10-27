"""Persistence for graph, plans, approvals, actions, verification and receipts."""

from __future__ import annotations

import json
import os
import secrets
import socket
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

from redacto.graph.schema import SCHEMA

RECEIPT_VERSION = "1.0"


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def _json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def _loads(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


class Repository:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _connect(self):
        """Short-lived connection: `with sqlite3.connect()` does not close on exit."""
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            self._migrate(conn)
            conn.commit()

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """Add later columns to pre-existing databases without losing data."""
        existing = {row[1] for row in conn.execute("PRAGMA table_info(revocation_requests)")}
        additions = {
            "target_key_version": "INTEGER",
            "target_embedding_json": "TEXT NOT NULL DEFAULT '[]'",
            "target_embedding_model": "TEXT",
            "target_normalized_len": "INTEGER",
            "target_fingerprint": "TEXT",
            "target_shingles_json": "TEXT NOT NULL DEFAULT '[]'",
            "target_anchors_json": "TEXT NOT NULL DEFAULT '[]'",
            "target_tokens_json": "TEXT NOT NULL DEFAULT '[]'",
            "target_label_redacted": "TEXT",
        }
        for column, ddl in additions.items():
            if column not in existing:
                conn.execute(f"ALTER TABLE revocation_requests ADD COLUMN {column} {ddl}")

        quarantine_columns = {row[1] for row in conn.execute("PRAGMA table_info(quarantine)")}
        quarantine_additions = {
            "reviewed_by": "TEXT",
            "review_note": "TEXT",
            "admission_event_id": "TEXT",
            "admitted_at": "TEXT",
            "recheck_json": "TEXT NOT NULL DEFAULT '{}'",
        }
        for column, ddl in quarantine_additions.items():
            if column not in quarantine_columns:
                conn.execute(f"ALTER TABLE quarantine ADD COLUMN {column} {ddl}")

        item_columns = {row[1] for row in conn.execute("PRAGMA table_info(revocation_plan_items)")}
        for column, ddl in {
            "expected_fingerprint": "TEXT",
            "fingerprint_key_version": "INTEGER",
        }.items():
            if column not in item_columns:
                conn.execute(f"ALTER TABLE revocation_plan_items ADD COLUMN {column} {ddl}")

        plan_columns = {row[1] for row in conn.execute("PRAGMA table_info(revocation_plans)")}
        for column, ddl in {
            "execution_token": "TEXT",
            "execution_pid": "INTEGER",
            "execution_host": "TEXT",
            "execution_started_at": "TEXT",
        }.items():
            if column not in plan_columns:
                conn.execute(f"ALTER TABLE revocation_plans ADD COLUMN {column} {ddl}")

        record_columns = {row[1] for row in conn.execute("PRAGMA table_info(records)")}
        if "fingerprint_key_version" not in record_columns:
            conn.execute("ALTER TABLE records ADD COLUMN fingerprint_key_version INTEGER")

        tombstone_columns = {row[1] for row in conn.execute("PRAGMA table_info(tombstones)")}
        if "key_version" not in tombstone_columns:
            conn.execute("ALTER TABLE tombstones ADD COLUMN key_version INTEGER NOT NULL DEFAULT 1")
        if "embedding_json" not in tombstone_columns:
            conn.execute("ALTER TABLE tombstones ADD COLUMN embedding_json TEXT NOT NULL DEFAULT '[]'")
        if "embedding_model" not in tombstone_columns:
            conn.execute("ALTER TABLE tombstones ADD COLUMN embedding_model TEXT")

    # ---------------------------------------------------------------- records
    def upsert_record(
        self,
        *,
        record_id: str,
        record_type: str,
        store_id: str,
        locator: dict[str, str],
        fingerprint: str | None = None,
        fingerprint_key_version: int | None = None,
        created_at: str | None = None,
        sensitivity: Sequence[str] = (),
        capabilities: dict[str, bool] | None = None,
        status: str = "active",
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO records (record_id, record_type, store_id, locator_json, fingerprint,
                                     fingerprint_key_version, created_at, observed_at,
                                     sensitivity_json, capabilities_json, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(record_id) DO UPDATE SET
                    record_type=excluded.record_type,
                    store_id=excluded.store_id,
                    locator_json=excluded.locator_json,
                    fingerprint=excluded.fingerprint,
                    fingerprint_key_version=excluded.fingerprint_key_version,
                    observed_at=excluded.observed_at,
                    sensitivity_json=excluded.sensitivity_json,
                    capabilities_json=excluded.capabilities_json,
                    status=excluded.status
                """,
                (
                    record_id,
                    record_type,
                    store_id,
                    _json(locator),
                    fingerprint,
                    fingerprint_key_version,
                    created_at,
                    now_iso(),
                    _json(list(sensitivity)),
                    _json(capabilities or {}),
                    status,
                ),
            )
            conn.commit()

    def get_record(self, record_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM records WHERE record_id = ?", (record_id,)).fetchone()
        parsed = _row(row)
        if parsed:
            parsed["locator"] = _loads(parsed.pop("locator_json"), {})
            parsed["sensitivity"] = _loads(parsed.pop("sensitivity_json"), [])
            parsed["capabilities"] = _loads(parsed.pop("capabilities_json"), {})
        return parsed

    def list_records(self, limit: int = 1000) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT record_id, record_type, store_id, locator_json, sensitivity_json, "
                "fingerprint_key_version FROM records ORDER BY record_id LIMIT ?",
                (limit,),
            ).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["locator"] = _loads(item.pop("locator_json"), {})
            item["sensitivity"] = _loads(item.pop("sensitivity_json"), [])
            results.append(item)
        return results

    def mark_record_deleted(self, record_id: str) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE records SET status = 'deleted' WHERE record_id = ?", (record_id,))
            conn.commit()

    # ---------------------------------------------------------------- lineage
    def add_lineage_edge(
        self,
        *,
        source_id: str,
        target_id: str,
        relation: str,
        evidence_type: str,
        evidence_ref: str | None = None,
        status: str = "confirmed",
        verified_by: str | None = None,
    ) -> str:
        edge_id = new_id("edge")
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO lineage_edges
                   (edge_id, source_id, target_id, relation, evidence_type, evidence_ref,
                    status, created_at, verified_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    edge_id,
                    source_id,
                    target_id,
                    relation,
                    evidence_type,
                    evidence_ref,
                    status,
                    now_iso(),
                    verified_by,
                ),
            )
            conn.commit()
        return edge_id

    def lineage_edges(self, source_id: str, *, status: str = "confirmed") -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM lineage_edges WHERE source_id = ? AND status = ? ORDER BY created_at",
                (source_id, status),
            ).fetchall()
        return [dict(row) for row in rows]

    def all_lineage_edges(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM lineage_edges ORDER BY created_at").fetchall()
        return [dict(row) for row in rows]

    # ------------------------------------------------------------- candidates
    def add_candidate_edge(
        self,
        *,
        source_id: str,
        target_id: str,
        relation_guess: str,
        evidence_summary_redacted: str,
        model_id: str | None = None,
        confidence: float | None = None,
        status: str = "candidate",
    ) -> str:
        candidate_id = new_id("cand")
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO candidate_edges
                   (candidate_id, source_id, target_id, relation_guess, evidence_summary_redacted,
                    model_id, confidence, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    candidate_id,
                    source_id,
                    target_id,
                    relation_guess,
                    evidence_summary_redacted,
                    model_id,
                    confidence,
                    status,
                    now_iso(),
                ),
            )
            conn.commit()
        return candidate_id

    def candidate_edges(
        self, source_id: str, *, statuses: Sequence[str] = ("candidate",)
    ) -> list[dict[str, Any]]:
        placeholders = ",".join("?" for _ in statuses)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM candidate_edges WHERE source_id = ? AND status IN ({placeholders}) "
                "ORDER BY created_at",
                (source_id, *statuses),
            ).fetchall()
        return [dict(row) for row in rows]

    def candidate_for_target(self, source_id: str, target_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM candidate_edges WHERE source_id = ? AND target_id = ? "
                "ORDER BY created_at DESC LIMIT 1",
                (source_id, target_id),
            ).fetchone()
        return _row(row)

    # --------------------------------------------------------------- requests
    def create_request(
        self,
        *,
        target_id: str,
        target_kind: str,
        mode: str,
        scope: dict[str, Any],
        policy: dict[str, Any],
        state: str = "PLANNED",
        target_fingerprint: str | None = None,
        target_shingles: Sequence[str] = (),
        target_anchors: Sequence[str] = (),
        target_tokens: Sequence[str] = (),
        target_label_redacted: str | None = None,
        target_key_version: int | None = None,
        target_embedding: Sequence[float] = (),
        target_embedding_model: str | None = None,
        target_normalized_len: int | None = None,
    ) -> str:
        request_id = new_id("req")
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO revocation_requests
                   (request_id, target_id, target_kind, mode, scope_json, policy_json, state,
                    created_at, target_fingerprint, target_shingles_json, target_anchors_json,
                    target_tokens_json, target_label_redacted, target_key_version,
                    target_embedding_json, target_embedding_model, target_normalized_len)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    request_id,
                    target_id,
                    target_kind,
                    mode,
                    _json(scope),
                    _json(policy),
                    state,
                    now_iso(),
                    target_fingerprint,
                    _json(list(target_shingles)),
                    _json(list(target_anchors)),
                    _json(list(target_tokens)),
                    target_label_redacted,
                    target_key_version,
                    _json(list(target_embedding)),
                    target_embedding_model,
                    target_normalized_len,
                ),
            )
            conn.commit()
        return request_id

    def get_request(self, request_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM revocation_requests WHERE request_id = ?", (request_id,)
            ).fetchone()
        parsed = _row(row)
        if parsed:
            parsed["scope"] = _loads(parsed.pop("scope_json"), {})
            parsed["policy"] = _loads(parsed.pop("policy_json"), {})
            parsed["target_shingles"] = _loads(parsed.pop("target_shingles_json", None), [])
            parsed["target_anchors"] = _loads(parsed.pop("target_anchors_json", None), [])
            parsed["target_tokens"] = _loads(parsed.pop("target_tokens_json", None), [])
            parsed["target_embedding"] = _loads(parsed.pop("target_embedding_json", None), [])
        return parsed

    def set_request_state(self, request_id: str, state: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE revocation_requests SET state = ? WHERE request_id = ?",
                (state, request_id),
            )
            conn.commit()

    # ------------------------------------------------------------------ plans
    def next_plan_version(self, request_id: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(version), 0) AS v FROM revocation_plans WHERE request_id = ?",
                (request_id,),
            ).fetchone()
        return int(row["v"]) + 1

    def create_plan(
        self,
        *,
        request_id: str,
        version: int,
        scope: dict[str, Any],
        plan_hash: str,
        items: Sequence[dict[str, Any]],
    ) -> str:
        plan_id = new_id("plan")
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO revocation_plans
                   (plan_id, request_id, version, state, plan_hash, scope_json, created_at)
                   VALUES (?, ?, ?, 'READY_FOR_APPROVAL', ?, ?, ?)""",
                (plan_id, request_id, version, plan_hash, _json(scope), now_iso()),
            )
            for item in items:
                conn.execute(
                    """INSERT INTO revocation_plan_items
                       (item_id, plan_id, request_id, record_id, evidence_class, proposed_action,
                        reason_redacted, risk, approved, state, expected_fingerprint,
                        fingerprint_key_version)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'planned', ?, ?)""",
                    (
                        item["item_id"],
                        plan_id,
                        request_id,
                        item["record_id"],
                        item["evidence_class"],
                        item["proposed_action"],
                        item["reason_redacted"],
                        item["risk"],
                        1 if item["approved"] else 0,
                        item.get("expected_fingerprint"),
                        item.get("fingerprint_key_version"),
                    ),
                )
            conn.commit()
        return plan_id

    def get_plan(self, plan_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM revocation_plans WHERE plan_id = ?", (plan_id,)
            ).fetchone()
        parsed = _row(row)
        if parsed:
            parsed["scope"] = _loads(parsed.pop("scope_json"), {})
        return parsed

    def latest_plan_for_request(self, request_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM revocation_plans WHERE request_id = ? ORDER BY version DESC LIMIT 1",
                (request_id,),
            ).fetchone()
        parsed = _row(row)
        if parsed:
            parsed["scope"] = _loads(parsed.pop("scope_json"), {})
        return parsed

    def plan_items(self, plan_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM revocation_plan_items WHERE plan_id = ? ORDER BY item_id",
                (plan_id,),
            ).fetchall()
        items = [dict(row) for row in rows]
        for item in items:
            item["approved"] = bool(item["approved"])
        return items

    def get_plan_item(self, item_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM revocation_plan_items WHERE item_id = ?", (item_id,)
            ).fetchone()
        parsed = _row(row)
        if parsed:
            parsed["approved"] = bool(parsed["approved"])
        return parsed

    def claim_plan_execution(self, plan_id: str) -> str | None:
        """Atomically take the apply lease for a plan."""
        token = new_id("exec")
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE revocation_plans SET execution_token = ?, execution_pid = ?, "
                "execution_host = ?, execution_started_at = ? "
                "WHERE plan_id = ? AND execution_token IS NULL",
                (token, os.getpid(), socket.gethostname(), now_iso(), plan_id),
            )
            conn.commit()
            return token if cursor.rowcount == 1 else None

    def plan_execution_lease(self, plan_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT execution_token, execution_pid, execution_host, execution_started_at "
                "FROM revocation_plans WHERE plan_id = ?",
                (plan_id,),
            ).fetchone()
        if row is None or not row["execution_token"]:
            return None
        return dict(row)

    def release_plan_execution(self, plan_id: str, token: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE revocation_plans SET execution_token = NULL, execution_pid = NULL, "
                "execution_host = NULL, execution_started_at = NULL "
                "WHERE plan_id = ? AND execution_token = ?",
                (plan_id, token),
            )
            conn.commit()

    def clear_plan_execution(self, plan_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE revocation_plans SET execution_token = NULL, execution_pid = NULL, "
                "execution_host = NULL, execution_started_at = NULL WHERE plan_id = ?",
                (plan_id,),
            )
            conn.commit()

    def set_plan_state(
        self,
        plan_id: str,
        state: str,
        *,
        approved_at: str | None = None,
        approved_by: str | None = None,
        applied_at: str | None = None,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """UPDATE revocation_plans
                   SET state = ?,
                       approved_at = COALESCE(?, approved_at),
                       approved_by = COALESCE(?, approved_by),
                       applied_at = COALESCE(?, applied_at)
                   WHERE plan_id = ?""",
                (state, approved_at, approved_by, applied_at, plan_id),
            )
            conn.commit()

    def update_plan_version(
        self, plan_id: str, version: int, plan_hash: str, state: str
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE revocation_plans SET version = ?, plan_hash = ?, state = ? WHERE plan_id = ?",
                (version, plan_hash, state, plan_id),
            )
            conn.commit()

    def set_item_review(
        self, item_id: str, *, approved: bool, action: str, state: str
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE revocation_plan_items SET approved = ?, proposed_action = ?, state = ? "
                "WHERE item_id = ?",
                (1 if approved else 0, action, state, item_id),
            )
            conn.commit()

    def add_plan_item_review(
        self,
        *,
        plan_id: str,
        item_id: str,
        plan_version: int,
        decision: str,
        reviewer: str,
        note: str | None,
    ) -> str:
        review_id = new_id("irev")
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO plan_item_reviews
                   (review_id, plan_id, item_id, plan_version, decision, reviewer, note, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (review_id, plan_id, item_id, plan_version, decision, reviewer, note, now_iso()),
            )
            conn.commit()
        return review_id

    def plan_item_reviews(self, plan_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM plan_item_reviews WHERE plan_id = ? ORDER BY created_at",
                (plan_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def set_item_state(self, item_id: str, state: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE revocation_plan_items SET state = ? WHERE item_id = ?", (state, item_id)
            )
            conn.commit()

    # -------------------------------------------------------------- approvals
    def create_approval(
        self,
        *,
        plan_id: str,
        plan_version: int,
        approval_ref: str,
        token_hash: str,
        ttl_seconds: int = 600,
    ) -> tuple[str, str]:
        approval_id = new_id("appr")
        created = datetime.now(timezone.utc)
        expires = created + timedelta(seconds=ttl_seconds)
        created_iso = created.replace(microsecond=0).isoformat()
        expires_iso = expires.replace(microsecond=0).isoformat()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO approvals
                   (approval_id, plan_id, plan_version, approval_ref, token_hash, created_at, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    approval_id,
                    plan_id,
                    plan_version,
                    approval_ref,
                    token_hash,
                    created_iso,
                    expires_iso,
                ),
            )
            conn.commit()
        return approval_id, expires_iso

    def find_approval(
        self, *, plan_id: str, plan_version: int, approval_ref: str
    ) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                """SELECT * FROM approvals
                   WHERE plan_id = ? AND plan_version = ? AND approval_ref = ?
                   ORDER BY created_at DESC, rowid DESC LIMIT 1""",
                (plan_id, plan_version, approval_ref),
            ).fetchone()
        return _row(row)

    def mark_approval_used(self, approval_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE approvals SET used_at = ? WHERE approval_id = ?",
                (now_iso(), approval_id),
            )
            conn.commit()

    def claim_approval(self, approval_id: str) -> bool:
        """Atomically consume a single-use approval.

        Returns True only for the caller that won the claim. Concurrent applies
        presenting the same token cannot both proceed.
        """
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE approvals SET used_at = ? WHERE approval_id = ? AND used_at IS NULL",
                (now_iso(), approval_id),
            )
            conn.commit()
            return cursor.rowcount == 1

    # ---------------------------------------------------------------- actions
    def get_action_by_key(self, idempotency_key: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM actions WHERE idempotency_key = ?", (idempotency_key,)
            ).fetchone()
        return _row(row)

    def record_action(
        self,
        *,
        request_id: str,
        item_id: str | None,
        adapter_id: str | None,
        operation: str,
        result: str,
        error_code: str | None,
        started_at: str,
        finished_at: str,
        idempotency_key: str,
    ) -> str:
        action_id = new_id("act")
        with self._connect() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO actions
                   (action_id, request_id, item_id, adapter_id, operation, result, error_code,
                    started_at, finished_at, idempotency_key)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    action_id,
                    request_id,
                    item_id,
                    adapter_id,
                    operation,
                    result,
                    error_code,
                    started_at,
                    finished_at,
                    idempotency_key,
                ),
            )
            conn.commit()
        return action_id

    def delete_action_by_key(self, idempotency_key: str) -> None:
        """Remove a failed action so a recovery apply can retry it."""
        with self._connect() as conn:
            conn.execute("DELETE FROM actions WHERE idempotency_key = ?", (idempotency_key,))
            conn.commit()

    def actions_for_request(self, request_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM actions WHERE request_id = ? ORDER BY started_at", (request_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    # ----------------------------------------------------------- verification
    def add_verification(
        self,
        *,
        request_id: str,
        adapter_id: str,
        method: str,
        outcome: str,
        residual_count: int,
        limitations: Iterable[str],
        checked_at: str,
    ) -> str:
        verification_id = new_id("ver")
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO verification_runs
                   (verification_id, request_id, adapter_id, method, outcome, residual_count,
                    limitations_json, checked_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    verification_id,
                    request_id,
                    adapter_id,
                    method,
                    outcome,
                    residual_count,
                    _json(list(limitations)),
                    checked_at,
                ),
            )
            conn.commit()
        return verification_id

    def verifications_for_request(self, request_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM verification_runs WHERE request_id = ? ORDER BY checked_at",
                (request_id,),
            ).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["limitations"] = _loads(item.pop("limitations_json"), [])
            results.append(item)
        return results

    # --------------------------------------------------------------- receipts
    def save_receipt(self, *, request_id: str, summary: dict[str, Any]) -> str:
        receipt_id = new_id("rcpt")
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO receipts (receipt_id, request_id, summary_json, created_at, receipt_version)
                   VALUES (?, ?, ?, ?, ?)""",
                (receipt_id, request_id, _json(summary), now_iso(), RECEIPT_VERSION),
            )
            conn.commit()
        return receipt_id

    def get_receipt(self, receipt_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM receipts WHERE receipt_id = ?", (receipt_id,)
            ).fetchone()
        parsed = _row(row)
        if parsed:
            parsed["summary"] = _loads(parsed.pop("summary_json"), {})
        return parsed

    def receipt_for_request(self, request_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM receipts WHERE request_id = ? ORDER BY created_at DESC LIMIT 1",
                (request_id,),
            ).fetchone()
        parsed = _row(row)
        if parsed:
            parsed["summary"] = _loads(parsed.pop("summary_json"), {})
        return parsed

    # ------------------------------------------------------------- tombstones
    def add_tombstone(
        self,
        *,
        request_id: str,
        target_id: str,
        target_kind: str,
        label_redacted: str,
        fingerprint_value: str,
        shingles: Sequence[str],
        anchors: Sequence[str],
        tokens: Sequence[str],
        related_record_ids: Sequence[str],
        related_fingerprints: Sequence[Any],
        scope: dict[str, Any],
        policy: dict[str, Any],
        status: str = "pending",
        key_version: int = 1,
        embedding: Sequence[float] = (),
        embedding_model: str | None = None,
    ) -> str:
        tombstone_id = new_id("tomb")
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO tombstones
                   (tombstone_id, request_id, target_id, target_kind, label_redacted, fingerprint,
                    shingles_json, anchors_json, tokens_json, related_record_ids_json,
                    related_fingerprints_json, embedding_json, embedding_model,
                    scope_json, policy_json, status, key_version, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    tombstone_id,
                    request_id,
                    target_id,
                    target_kind,
                    label_redacted,
                    fingerprint_value,
                    _json(list(shingles)),
                    _json(list(anchors)),
                    _json(list(tokens)),
                    _json(list(related_record_ids)),
                    _json(list(related_fingerprints)),
                    _json(list(embedding)),
                    embedding_model,
                    _json(scope),
                    _json(policy),
                    status,
                    key_version,
                    now_iso(),
                ),
            )
            conn.commit()
        return tombstone_id

    @staticmethod
    def _tombstone_row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["shingles"] = _loads(item.pop("shingles_json"), [])
        item["anchors"] = _loads(item.pop("anchors_json"), [])
        item["tokens"] = _loads(item.pop("tokens_json"), [])
        item["related_record_ids"] = _loads(item.pop("related_record_ids_json"), [])
        item["related_fingerprints"] = _loads(item.pop("related_fingerprints_json"), [])
        item["embedding"] = _loads(item.pop("embedding_json", None), [])
        item["scope"] = _loads(item.pop("scope_json"), {})
        item["policy"] = _loads(item.pop("policy_json"), {})
        return item

    def list_tombstones(
        self, *, statuses: Sequence[str] = ("active",), limit: int = 200
    ) -> list[dict[str, Any]]:
        placeholders = ",".join("?" for _ in statuses)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM tombstones WHERE status IN ({placeholders}) "
                "ORDER BY created_at DESC LIMIT ?",
                (*statuses, limit),
            ).fetchall()
        return [self._tombstone_row(row) for row in rows]

    def get_tombstone(self, tombstone_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM tombstones WHERE tombstone_id = ?", (tombstone_id,)
            ).fetchone()
        return self._tombstone_row(row) if row is not None else None

    def tombstones_for_request(self, request_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM tombstones WHERE request_id = ? ORDER BY created_at",
                (request_id,),
            ).fetchall()
        return [self._tombstone_row(row) for row in rows]

    def set_tombstone_status(self, tombstone_id: str, status: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE tombstones SET status = ?, activated_at = COALESCE(activated_at, ?) "
                "WHERE tombstone_id = ?",
                (status, now_iso() if status == "active" else None, tombstone_id),
            )
            conn.commit()

    # --------------------------------------------------------- ingestion audit
    def record_ingestion_event(
        self,
        *,
        tombstone_id: str | None,
        store_id: str | None,
        record_id: str,
        locator: dict[str, Any],
        decision: str,
        reason_code: str,
        match_score: float,
        present_in_store: bool,
    ) -> str:
        new_event_id = new_id("evt")
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO ingestion_events
                   (event_id, tombstone_id, store_id, record_id, locator_json, decision,
                    reason_code, match_score, present_in_store, attempts, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                   ON CONFLICT(tombstone_id, record_id, decision) DO UPDATE SET
                       attempts = ingestion_events.attempts + 1,
                       reason_code = excluded.reason_code,
                       match_score = excluded.match_score,
                       present_in_store = excluded.present_in_store,
                       created_at = excluded.created_at""",
                (
                    new_event_id,
                    tombstone_id,
                    store_id,
                    record_id,
                    _json(locator),
                    decision,
                    reason_code,
                    match_score,
                    1 if present_in_store else 0,
                    now_iso(),
                ),
            )
            conn.commit()
            row = conn.execute(
                "SELECT event_id FROM ingestion_events WHERE tombstone_id IS ? "
                "AND record_id = ? AND decision = ?",
                (tombstone_id, record_id, decision),
            ).fetchone()
        return row["event_id"] if row else new_event_id

    def ingestion_events(self, *, limit: int = 200) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM ingestion_events ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["locator"] = _loads(item.pop("locator_json"), {})
            item["present_in_store"] = bool(item["present_in_store"])
            results.append(item)
        return results

    # -------------------------------------------------------------- quarantine
    def add_quarantine(
        self,
        *,
        tombstone_id: str | None,
        store_id: str | None,
        record_id: str,
        locator: dict[str, Any],
        reason_code: str,
        match_score: float,
    ) -> str:
        quarantine_id = new_id("quar")
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO quarantine
                   (quarantine_id, tombstone_id, store_id, record_id, locator_json, reason_code,
                    match_score, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'pending_review', ?)
                   ON CONFLICT(tombstone_id, record_id) DO NOTHING""",
                (
                    quarantine_id,
                    tombstone_id,
                    store_id,
                    record_id,
                    _json(locator),
                    reason_code,
                    match_score,
                    now_iso(),
                ),
            )
            conn.commit()
        return quarantine_id

    def list_quarantine(
        self, *, statuses: Sequence[str] = ("pending_review",), limit: int = 200
    ) -> list[dict[str, Any]]:
        placeholders = ",".join("?" for _ in statuses)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM quarantine WHERE status IN ({placeholders}) "
                "ORDER BY created_at DESC LIMIT ?",
                (*statuses, limit),
            ).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["locator"] = _loads(item.pop("locator_json"), {})
            item["recheck"] = _loads(item.pop("recheck_json", None), {})
            results.append(item)
        return results

    def get_quarantine(self, quarantine_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM quarantine WHERE quarantine_id = ?", (quarantine_id,)
            ).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["locator"] = _loads(item.pop("locator_json"), {})
        item["recheck"] = _loads(item.pop("recheck_json", None), {})
        return item

    def set_quarantine_status(
        self,
        quarantine_id: str,
        status: str,
        *,
        reviewed_by: str | None = None,
        note: str | None = None,
        admission_event_id: str | None = None,
        recheck: dict[str, Any] | None = None,
        admitted_at: str | None = None,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """UPDATE quarantine
                   SET status = ?,
                       reviewed_at = ?,
                       reviewed_by = COALESCE(?, reviewed_by),
                       review_note = COALESCE(?, review_note),
                       admission_event_id = COALESCE(?, admission_event_id),
                       admitted_at = COALESCE(?, admitted_at),
                       recheck_json = COALESCE(?, recheck_json)
                   WHERE quarantine_id = ?""",
                (
                    status,
                    now_iso(),
                    reviewed_by,
                    note,
                    admission_event_id,
                    admitted_at,
                    _json(recheck) if recheck is not None else None,
                    quarantine_id,
                ),
            )
            conn.commit()
