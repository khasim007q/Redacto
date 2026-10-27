"""Transport-independent Redacto engine.

All MCP tools, the CLI and the demo call this class, so scope checks, policy and
authorization cannot be bypassed by a different entry point.
"""

from __future__ import annotations

from typing import Any, Sequence

from redacto.adapters.base import AdapterError, Record
from redacto.adapters.registry import AdapterSlot, build_adapters
from redacto.config import Settings, load_settings
from redacto.discovery.embeddings import build_embedder, cosine
from redacto.discovery.exact import ExactMatcher, shares_entity
from redacto.discovery.normalization import fingerprint, normalize_loose
from redacto.discovery.relationship_assessor import (
    CandidateContext,
    RelationshipAssessor,
    build_assessor,
    minimize_snippet,
)
import os
import socket
from datetime import datetime, timezone

from redacto.errors import HmacKeyError, RedactoError
from redacto.graph.repository import RECEIPT_VERSION, Repository, new_id, now_iso
from redacto.graph.traversal import traverse
from redacto.ingestion import (
    anchor_items,
    tokens,
    token_set,
    ALLOWED,
    BLOCKED,
    QUARANTINED,
    contains_verbatim_passage,
    overlap_ratio,
    TombstoneGuard,
    TombstoneMaterial,
    summarize_guard_findings,
)
from redacto.policy import authorization, classify
from redacto.process import pid_alive
from redacto.policy.plan import build_plan_items, compute_plan_hash, estimated_impact
from redacto.status import collect_status

TARGET_KINDS = {"source", "fact", "secret"}
MODES = {"source_revocation", "fact_revocation"}
TERMINAL_PLAN_STATES = {
    # EXECUTING, FAILED and PARTIAL are deliberately recoverable: a crashed, failed
    # or partially failed apply can be re-approved and retried. VERIFYING means the
    # apply already completed and is waiting for verification.
    "VERIFYING",
    "VERIFIED_WITHIN_SCOPE",
    "NEEDS_REVIEW",
    "CANCELLED",
}
RELATION_TO_CLASS = {
    "possible_derivative": classify.SUSPECTED_DERIVATIVE,
    "related_but_not_disclosing": classify.RELATED_NONDISCLOSING,
    "uncertain": classify.UNKNOWN,
}

GLOBAL_VERIFICATION_LIMITATIONS = [
    "Verification covers only configured, reachable stores; unreachable stores are reported, not assumed clean.",
    "Detection uses planned record IDs plus a keyed fingerprint of the whole target content.",
    "Paraphrased remnants, backups, provider logs, replication queues and model weights are outside this scope.",
    "SQLite deletes overwrite rows and attempt a WAL truncate checkpoint; another open writer can delay physical removal.",
    "Files are unlinked rather than overwritten, and files with other extensions under a configured root are not scanned.",
]


# Shortest normalized value that can be verified by windowed hashing without
# producing false matches from ordinary words.
MIN_VERIFIABLE_VALUE_LEN = 8


def contains_normalized(
    content: str, target_fingerprint: str, normalized_len: int, key: str
) -> bool:
    """Whether the record contains the revoked value, separator-insensitively.

    The plaintext value is never stored, so verification slides a window of the
    value's normalized length over the record's normalized text and hashes each
    window. This catches `STRIPE_KEY=sk-...`, `key:sk-...`, `?token=sk-...` and a
    value glued to other text, which a whole-token comparison misses.
    """
    normalized = normalize_loose(content)
    if normalized_len <= 0 or len(normalized) < normalized_len:
        return False
    for start in range(len(normalized) - normalized_len + 1):
        if fingerprint(normalized[start : start + normalized_len], key) == target_fingerprint:
            return True
    return False


def _statement_for(
    status: str, review_pending: int, unreachable_stores: list[str], not_verifiable: list[str]
) -> str:
    if status == "VERIFIED_WITHIN_SCOPE":
        return "Verified within configured scope — not a claim of universal erasure."
    if status == "NEEDS_REVIEW":
        return (
            "Verified within configured scope for approved actions; "
            f"{review_pending} candidate(s) still need human review and were preserved. "
            "Not a claim of universal erasure."
        )
    details = []
    if unreachable_stores:
        details.append("unreachable stores: " + ", ".join(unreachable_stores))
    if not_verifiable:
        details.append("unverifiable stores: " + ", ".join(not_verifiable))
    reason = f" ({'; '.join(details)})" if details else ""
    return (
        f"Incomplete{reason}: removal is not verified across the configured scope. "
        "Not a claim of universal erasure."
    )


class Engine:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or load_settings()
        self._repo: Repository | None = None

    @property
    def repo(self) -> Repository:
        """Lazily open the graph database so read-only status calls do not create it."""
        if self._repo is None:
            self._repo = Repository(self.settings.db_path)
        return self._repo

    # ----------------------------------------------------------------- utils
    def adapters(self) -> dict[str, AdapterSlot]:
        return build_adapters(self.settings)

    def assessor(self) -> RelationshipAssessor:
        return build_assessor(
            provider=self.settings.model_provider,
            base_url=self.settings.model_base_url,
            model=self.settings.model_name,
            timeout=self.settings.model_timeout_seconds,
        )

    def status(self, *, transport: str = "stdio") -> dict[str, Any]:
        return collect_status(self.settings, transport=transport)

    def _require_record(self, record_id: str) -> dict[str, Any]:
        record = self.repo.get_record(record_id)
        if record is not None:
            return record
        # A brand-new workspace has no graph yet. Discover the target across the
        # configured stores so `scan`/`plan` work without a separate ingest step.
        discovered = self._discover_record(record_id)
        if discovered is not None:
            return discovered
        raise RedactoError(
            "unknown_record",
            "The target record is not in the configured provenance graph and was not "
            "found in any configured store. Check the store paths and the target id.",
            {"record_id": record_id, "known_example": "fs:acquisition-plan.md"},
        )

    def _discover_record(self, record_id: str) -> dict[str, Any] | None:
        for slot in self.adapters().values():
            if slot.adapter is None:
                continue
            try:
                records = list(slot.adapter.list_records(limit=self.settings.max_scan_records))
            except AdapterError:
                continue
            capabilities = self._record_capabilities(slot.adapter_id, slot)
            for candidate in records:
                if candidate.record_id == record_id:
                    self._upsert_scanned(candidate, capabilities)
                    return self.repo.get_record(record_id)
        return None

    def _scope_stores(self, stores: Sequence[str] | None) -> list[str]:
        configured = list(self.adapters().keys())
        if stores is None or len(stores) == 0:
            return configured
        unknown = [s for s in stores if s not in configured]
        if unknown:
            raise RedactoError(
                "out_of_scope_store",
                "Requested stores are not configured; scope cannot be broadened.",
                {"unknown_stores": unknown, "configured_stores": configured},
            )
        seen: list[str] = []
        for store in stores:
            if store not in seen:
                seen.append(store)
        return seen

    def _target_content(
        self, record: dict[str, Any], target_kind: str, target_text: str | None
    ) -> str:
        if target_kind in {"fact", "secret"}:
            if not target_text or len(target_text.strip()) < 8:
                raise RedactoError(
                    "invalid_target_value",
                    "Fact/secret targets require a value of at least 8 characters; it is never persisted.",
                )
            return target_text
        slots = self.adapters()
        slot = slots.get(record["store_id"])
        if slot is None or slot.adapter is None:
            raise RedactoError(
                "target_unreachable",
                "The target's store is not reachable; cannot read the target content.",
                {"store_id": record["store_id"]},
            )
        try:
            return slot.adapter.read_record(record["locator"]).content
        except AdapterError as exc:
            raise RedactoError(
                "target_unreachable",
                f"Cannot read the target record: {exc}",
                {"store_id": record["store_id"], "adapter_code": exc.code},
            ) from exc

    def _record_capabilities(self, adapter_id: str, slot: AdapterSlot) -> dict[str, bool]:
        if slot.adapter is None:
            return {"delete": False, "redact": False, "invalidate": False}
        caps = slot.adapter.capabilities()
        return {
            "delete": caps.can_delete,
            "redact": caps.can_redact,
            "invalidate": caps.can_invalidate,
        }

    def _upsert_scanned(self, record: Record, capabilities: dict[str, bool]) -> None:
        existing = self.repo.get_record(record.record_id)
        sensitivity = (
            existing["sensitivity"] if existing and existing["sensitivity"] else record.sensitivity
        )
        self.repo.upsert_record(
            record_id=record.record_id,
            record_type=record.record_type,
            store_id=record.store_id,
            locator=record.locator,
            fingerprint=fingerprint(record.content, self.settings.current_hmac_key),
            fingerprint_key_version=self.settings.hmac_key_version,
            created_at=record.metadata.get("created_at") or None,
            sensitivity=sensitivity or ["unknown"],
            capabilities=capabilities,
            status="active",
        )

    def embedder(self):
        return build_embedder(self.settings.embedding_provider)

    def guard(self) -> TombstoneGuard:
        """Active tombstones, rebuilt from stored keyed material only.

        Fails closed when the current key version is missing or the key ring is
        invalid: no ingestion should proceed while protection cannot be evaluated.
        """
        try:
            self.settings.current_hmac_key
        except HmacKeyError as exc:
            raise RedactoError(exc.code, exc.message, {"keyring_error": exc.message}) from exc
        return TombstoneGuard.from_repo(
            self.repo,
            keyring=self.settings.hmac_keys,
            current_version=self.settings.hmac_key_version,
            embedder=self.embedder(),
            embedding_threshold=self.settings.embedding_quarantine_threshold,
        )

    def _record_guard_decision(
        self, decision, record: Record, *, present_in_store: bool
    ) -> None:
        self.repo.record_ingestion_event(
            tombstone_id=decision.tombstone_id,
            store_id=record.store_id,
            record_id=record.record_id,
            locator=record.locator,
            decision=decision.decision,
            reason_code=decision.reason_code,
            match_score=decision.match_score,
            present_in_store=present_in_store,
        )
        if decision.quarantined:
            self.repo.add_quarantine(
                tombstone_id=decision.tombstone_id,
                store_id=record.store_id,
                record_id=record.record_id,
                locator=record.locator,
                reason_code=decision.reason_code,
                match_score=decision.match_score,
            )

    def _record_is_oversized(self, record: Record) -> bool:
        return len(record.content.encode("utf-8")) > self.settings.max_record_bytes

    def _skip_finding(self, record: Record, *, present_in_store: bool) -> dict[str, Any]:
        return {
            "record_id": record.record_id,
            "store_id": record.store_id,
            "record_type": record.record_type,
            "decision": "skipped",
            "reason_code": "oversized_record",
            "match_score": 0.0,
            "tombstone_id": None,
            "target_id": None,
            "target_kind": None,
            "label_redacted": None,
            "degraded": False,
            "present_in_store": present_in_store,
            "admitted": False,
            "size_bytes": len(record.content.encode("utf-8")),
            "limit_bytes": self.settings.max_record_bytes,
        }

    @staticmethod
    def _guard_finding(decision, record: Record, *, present_in_store: bool) -> dict[str, Any]:
        return {
            "record_id": record.record_id,
            "store_id": record.store_id,
            "record_type": record.record_type,
            **decision.as_dict(),
            "present_in_store": present_in_store,
            "admitted": False,
        }

    NODE_TYPES = {
        "doc": "ARTIFACT",
        "memory": "MEMORY",
        "log": "LOG_RECORD",
        "index_entry": "INDEX_ENTRY",
        "cache_entry": "CACHE_ENTRY",
        "store": "STORE",
        "agent_run": "AGENT_RUN",
    }

    @classmethod
    def _node_type(cls, record_type: str) -> str:
        return cls.NODE_TYPES.get(record_type, "ARTIFACT")

    def _candidate(
        self,
        *,
        record_id: str,
        store_id: str | None,
        record_type: str,
        capabilities: dict[str, bool],
        evidence_class: str,
        reason_redacted: str,
        depth: int | None = None,
        relation: str | None = None,
        evidence_type: str | None = None,
        confirmed: bool = False,
        unreachable: bool = False,
        content_overlap: float = 1.0,
        size_bytes: int = 0,
        matched_bytes: int = 0,
        match_kind: str | None = None,
        partial_match: bool = False,
        expected_fingerprint: str | None = None,
        fingerprint_key_version: int | None = None,
    ) -> dict[str, Any]:
        action, approved, risk = classify.propose_action(
            record_type=record_type,
            capabilities=capabilities,
            evidence_class=evidence_class,
            unreachable=unreachable,
            partial_match=partial_match,
            content_overlap=content_overlap,
        )
        risk = classify.collateral_risk(action, risk, content_overlap)
        return {
            "record_id": record_id,
            "store_id": store_id,
            "record_type": record_type,
            "node_type": self._node_type(record_type),
            "capabilities": capabilities,
            "evidence_class": evidence_class,
            "proposed_action": action,
            "reason_redacted": reason_redacted,
            "risk": risk,
            "approved": approved,
            "depth": depth,
            "relation": relation,
            "evidence_type": evidence_type,
            "confirmed": confirmed or evidence_class in {classify.DIRECT_MATCH, classify.CONFIRMED_DESCENDANT},
            "candidate_only": evidence_class
            in {classify.SUSPECTED_DERIVATIVE, classify.RELATED_NONDISCLOSING, classify.UNKNOWN},
            "unreachable": unreachable,
            "size_bytes": size_bytes,
            "matched_bytes": matched_bytes,
            "match_ratio": round(content_overlap, 4),
            "match_kind": match_kind,
            "partial_match": partial_match,
            "collateral_note": (
                f"Removes {size_bytes} bytes; about {content_overlap:.0%} of the record "
                "matches the target."
                if size_bytes
                else ""
            ),
            "expected_fingerprint": expected_fingerprint,
            "fingerprint_key_version": fingerprint_key_version,
        }

    # ------------------------------------------------------------------ scan
    def scan(
        self,
        *,
        target_id: str,
        target_kind: str = "source",
        stores: Sequence[str] | None = None,
        depth: int = 3,
        use_model: bool = True,
        target_text: str | None = None,
        _collect_records: dict[str, Record] | None = None,
    ) -> dict[str, Any]:
        if target_kind not in TARGET_KINDS:
            raise RedactoError("invalid_target_kind", f"target_kind must be one of {sorted(TARGET_KINDS)}")
        if not 1 <= depth <= 5:
            raise RedactoError("invalid_depth", "depth must be between 1 and 5")
        # Fail with the key-ring reason before any adapter reports target_unreachable.
        guard = self.guard()
        scope_stores = self._scope_stores(stores)
        record = self._require_record(target_id)
        target_content = self._target_content(record, target_kind, target_text)
        embedder = self.embedder()
        target_embedding = (
            embedder.embed(target_content) if embedder.model_id != "none" else []
        )

        traversal = traverse(self.repo, target_id, max_depth=depth)
        matcher = ExactMatcher(
            target_text=target_content,
            target_record_id=target_id,
            target_locator=record["locator"],
            target_kind=target_kind,
            # A fact/secret anchor is only a lookup handle: it must not match by
            # identity or it would be deleted without containing the value.
            include_target_identity=target_kind == "source",
        )

        slots = self.adapters()
        guard_findings: list[dict[str, Any]] = []
        guarded_ids: set[str] = set()
        scanned: dict[str, Record] = {}
        coverage: list[dict[str, Any]] = []
        unreachable: list[dict[str, Any]] = []
        truncated_stores: list[str] = []

        for store in scope_stores:
            slot = slots[store]
            if slot.adapter is None:
                entry = {
                    "store_id": store,
                    "status": "unreachable",
                    "records_scanned": 0,
                    "limitations": [slot.unavailable_reason or "adapter unavailable"],
                }
                coverage.append(entry)
                unreachable.append(entry)
                continue
            limit = self.settings.max_scan_records
            try:
                records = list(slot.adapter.list_records(limit=limit + 1))
            except AdapterError as exc:
                entry = {
                    "store_id": store,
                    "status": "error",
                    "records_scanned": 0,
                    "limitations": [f"{exc.code}: {exc}"],
                }
                coverage.append(entry)
                unreachable.append(entry)
                continue
            truncated = len(records) > limit
            if truncated:
                records = records[:limit]
                truncated_stores.append(store)
            for scanned_record in records:
                scanned[scanned_record.record_id] = scanned_record
            coverage.append(
                {
                    "store_id": store,
                    "status": "scanned",
                    "records_scanned": len(records),
                    "truncated": truncated,
                    "limit": limit,
                    "limitations": (
                        [
                            f"Record cap reached ({limit}); some records in this store were "
                            "not scanned and are not proven clean."
                        ]
                        if truncated
                        else []
                    ),
                }
            )
            caps = self._record_capabilities(store, slot)
            for scanned_record in records:
                if self._record_is_oversized(scanned_record):
                    guard_findings.append(
                        self._skip_finding(scanned_record, present_in_store=True)
                    )
                    guarded_ids.add(scanned_record.record_id)
                    continue
                # The guard protects the admission boundary. Records already active in
                # the graph (for example a record admitted after review) stay visible so
                # a later revocation can target them. Restored or never-admitted records
                # are still guarded, including a restored revocation target.
                existing = self.repo.get_record(scanned_record.record_id)
                already_active = existing is not None and existing["status"] == "active"
                decision = (
                    None
                    if already_active
                    else guard.evaluate(
                        record_id=scanned_record.record_id, content=scanned_record.content
                    )
                )
                if decision is not None and decision.decision != ALLOWED:
                    self._record_guard_decision(decision, scanned_record, present_in_store=True)
                    guard_findings.append(
                        self._guard_finding(decision, scanned_record, present_in_store=True)
                    )
                    guarded_ids.add(scanned_record.record_id)
                    continue
                self._upsert_scanned(scanned_record, caps)

        if _collect_records is not None:
            _collect_records.update(scanned)

        # Fact/secret revocation targets a value, not a document's descendants: the
        # anchor record is only a lookup handle. Only records containing the value
        # may be treated as direct matches.
        fact_mode = target_kind in {"fact", "secret"}
        descendant_by_id = (
            {} if fact_mode else {node.record_id: node for node in traversal.descendants}
        )
        candidate_edges = {edge["target_id"]: edge for edge in traversal.candidates}
        candidates: dict[str, dict[str, Any]] = {}
        unrelated_preserved = 0
        embedding_candidates = 0

        for record_id, scanned_record in scanned.items():
            if record_id in guarded_ids:
                # A revoked trace reappearing in a store is reported by the guard,
                # not re-admitted as a fresh candidate.
                continue
            capabilities = self._record_capabilities(scanned_record.store_id, slots[scanned_record.store_id])
            core = scanned_record.core_content
            sizing_text = core or scanned_record.content
            size = len(sizing_text.encode("utf-8"))
            ratio = overlap_ratio(target_content, sizing_text)
            common = {
                "content_overlap": ratio,
                "size_bytes": size,
                "matched_bytes": int(ratio * size),
                "expected_fingerprint": fingerprint(
                    scanned_record.content, self.settings.current_hmac_key
                ),
                "fingerprint_key_version": self.settings.hmac_key_version,
            }
            match = matcher.match(scanned_record)
            if match is not None:
                size = len(sizing_text.encode("utf-8"))
                if match.kind in {"record_id", "locator", "normalized_content"}:
                    matched, ratio = size, 1.0
                elif core is not None:
                    # Structured record: size against the payload that a delete would
                    # destroy. A value found outside the payload (a nested argument,
                    # a metadata field, a key) adds only itself to that payload.
                    matched = match.matched_chars
                    size = len(core.encode("utf-8"))
                    if not matcher.value_in(core):
                        size += matched
                    matched = min(matched, size)
                    ratio = (matched / size) if size else 0.0
                else:
                    matched = min(match.matched_chars or size, size)
                    ratio = (matched / size) if size else 0.0
                candidates[record_id] = self._candidate(
                    record_id=record_id,
                    store_id=scanned_record.store_id,
                    record_type=scanned_record.record_type,
                    capabilities=capabilities,
                    evidence_class=classify.DIRECT_MATCH,
                    reason_redacted=classify.explain(
                        evidence_class=classify.DIRECT_MATCH,
                        record_type=scanned_record.record_type,
                        action=classify.DELETE_RECORD,
                        match_detail=match.detail,
                    ),
                    content_overlap=ratio,
                    size_bytes=size,
                    matched_bytes=matched,
                    match_kind=match.kind,
                    partial_match=match.is_partial,
                    expected_fingerprint=common["expected_fingerprint"],
                    fingerprint_key_version=common["fingerprint_key_version"],
                )
                continue
            if record_id in descendant_by_id:
                node = descendant_by_id[record_id]
                last_edge = node.via[-1] if node.via else {}
                size = len(sizing_text.encode("utf-8"))
                ratio = overlap_ratio(target_content, sizing_text)
                candidates[record_id] = self._candidate(
                    record_id=record_id,
                    store_id=scanned_record.store_id,
                    record_type=scanned_record.record_type,
                    capabilities=capabilities,
                    evidence_class=classify.CONFIRMED_DESCENDANT,
                    reason_redacted=classify.explain(
                        evidence_class=classify.CONFIRMED_DESCENDANT,
                        record_type=scanned_record.record_type,
                        action=classify.DELETE_RECORD,
                        relation=last_edge.get("relation"),
                        evidence_type=last_edge.get("evidence_type"),
                        depth=node.depth,
                    ),
                    depth=node.depth,
                    relation=last_edge.get("relation"),
                    evidence_type=last_edge.get("evidence_type"),
                    content_overlap=ratio,
                    size_bytes=size,
                    matched_bytes=int(ratio * size),
                    match_kind="lineage",
                    expected_fingerprint=common["expected_fingerprint"],
                    fingerprint_key_version=common["fingerprint_key_version"],
                )
                continue

            edge = candidate_edges.get(record_id)
            if edge is not None:
                evidence_class = RELATION_TO_CLASS.get(edge["relation_guess"], classify.UNKNOWN)
                if edge["relation_guess"] == "unrelated":
                    unrelated_preserved += 1
                    continue
                candidates[record_id] = self._candidate(
                    record_id=record_id,
                    store_id=scanned_record.store_id,
                    record_type=scanned_record.record_type,
                    capabilities=capabilities,
                    evidence_class=evidence_class,
                    reason_redacted=classify.explain(
                        evidence_class=evidence_class,
                        record_type=scanned_record.record_type,
                        action=classify.REVIEW_REQUIRED,
                        candidate_evidence=edge["evidence_summary_redacted"],
                    ),
                    relation=edge["relation_guess"],
                    match_kind="candidate_edge",
                    **common,
                )
                continue

            if not fact_mode and contains_verbatim_passage(
                target_content, scanned_record.content
            ):
                evidence = (
                    "A verbatim passage from the target appears inside a larger record; "
                    "review the whole-record deletion."
                )
                candidates[record_id] = self._candidate(
                    record_id=record_id,
                    store_id=scanned_record.store_id,
                    record_type=scanned_record.record_type,
                    capabilities=capabilities,
                    evidence_class=classify.SUSPECTED_DERIVATIVE,
                    reason_redacted=classify.explain(
                        evidence_class=classify.SUSPECTED_DERIVATIVE,
                        record_type=scanned_record.record_type,
                        action=classify.REVIEW_REQUIRED,
                        candidate_evidence=evidence,
                    ),
                    match_kind="verbatim_passage",
                    **common,
                )
                if record_id not in candidate_edges:
                    self.repo.add_candidate_edge(
                        source_id=target_id,
                        target_id=record_id,
                        relation_guess="possible_derivative",
                        evidence_summary_redacted=evidence,
                        model_id="heuristic_passage",
                    )
                    candidate_edges[record_id] = {
                        "target_id": record_id,
                        "relation_guess": "possible_derivative",
                    }
                continue

            if not fact_mode:
                target_anchor_weights = dict(anchor_items(target_content))
                overlap_score = sum(
                    weight
                    for value, weight in anchor_items(scanned_record.content)
                    if value in target_anchor_weights
                )
                if overlap_score >= 4:
                    evidence = (
                        "Shares distinctive amounts/dates with the target; review before "
                        "deciding. Reworded disclosure is not proven clean."
                    )
                    candidates[record_id] = self._candidate(
                        record_id=record_id,
                        store_id=scanned_record.store_id,
                        record_type=scanned_record.record_type,
                        capabilities=capabilities,
                        evidence_class=classify.SUSPECTED_DERIVATIVE,
                        reason_redacted=classify.explain(
                            evidence_class=classify.SUSPECTED_DERIVATIVE,
                            record_type=scanned_record.record_type,
                            action=classify.REVIEW_REQUIRED,
                            candidate_evidence=evidence,
                        ),
                        match_kind="anchor_disclosure",
                        **common,
                    )
                    if record_id not in candidate_edges:
                        self.repo.add_candidate_edge(
                            source_id=target_id,
                            target_id=record_id,
                            relation_guess="possible_derivative",
                            evidence_summary_redacted=evidence,
                            model_id="heuristic_anchors",
                            confidence=min(0.95, overlap_score / 10),
                        )
                        candidate_edges[record_id] = {
                            "target_id": record_id,
                            "relation_guess": "possible_derivative",
                        }
                    continue

            if shares_entity(target_content, scanned_record.content):
                evidence = "Shares a named entity with the target but shows no disclosure evidence."
                candidates[record_id] = self._candidate(
                    record_id=record_id,
                    store_id=scanned_record.store_id,
                    record_type=scanned_record.record_type,
                    capabilities=capabilities,
                    evidence_class=classify.RELATED_NONDISCLOSING,
                    reason_redacted=classify.explain(
                        evidence_class=classify.RELATED_NONDISCLOSING,
                        record_type=scanned_record.record_type,
                        action=classify.SKIP_PRESERVE,
                        candidate_evidence=evidence,
                    ),
                    match_kind="shared_entity",
                    **common,
                )
                new_edge_id = self.repo.add_candidate_edge(
                    source_id=target_id,
                    target_id=record_id,
                    relation_guess="related_but_not_disclosing",
                    evidence_summary_redacted=evidence,
                    model_id="heuristic_match",
                )
                candidate_edges[record_id] = {
                    "candidate_id": new_edge_id,
                    "target_id": record_id,
                    "relation_guess": "related_but_not_disclosing",
                    "evidence_summary_redacted": evidence,
                }
                continue

            if target_embedding:
                similarity = cosine(target_embedding, embedder.embed(scanned_record.content))
                if similarity >= self.settings.embedding_candidate_threshold:
                    evidence = (
                        f"Embedding similarity {similarity:.2f}; candidate only, not lineage."
                    )
                    candidates[record_id] = self._candidate(
                        record_id=record_id,
                        store_id=scanned_record.store_id,
                        record_type=scanned_record.record_type,
                        capabilities=capabilities,
                        evidence_class=classify.SUSPECTED_DERIVATIVE,
                        reason_redacted=classify.explain(
                            evidence_class=classify.SUSPECTED_DERIVATIVE,
                            record_type=scanned_record.record_type,
                            action=classify.REVIEW_REQUIRED,
                            candidate_evidence=evidence,
                        ),
                        relation="possible_derivative",
                        match_kind="embedding",
                        **common,
                    )
                    embedding_candidates += 1
                    if record_id not in candidate_edges:
                        self.repo.add_candidate_edge(
                            source_id=target_id,
                            target_id=record_id,
                            relation_guess="possible_derivative",
                            evidence_summary_redacted=evidence,
                            model_id=embedder.model_id,
                            confidence=similarity,
                        )
                        candidate_edges[record_id] = {
                            "target_id": record_id,
                            "relation_guess": "possible_derivative",
                        }
                    continue

            unrelated_preserved += 1

        for node in traversal.descendants if not fact_mode else []:
            if node.record_id in candidates or node.record_id in scanned:
                continue
            graph_record = self.repo.get_record(node.record_id) or {}
            candidates[node.record_id] = self._candidate(
                record_id=node.record_id,
                store_id=graph_record.get("store_id"),
                record_type=graph_record.get("record_type", "unknown"),
                capabilities=graph_record.get("capabilities", {}),
                evidence_class=classify.UNKNOWN,
                reason_redacted=classify.explain(
                    evidence_class=classify.UNKNOWN,
                    record_type=graph_record.get("record_type", "unknown"),
                    action=classify.REVIEW_REQUIRED,
                    unknown_reason="confirmed descendant was not reachable during scan",
                ),
                depth=node.depth,
                unreachable=True,
            )

        for edge in traversal.candidates:
            record_id = edge["target_id"]
            if record_id in candidates or record_id in scanned:
                continue
            graph_record = self.repo.get_record(record_id) or {}
            candidates[record_id] = self._candidate(
                record_id=record_id,
                store_id=graph_record.get("store_id"),
                record_type=graph_record.get("record_type", "unknown"),
                capabilities=graph_record.get("capabilities", {}),
                evidence_class=classify.UNKNOWN,
                reason_redacted=classify.explain(
                    evidence_class=classify.UNKNOWN,
                    record_type=graph_record.get("record_type", "unknown"),
                    action=classify.REVIEW_REQUIRED,
                    unknown_reason="candidate record was not reachable during scan",
                ),
                relation=edge["relation_guess"],
                unreachable=True,
            )

        model_meta = self._assess_candidates(
            target_id=target_id,
            target_kind=target_kind,
            candidates=candidates,
            scanned=scanned,
            candidate_edges=candidate_edges,
            enabled=use_model,
        )

        ordered = sorted(
            candidates.values(),
            key=lambda c: (classify.severity(c["evidence_class"]), c["record_id"]),
        )
        counts = {
            "direct_match": sum(1 for c in ordered if c["evidence_class"] == classify.DIRECT_MATCH),
            "confirmed_descendant": sum(
                1 for c in ordered if c["evidence_class"] == classify.CONFIRMED_DESCENDANT
            ),
            "suspected_derivative": sum(
                1 for c in ordered if c["evidence_class"] == classify.SUSPECTED_DERIVATIVE
            ),
            "related_nondisclosing": sum(
                1 for c in ordered if c["evidence_class"] == classify.RELATED_NONDISCLOSING
            ),
            "unknown": sum(1 for c in ordered if c["evidence_class"] == classify.UNKNOWN),
            "unrelated_preserved": unrelated_preserved,
        }
        counts["unresolved"] = counts["suspected_derivative"] + counts["unknown"]

        return {
            "scan_id": new_id("scan"),
            "target": {
                "record_id": record["record_id"],
                "record_type": record["record_type"],
                "node_type": "SOURCE" if target_kind == "source" else "FACT",
                "store_id": record["store_id"],
                "kind": target_kind,
                "label": record["locator"].get("path") or record["locator"].get("id") or record["record_id"],
            },
            "scope": {"stores": scope_stores, "max_depth": depth},
            "candidates": [classify.summarize_candidate(c) | {"confirmed": c["confirmed"], "candidate_only": c["candidate_only"], "relation": c.get("relation")} for c in ordered],
            "counts": counts | {
                "unreachable": sum(
                    1 for c in ordered if c["proposed_action"] == classify.UNREACHABLE
                )
            },
            "coverage": coverage,
            "unreachable_stores": [entry["store_id"] for entry in unreachable],
            "model": model_meta,
            "embeddings": {
                "provider": embedder.model_id,
                "candidate_threshold": self.settings.embedding_candidate_threshold,
                "quarantine_threshold": self.settings.embedding_quarantine_threshold,
                "candidates_generated": embedding_candidates,
                "note": "Embedding similarity generates review candidates only; it never proves lineage.",
            },
            "guard": {
                "active_tombstones": guard.active_count,
                "counts": summarize_guard_findings(guard_findings),
                "findings": guard_findings,
            },
            "limitations": [
                "Scan is read-only with respect to record content; only minimized graph metadata is written.",
                "Only configured file types are scanned; other files under the root are reported in status.",
                "Semantic candidates stay advisory; unassessed candidates are never destructive.",
                "Records matching an active tombstone are blocked or quarantined and never re-admitted to the graph.",
                "Records larger than REDACTO_MAX_RECORD_BYTES are skipped before matching and reported.",
                "Stores that reach REDACTO_MAX_SCAN_RECORDS are marked truncated; unscanned records are not proven clean.",
            ],
            "truncated_stores": truncated_stores,
        }

    def _assess_candidates(
        self,
        *,
        target_id: str,
        target_kind: str,
        candidates: dict[str, dict[str, Any]],
        scanned: dict[str, Record],
        candidate_edges: dict[str, dict[str, Any]],
        enabled: bool,
    ) -> dict[str, Any]:
        try:
            assessor = self.assessor()
            model_id = assessor.model_id
        except Exception as exc:  # a custom assessor must never break scan
            assessor = None
            model_id = "error"
            assessor_error = f"assessor_unavailable:{type(exc).__name__}"
        else:
            assessor_error = None
        provider_configured = model_id != "none"
        meta: dict[str, Any] = {
            "provider": self.settings.model_provider,
            "model_id": model_id,
            "used": False,
            "assessed": 0,
            "unassessed": 0,
            "errors": {},
        }
        if assessor_error is not None:
            meta["provider_error"] = assessor_error
            meta["detail"] = "Assessor could not be constructed; all candidates are unassessed."
            meta["unassessed"] = sum(
                1
                for c in candidates.values()
                if c["evidence_class"] in {classify.SUSPECTED_DERIVATIVE, classify.UNKNOWN}
            )
            return meta
        if not enabled or not provider_configured or target_kind == "secret":
            if target_kind == "secret":
                meta["detail"] = (
                    "Model assessment skipped for secret targets so credential-like "
                    "content is never sent to a provider."
                )
            else:
                meta["detail"] = (
                    "Model assessment disabled; deterministic discovery only."
                    if not provider_configured
                    else "Model assessment skipped by request."
                )
            meta["unassessed"] = sum(
                1
                for c in candidates.values()
                if c["evidence_class"] in {classify.SUSPECTED_DERIVATIVE, classify.UNKNOWN}
            )
            return meta

        eligible = [
            c
            for c in candidates.values()
            if c["evidence_class"]
            in {classify.SUSPECTED_DERIVATIVE, classify.RELATED_NONDISCLOSING, classify.UNKNOWN}
            and c["record_id"] in scanned
        ]
        if not eligible:
            meta["detail"] = "No candidates required assessment."
            return meta

        contexts = [
            CandidateContext(
                candidate_id=candidate["record_id"],
                snippet_redacted=minimize_snippet(scanned[candidate["record_id"]].content),
                record_type=candidate["record_type"],
            )
            for candidate in eligible
        ]
        try:
            outcome = assessor.assess(contexts)
        except Exception as exc:  # custom/broken assessor: unassessed, never destructive
            meta["provider_error"] = f"assessor_exception:{type(exc).__name__}"
            meta["unassessed"] = len(eligible)
            meta["errors"] = {c.candidate_id: "unassessed_provider_error" for c in contexts}
            return meta
        meta["used"] = True
        meta["provider_error"] = outcome.provider_error
        meta["assessed"] = len(outcome.assessments)

        for candidate in eligible:
            record_id = candidate["record_id"]
            assessment = outcome.assessments.get(record_id)
            if assessment is None:
                meta["errors"][record_id] = outcome.errors.get(record_id, "unassessed")
                meta["unassessed"] += 1
                continue
            if assessment.relationship == "unrelated":
                candidates.pop(record_id, None)
                continue
            evidence = classify.redacted_reason(
                " ".join(assessment.evidence) or "Model assessment provided no reason."
            )
            evidence_class = RELATION_TO_CLASS.get(assessment.relationship, classify.UNKNOWN)
            upgraded = self._candidate(
                record_id=record_id,
                store_id=candidate["store_id"],
                record_type=candidate["record_type"],
                capabilities=candidate["capabilities"],
                evidence_class=evidence_class,
                reason_redacted=classify.explain(
                    evidence_class=evidence_class,
                    record_type=candidate["record_type"],
                    action=classify.REVIEW_REQUIRED,
                    candidate_evidence=evidence,
                ),
                relation=assessment.relationship,
            )
            candidates[record_id] = upgraded
            if record_id not in candidate_edges:
                candidate_edges[record_id] = {
                    "target_id": record_id,
                    "relation_guess": assessment.relationship,
                }
                self.repo.add_candidate_edge(
                    source_id=target_id,
                    target_id=record_id,
                    relation_guess=assessment.relationship,
                    evidence_summary_redacted=evidence,
                    model_id=outcome.model_id,
                )
        return meta

    # ------------------------------------------------- internal lineage hook
    LINEAGE_RELATIONS = {
        "READ_FROM",
        "DERIVED_FROM",
        "EXTRACTED_FROM",
        "SUMMARIZED_FROM",
        "INDEXED_AS",
        "CACHED_AS",
        "STORED_IN",
        "REGENERATED_FROM",
    }
    EVIDENCE_TYPES = {
        "instrumented",
        "imported_metadata",
        "human_verified",
        "model_inferred",
        "heuristic_match",
    }
    CONFIRMABLE_EVIDENCE = {"instrumented", "imported_metadata", "human_verified"}

    def record_lineage(
        self,
        *,
        source_ids: Sequence[str],
        output_id: str,
        relation: str,
        evidence_type: str,
        evidence_ref: str | None = None,
        verified_by: str | None = None,
        confidence: float | None = None,
    ) -> dict[str, Any]:
        """Internal-only hook for trusted ingestion/transformation code.

        This is deliberately not an MCP tool. Instrumented/imported/human-verified
        evidence is required before an edge can be confirmed; model or heuristic
        evidence only creates candidate edges. Arbitrary agent claims cannot be
        promoted to confirmed lineage through this method.
        """
        if relation not in self.LINEAGE_RELATIONS:
            raise RedactoError(
                "invalid_relation",
                "Relationship is not part of the provenance vocabulary.",
                {"relation": relation},
            )
        if evidence_type not in self.EVIDENCE_TYPES:
            raise RedactoError(
                "invalid_evidence_type",
                "Evidence type is not part of the provenance vocabulary.",
                {"evidence_type": evidence_type},
            )
        if not source_ids:
            raise RedactoError("invalid_sources", "At least one source_id is required.")
        self._require_record(output_id)
        for source_id in source_ids:
            self._require_record(source_id)
        if evidence_type in {"instrumented", "imported_metadata"} and not evidence_ref:
            raise RedactoError(
                "missing_evidence_ref",
                "Instrumented/imported lineage requires an opaque evidence reference.",
            )
        if evidence_type == "human_verified" and not verified_by:
            raise RedactoError(
                "missing_verifier",
                "Human-verified lineage requires a verifier identity.",
            )

        confirmed = evidence_type in self.CONFIRMABLE_EVIDENCE
        edges: list[dict[str, Any]] = []
        for source_id in source_ids:
            if confirmed:
                edge_id = self.repo.add_lineage_edge(
                    source_id=source_id,
                    target_id=output_id,
                    relation=relation,
                    evidence_type=evidence_type,
                    evidence_ref=evidence_ref,
                    status="confirmed",
                    verified_by=verified_by,
                )
            else:
                edge_id = self.repo.add_candidate_edge(
                    source_id=source_id,
                    target_id=output_id,
                    relation_guess=relation,
                    evidence_summary_redacted=(
                        f"{evidence_type} relationship claim; advisory until reviewed."
                    ),
                    model_id=evidence_type,
                    confidence=confidence,
                    status="candidate",
                )
            edges.append({"edge_id": edge_id, "source_id": source_id, "status": "confirmed" if confirmed else "candidate"})

        return {
            "ok": True,
            "output_id": output_id,
            "relation": relation,
            "evidence_type": evidence_type,
            "status": "confirmed" if confirmed else "candidate",
            "edges": edges,
        }

    # ----------------------------------------------------------------- trace
    def trace(self, *, source_id: str, depth: int = 3) -> dict[str, Any]:
        if not 1 <= depth <= 5:
            raise RedactoError("invalid_depth", "depth must be between 1 and 5")
        record = self._require_record(source_id)
        traversal = traverse(self.repo, source_id, max_depth=depth)

        def describe(node) -> dict[str, Any]:
            graph_record = self.repo.get_record(node.record_id) or {}
            return {
                "record_id": node.record_id,
                "record_type": graph_record.get("record_type", "unknown"),
                "node_type": self._node_type(graph_record.get("record_type", "unknown")),
                "store_id": graph_record.get("store_id"),
                "depth": node.depth,
                "via": node.via,
            }

        return {
            "source": {
                "record_id": record["record_id"],
                "record_type": record["record_type"],
                "node_type": "SOURCE",
                "store_id": record["store_id"],
                "label": record["locator"].get("path") or record["locator"].get("id"),
            },
            "confirmed_descendants": [describe(node) for node in traversal.descendants],
            "weak_exposure": [describe(node) for node in traversal.exposures],
            "candidate_relationships": [
                {
                    "record_id": edge["target_id"],
                    "relation_guess": edge["relation_guess"],
                    "evidence_summary_redacted": edge["evidence_summary_redacted"],
                    "model_id": edge["model_id"],
                    "confidence": edge["confidence"],
                    "status": edge["status"],
                }
                for edge in traversal.candidates
            ],
            "explanation": (
                "Confirmed descendants require instrumented, imported or human-verified edges. "
                "READ_FROM links are exposure evidence only and never authorize deletion on their own. "
                "Candidate relationships are advisory until reviewed."
            ),
            "max_depth_reached": traversal.max_depth_reached,
        }

    # ------------------------------------------------------------------ plan
    def plan(
        self,
        *,
        target_id: str,
        mode: str = "source_revocation",
        target_kind: str = "source",
        stores: Sequence[str] | None = None,
        depth: int = 3,
        use_model: bool = True,
        target_text: str | None = None,
    ) -> dict[str, Any]:
        if mode not in MODES:
            raise RedactoError("invalid_mode", f"mode must be one of {sorted(MODES)}")
        scan_result = self.scan(
            target_id=target_id,
            target_kind=target_kind,
            stores=stores,
            depth=depth,
            use_model=use_model,
            target_text=target_text,
        )
        items = build_plan_items(scan_result["candidates"])
        scope = {"stores": scan_result["scope"]["stores"], "max_depth": depth}
        policy = {
            "preserve_related": True,
            "review_suspected": True,
            "require_approval": True,
            "unreachable_stores": scan_result["unreachable_stores"],
            "model": scan_result["model"],
        }
        # Capture tombstone material now: after apply the target content may be gone.
        target_record = self._require_record(target_id)
        target_content = self._target_content(target_record, target_kind, target_text)
        embedder = self.embedder()
        material = TombstoneMaterial.build(
            target_content, self.settings.current_hmac_key, embedder
        )
        if target_kind == "source":
            label_redacted = (
                target_record["locator"].get("path")
                or target_record["locator"].get("id")
                or target_id
            )
        else:
            label_redacted = f"<redacted {target_kind} target>"

        request_id = self.repo.create_request(
            target_id=target_id,
            target_kind=target_kind,
            mode=mode,
            scope=scope,
            policy=policy,
            state="READY_FOR_APPROVAL",
            target_fingerprint=material.fingerprint,
            target_shingles=material.shingles,
            target_anchors=material.anchors,
            target_tokens=material.tokens,
            target_label_redacted=label_redacted,
            target_key_version=self.settings.hmac_key_version,
            target_embedding=material.embedding,
            target_embedding_model=material.embedding_model or None,
            target_normalized_len=(
                len(normalize_loose(target_content))
                if target_kind in {"fact", "secret"}
                else None
            ),
        )
        version = self.repo.next_plan_version(request_id)
        plan_hash = compute_plan_hash(
            target_id=target_id,
            mode=mode,
            scope=scope,
            policy=policy,
            version=version,
            items=items,
        )
        plan_id = self.repo.create_plan(
            request_id=request_id,
            version=version,
            scope=scope,
            plan_hash=plan_hash,
            items=items,
        )
        warnings: list[str] = []
        if scan_result["unreachable_stores"]:
            warnings.append(
                "Unreachable stores are reported as gaps: "
                + ", ".join(scan_result["unreachable_stores"])
            )
        if any(item["proposed_action"] == classify.REVIEW_REQUIRED for item in items):
            warnings.append("Some candidates require human review and are excluded from execution.")

        return {
            "ok": True,
            "request_id": request_id,
            "plan_id": plan_id,
            "plan_version": version,
            "state": "READY_FOR_APPROVAL",
            "plan_hash": plan_hash,
            "mode": mode,
            "target": scan_result["target"],
            "scope": scope,
            "items": items,
            "counts": scan_result["counts"],
            "estimated_impact": estimated_impact(items),
            "unreachable_stores": scan_result["unreachable_stores"],
            "model": scan_result["model"],
            "approval_required": True,
            "approval_instructions": (
                "The application must issue a short-lived confirmation token bound to this "
                "plan_id and plan_version (see `redacto approve`). The agent cannot approve."
            ),
            "warnings": warnings,
            "limitations": scan_result["limitations"],
        }

    # ------------------------------------------------------------- tombstones
    @staticmethod
    def _tombstone_public(tombstone: dict[str, Any] | None) -> dict[str, Any] | None:
        if tombstone is None:
            return None
        return {
            "tombstone_id": tombstone["tombstone_id"],
            "request_id": tombstone["request_id"],
            "target_id": tombstone["target_id"],
            "target_kind": tombstone["target_kind"],
            "label_redacted": tombstone["label_redacted"],
            "scope": tombstone["scope"],
            "policy": tombstone["policy"],
            "status": tombstone["status"],
            "key_version": tombstone.get("key_version", 1),
            "embedding_model": tombstone.get("embedding_model"),
            "created_at": tombstone["created_at"],
            "activated_at": tombstone["activated_at"],
            "related_record_ids": tombstone["related_record_ids"],
            "related_record_count": len(tombstone["related_record_ids"]),
        }

    def activate_tombstones(self, request_id: str, plan_id: str) -> dict[str, Any] | None:
        """Create (or return) the active tombstone for a completed revocation."""
        existing = self.repo.tombstones_for_request(request_id)
        if existing:
            return existing[0]
        request = self.repo.get_request(request_id)
        if request is None or not request.get("target_fingerprint"):
            return None

        items = self.repo.plan_items(plan_id)
        removed = [i for i in items if i["state"] in {"done", "already_absent"}]
        related_ids = [i["record_id"] for i in removed if i["record_id"] != request["target_id"]]
        related_fingerprints: list[dict[str, Any]] = []
        for record_id in related_ids:
            record = self.repo.get_record(record_id)
            if record and record.get("fingerprint"):
                related_fingerprints.append(
                    {
                        "version": (
                            record.get("fingerprint_key_version")
                            or request.get("target_key_version")
                            or 1
                        ),
                        "fingerprint": record["fingerprint"],
                    }
                )

        tombstone_id = self.repo.add_tombstone(
            request_id=request_id,
            target_id=request["target_id"],
            target_kind=request["target_kind"],
            label_redacted=request.get("target_label_redacted") or request["target_id"],
            fingerprint_value=request["target_fingerprint"],
            shingles=request.get("target_shingles", []),
            anchors=request.get("target_anchors", []),
            tokens=request.get("target_tokens", []),
            related_record_ids=related_ids,
            related_fingerprints=related_fingerprints,
            scope=request["scope"],
            policy=request["policy"],
            status="pending",
            key_version=request.get("target_key_version") or self.settings.hmac_key_version,
            embedding=request.get("target_embedding", []),
            embedding_model=request.get("target_embedding_model"),
        )
        self.repo.set_tombstone_status(tombstone_id, "active")
        return self.repo.get_tombstone(tombstone_id)

    def tombstones(self, *, statuses: Sequence[str] = ("active",)) -> dict[str, Any]:
        """List tombstones without fingerprints or any revoked content."""
        items = self.repo.list_tombstones(statuses=statuses)
        return {
            "ok": True,
            "count": len(items),
            "statuses": list(statuses),
            "tombstones": [self._tombstone_public(item) for item in items],
            "note": (
                "Tombstones retain keyed fingerprints, derived match anchors, scope, policy "
                "and status only. No revoked content is stored."
            ),
        }

    def keyring_report(self, *, retire_version: int | None = None) -> dict[str, Any]:
        """Audit the versioned key ring and whether a version can be retired."""
        active = self.repo.list_tombstones(statuses=("active",))
        by_version: dict[int, int] = {}
        required_versions: set[int] = set()
        for tombstone in active:
            version = int(tombstone.get("key_version") or 1)
            by_version[version] = by_version.get(version, 0) + 1
            required_versions.add(version)
            for entry in tombstone.get("related_fingerprints", []):
                if isinstance(entry, dict) and entry.get("version"):
                    required_versions.add(int(entry["version"]))
        configured = sorted(self.settings.hmac_keys)
        missing = sorted(version for version in required_versions if version not in self.settings.hmac_keys)
        # Never suggest retiring the current key or one still referenced by a tombstone.
        unused_configured = [
            version
            for version in configured
            if version != self.settings.hmac_key_version and version not in required_versions
        ]
        current_missing = self.settings.hmac_key_version not in self.settings.hmac_keys

        report: dict[str, Any] = {
            "ok": True,
            "current_key_version": self.settings.hmac_key_version,
            "configured_versions": configured,
            "active_tombstones": len(active),
            "tombstones_by_key_version": by_version,
            "in_use_key_versions": sorted(required_versions),
            "missing_key_versions": missing,
            "protection_degraded": bool(
                self.settings.keyring_error or missing or current_missing
            ),
            "keyring_error": self.settings.keyring_error,
            "retirable_versions": unused_configured,
            "rotation_steps": [
                "Add the new key as a new version in REDACTO_HMAC_KEYS; keep the old key.",
                "Raise REDACTO_HMAC_KEY_VERSION to the new version and restart.",
                "Run `redacto keyring` and confirm missing_key_versions is empty.",
                "Keep old keys until no active tombstone references them.",
                "Remove a key only when its version appears in retirable_versions.",
            ],
        }
        if current_missing:
            report["warning"] = (
                "The current key version is missing: ingestion and new revocations will be "
                "refused until it is restored."
            )
        if missing:
            report["warning"] = (
                "Active tombstones reference missing key versions: ingestion fails closed "
                "until those keys are restored."
            )
        if retire_version is not None:
            if retire_version not in self.settings.hmac_keys:
                raise RedactoError(
                    "unknown_key_version",
                    "That key version is not configured.",
                    {"version": retire_version, "configured": configured},
                )
            if retire_version == self.settings.hmac_key_version:
                raise RedactoError(
                    "current_version_in_use",
                    "The current key version cannot be retired; rotate first.",
                    {"version": retire_version},
                )
            if retire_version in required_versions:
                raise RedactoError(
                    "version_still_in_use",
                    "Active tombstones still reference this key version; keep the key.",
                    {
                        "version": retire_version,
                        "active_tombstones": by_version.get(retire_version, 0),
                    },
                )
            report["retirement"] = {
                "version": retire_version,
                "safe": True,
                "action": "Remove this version from REDACTO_HMAC_KEYS and restart.",
            }
        return report

    # --------------------------------------------------------------- ingestion
    def ingest(
        self,
        records: Sequence[Record],
        *,
        store_id: str | None = None,
        write_to_store: bool = False,
    ) -> dict[str, Any]:
        """Admit records through the tombstone guard.

        Blocked records never enter the store or the provenance graph. Quarantined
        records are held for review and also not admitted. Allowed records are
        written to the store first (when requested) and then added to the graph.
        """
        guard = self.guard()
        slots = self.adapters()
        if write_to_store:
            if not store_id:
                raise RedactoError("invalid_store", "store_id is required when write_to_store is true.")
            if store_id not in slots:
                raise RedactoError(
                    "out_of_scope_store",
                    "The target store is not configured; ingestion cannot broaden scope.",
                    {"store_id": store_id},
                )
            if slots[store_id].adapter is None:
                raise RedactoError(
                    "store_unreachable",
                    "The target store is not reachable; nothing was written.",
                    {"store_id": store_id, "reason": slots[store_id].unavailable_reason},
                )

        counts = {ALLOWED: 0, BLOCKED: 0, QUARANTINED: 0, "skipped": 0}
        results: list[dict[str, Any]] = []
        for record in records:
            if store_id is not None and record.store_id != store_id:
                record = record.model_copy(update={"store_id": store_id})
            if self._record_is_oversized(record):
                counts["skipped"] += 1
                results.append(self._skip_finding(record, present_in_store=False))
                continue
            decision = guard.evaluate(record_id=record.record_id, content=record.content)
            if decision.decision != ALLOWED:
                self._record_guard_decision(decision, record, present_in_store=False)
                counts[decision.decision] += 1
                results.append(self._guard_finding(decision, record, present_in_store=False))
                continue

            if write_to_store:
                try:
                    slots[store_id].adapter.write_record(record)  # type: ignore[union-attr]
                except AdapterError as exc:
                    raise RedactoError(
                        "ingestion_write_failed",
                        f"Store rejected the write: {exc}",
                        {"store_id": store_id, "adapter_code": exc.code},
                    ) from exc
            capabilities = (
                self._record_capabilities(record.store_id, slots[record.store_id])
                if record.store_id in slots
                else {}
            )
            self._upsert_scanned(record, capabilities)
            counts[ALLOWED] += 1
            results.append(
                {
                    "record_id": record.record_id,
                    "store_id": record.store_id,
                    "record_type": record.record_type,
                    "decision": ALLOWED,
                    "reason_code": "no_match",
                    "match_score": 0.0,
                    "written_to_store": bool(write_to_store),
                    "admitted": True,
                }
            )
        return {
            "ok": True,
            "counts": counts,
            "results": results,
            "guard": {"active_tombstones": guard.active_count},
            "limitations": [
                "The guard blocks admission; it does not delete records already present in a store.",
                "Quarantined records are held for review and are not added to the active graph.",
                "A quarantined new write is not written to the store; the caller still holds the source record.",
            ],
        }

    def reingest_stores(self, stores: Sequence[str] | None = None) -> dict[str, Any]:
        """Rescan configured stores through the guard without creating candidates."""
        guard = self.guard()
        scope_stores = self._scope_stores(stores)
        slots = self.adapters()
        counts = {ALLOWED: 0, BLOCKED: 0, QUARANTINED: 0, "skipped": 0}
        findings: list[dict[str, Any]] = []
        unreachable: list[dict[str, Any]] = []
        truncated_stores: list[str] = []

        for store in scope_stores:
            slot = slots[store]
            if slot.adapter is None:
                unreachable.append({"store_id": store, "reason": slot.unavailable_reason})
                continue
            limit = self.settings.max_scan_records
            try:
                records = list(slot.adapter.list_records(limit=limit + 1))
            except AdapterError as exc:
                unreachable.append({"store_id": store, "reason": f"{exc.code}: {exc}"})
                continue
            if len(records) > limit:
                records = records[:limit]
                truncated_stores.append(store)
            capabilities = self._record_capabilities(store, slot)
            for record in records:
                if self._record_is_oversized(record):
                    counts["skipped"] += 1
                    findings.append(self._skip_finding(record, present_in_store=True))
                    continue
                decision = guard.evaluate(record_id=record.record_id, content=record.content)
                if decision.decision != ALLOWED:
                    self._record_guard_decision(decision, record, present_in_store=True)
                    counts[decision.decision] += 1
                    findings.append(self._guard_finding(decision, record, present_in_store=True))
                    continue
                self._upsert_scanned(record, capabilities)
                counts[ALLOWED] += 1

        return {
            "ok": True,
            "counts": counts,
            "findings": findings,
            "unreachable_stores": unreachable,
            "truncated_stores": truncated_stores,
            "guard": {"active_tombstones": guard.active_count},
            "note": (
                "Blocked and quarantined records were not admitted to the graph. "
                "Records already present in a store are reported, not silently deleted."
            ),
        }

    def quarantine(self, *, statuses: Sequence[str] = ("pending_review",)) -> dict[str, Any]:
        items = self.repo.list_quarantine(statuses=statuses)
        return {
            "ok": True,
            "count": len(items),
            "statuses": list(statuses),
            "quarantine": items,
            "note": "Quarantine entries hold a locator and redacted match reason, never record content.",
        }

    def resolve_quarantine(
        self,
        *,
        quarantine_id: str,
        decision: str,
        reviewer: str = "local-operator",
        note: str | None = None,
    ) -> dict[str, Any]:
        """Resolve a quarantine entry through an explicit, auditable path.

        Approving re-reads the stored record, rechecks every active tombstone and the
        current safety mode, then admits it to the provenance graph. Rejecting records
        the decision without admitting anything. Neither path deletes stored content.
        """
        if decision not in {"approved", "rejected"}:
            raise RedactoError("invalid_decision", "decision must be 'approved' or 'rejected'.")
        reviewer = (reviewer or "").strip()
        if not reviewer:
            raise RedactoError("invalid_reviewer", "A reviewer identity is required for the audit record.")
        if note is not None and len(note) > 500:
            raise RedactoError("note_too_long", "Review note must be 500 characters or fewer.")

        entry = self.repo.get_quarantine(quarantine_id)
        if entry is None:
            raise RedactoError(
                "unknown_quarantine", "No such quarantine entry.", {"quarantine_id": quarantine_id}
            )
        if entry["status"] != "pending_review":
            raise RedactoError(
                "quarantine_already_resolved",
                "This quarantine entry already has a recorded decision.",
                {"quarantine_id": quarantine_id, "status": entry["status"]},
            )

        guard = self.guard()
        policy_snapshot = {
            "safety_mode": self.settings.safety_mode,
            "active_tombstones": guard.active_count,
            "reviewer": reviewer,
            "note": note or "",
        }
        slots = self.adapters()
        slot = slots.get(entry["store_id"]) if entry["store_id"] else None
        present = slot is not None and slot.adapter is not None

        if decision == "rejected":
            record = {
                **policy_snapshot,
                "outcome": "rejected",
                "reason": "human_review_rejected",
                "admitted": False,
            }
            event_id = self.repo.record_ingestion_event(
                tombstone_id=entry["tombstone_id"],
                store_id=entry["store_id"],
                record_id=entry["record_id"],
                locator=entry["locator"],
                decision="rejected",
                reason_code="quarantine_rejected",
                match_score=entry["match_score"],
                present_in_store=present,
            )
            self.repo.set_quarantine_status(
                quarantine_id,
                "rejected",
                reviewed_by=reviewer,
                note=note,
                recheck=record,
            )
            return {
                "ok": True,
                "quarantine_id": quarantine_id,
                "status": "rejected",
                "admitted": False,
                "audit_event_id": event_id,
                "decision_record": record,
            }

        if not present:
            record = {
                **policy_snapshot,
                "outcome": "resubmit_required",
                "reason": "source_store_unreachable_or_content_not_retained",
                "admitted": False,
            }
            event_id = self.repo.record_ingestion_event(
                tombstone_id=entry["tombstone_id"],
                store_id=entry["store_id"],
                record_id=entry["record_id"],
                locator=entry["locator"],
                decision="resubmit_required",
                reason_code="quarantine_source_unavailable",
                match_score=entry["match_score"],
                present_in_store=False,
            )
            self.repo.set_quarantine_status(
                quarantine_id,
                "pending_review",
                reviewed_by=reviewer,
                note=note,
                recheck=record,
            )
            return {
                "ok": True,
                "quarantine_id": quarantine_id,
                "status": "pending_review",
                "admitted": False,
                "audit_event_id": event_id,
                "decision_record": record,
                "message": "Content is not retained in quarantine; resubmit the record to review it.",
            }

        try:
            record = slot.adapter.read_record(entry["locator"])  # type: ignore[union-attr]
        except AdapterError as exc:
            outcome = {
                **policy_snapshot,
                "outcome": "resubmit_required",
                "reason": f"source_record_unreadable:{exc.code}",
                "admitted": False,
            }
            event_id = self.repo.record_ingestion_event(
                tombstone_id=entry["tombstone_id"],
                store_id=entry["store_id"],
                record_id=entry["record_id"],
                locator=entry["locator"],
                decision="resubmit_required",
                reason_code="quarantine_source_unavailable",
                match_score=entry["match_score"],
                present_in_store=False,
            )
            self.repo.set_quarantine_status(
                quarantine_id, "pending_review", reviewed_by=reviewer, note=note, recheck=outcome
            )
            return {
                "ok": True,
                "quarantine_id": quarantine_id,
                "status": "pending_review",
                "admitted": False,
                "audit_event_id": event_id,
                "decision_record": outcome,
            }

        # Recheck the guard at resolution time, not at quarantine time.
        # A human approval may override uncertainty, never a hard tombstone block.
        recheck = guard.evaluate(record_id=record.record_id, content=record.content)
        override_allowed = self.settings.safety_mode != "strict"
        refused = recheck.decision == BLOCKED or (
            recheck.decision == QUARANTINED and not override_allowed
        )
        decision_record = {
            **policy_snapshot,
            "outcome": recheck.decision,
            "guard": recheck.as_dict(),
            "review_override_allowed": override_allowed,
            "admitted": not refused,
        }
        if refused:
            event_id = self.repo.record_ingestion_event(
                tombstone_id=recheck.tombstone_id or entry["tombstone_id"],
                store_id=record.store_id,
                record_id=record.record_id,
                locator=record.locator,
                decision=recheck.decision,
                reason_code=f"quarantine_recheck:{recheck.reason_code}",
                match_score=recheck.match_score,
                present_in_store=True,
            )
            self.repo.set_quarantine_status(
                quarantine_id,
                "blocked_on_recheck",
                reviewed_by=reviewer,
                note=note,
                recheck=decision_record,
            )
            return {
                "ok": True,
                "quarantine_id": quarantine_id,
                "status": "blocked_on_recheck",
                "admitted": False,
                "audit_event_id": event_id,
                "decision_record": decision_record,
                "message": (
                    "Approval refused: an active tombstone still blocks this record, or "
                    "the current safety mode does not allow an uncertainty override. "
                    "It was not admitted."
                ),
            }

        if recheck.decision == QUARANTINED:
            decision_record["outcome"] = "quarantined_overridden"
            decision_record["override_reason"] = "human_review_approved"
        capabilities = self._record_capabilities(entry["store_id"], slot)
        self._upsert_scanned(record, capabilities)
        event_id = self.repo.record_ingestion_event(
            tombstone_id=None,
            store_id=record.store_id,
            record_id=record.record_id,
            locator=record.locator,
            decision="admitted",
            reason_code="quarantine_approved",
            match_score=entry["match_score"],
            present_in_store=True,
        )
        self.repo.set_quarantine_status(
            quarantine_id,
            "approved",
            reviewed_by=reviewer,
            note=note,
            admission_event_id=event_id,
            recheck=decision_record,
            admitted_at=now_iso(),
        )
        return {
            "ok": True,
            "quarantine_id": quarantine_id,
            "status": "approved",
            "admitted": True,
            "record_id": record.record_id,
            "audit_event_id": event_id,
            "decision_record": decision_record,
        }

    # --------------------------------------------------------------- approve
    def approve_plan(self, *, plan_id: str, approval_ref: str, ttl_seconds: int = 600) -> dict[str, Any]:
        plan = self.repo.get_plan(plan_id)
        recovery = bool(plan and plan["state"] in {"EXECUTING", "FAILED", "PARTIAL"})
        # A lease can be left behind in any state, including before EXECUTING.
        # Refuse while its owner is alive; clear it when the owner is gone.
        lease = self.repo.plan_execution_lease(plan_id)
        if lease is not None:
            if not self._lease_is_stale(lease):
                raise RedactoError(
                    "apply_in_progress",
                    "This plan is still executing; recovery approval is refused.",
                    {"plan_id": plan_id, "pid": lease.get("execution_pid")},
                )
            self.repo.clear_plan_execution(plan_id)
            # Clearing a stale lease is itself a recovery action.
            recovery = True
        try:
            issued = authorization.issue_approval(
                self.repo, plan_id=plan_id, approval_ref=approval_ref, ttl_seconds=ttl_seconds
            )
        except ValueError as exc:
            raise RedactoError(str(exc), f"Approval could not be issued: {exc}") from exc
        result = {"ok": True, **issued, "recovery": recovery}
        if recovery:
            result["note"] = (
                "Recovery approval for an EXECUTING plan. Completed actions are skipped by "
                "idempotency; remaining actions run under the new token."
            )
        return result

    def review_plan_item(
        self,
        *,
        plan_id: str,
        item_id: str,
        decision: str,
        reviewer: str,
        note: str | None = None,
    ) -> dict[str, Any]:
        """Approve or reject one review-required plan item (application action).

        Approving rewrites the item to a concrete adapter action and bumps the plan
        version, so the changed plan needs a fresh approval token. Rejecting leaves
        the item unapproved. Both decisions are audited.
        """
        if decision not in {"approved", "rejected"}:
            raise RedactoError("invalid_decision", "decision must be 'approved' or 'rejected'.")
        reviewer = (reviewer or "").strip()
        if not reviewer:
            raise RedactoError("invalid_reviewer", "A reviewer identity is required.")
        if note is not None and len(note) > 500:
            raise RedactoError("note_too_long", "Review note must be 500 characters or fewer.")

        plan = self.repo.get_plan(plan_id)
        if plan is None:
            raise RedactoError(
                "unknown_plan",
                f"No such plan in the graph database at {self.settings.db_path}.",
                {"plan_id": plan_id, "db_path": str(self.settings.db_path)},
            )
        # A plan that already applied its actionable items can still have unresolved
        # review items (for example a small secret inside a large handbook). Refusing
        # review here would strand that revocation forever.
        if plan["state"] not in {
            "READY_FOR_APPROVAL",
            "APPROVED",
            "VERIFYING",
            "PARTIAL",
            "NEEDS_REVIEW",
        }:
            raise RedactoError(
                "plan_not_reviewable",
                "This plan can no longer accept item reviews.",
                {"plan_id": plan_id, "state": plan["state"]},
            )
        item = self.repo.get_plan_item(item_id)
        if item is None or item["plan_id"] != plan_id:
            raise RedactoError("unknown_plan_item", "No such item on this plan.", {"item_id": item_id})
        if item["proposed_action"] != classify.REVIEW_REQUIRED:
            raise RedactoError(
                "item_not_reviewable",
                "Only REVIEW_REQUIRED items can be reviewed.",
                {"item_id": item_id, "proposed_action": item["proposed_action"]},
            )

        record = self.repo.get_record(item["record_id"]) or {}
        if decision == "approved":
            action = classify.override_action(
                record_type=record.get("record_type", "unknown"),
                capabilities=record.get("capabilities", {}),
            )
            if action is None:
                raise RedactoError(
                    "no_safe_action",
                    "This adapter cannot perform an approved action for the item.",
                    {"item_id": item_id, "record_id": item["record_id"]},
                )
            self.repo.set_item_review(
                item_id, approved=True, action=action, state="review_approved"
            )
        else:
            self.repo.set_item_review(
                item_id,
                approved=False,
                action=classify.REVIEW_REQUIRED,
                state="review_rejected",
            )

        request = self.repo.get_request(plan["request_id"])
        assert request is not None
        items = self.repo.plan_items(plan_id)
        version = int(plan["version"]) + 1
        plan_hash = compute_plan_hash(
            target_id=request["target_id"],
            mode=request["mode"],
            scope=plan["scope"],
            policy=request["policy"],
            version=version,
            items=items,
        )
        self.repo.update_plan_version(plan_id, version, plan_hash, "READY_FOR_APPROVAL")
        self.repo.set_request_state(plan["request_id"], "READY_FOR_APPROVAL")
        review_id = self.repo.add_plan_item_review(
            plan_id=plan_id,
            item_id=item_id,
            plan_version=version,
            decision=decision,
            reviewer=reviewer,
            note=note,
        )
        return {
            "ok": True,
            "plan_id": plan_id,
            "plan_version": version,
            "plan_hash": plan_hash,
            "state": "READY_FOR_APPROVAL",
            "item_id": item_id,
            "decision": decision,
            "review_id": review_id,
            "approval_required": True,
            "message": (
                "Plan changed; issue a new approval token for this version before applying."
            ),
        }

    def cancel_plan(self, *, plan_id: str, reason: str = "") -> dict[str, Any]:
        plan = self.repo.get_plan(plan_id)
        if plan is None:
            raise RedactoError(
                "unknown_plan",
                f"No such plan in the graph database at {self.settings.db_path}.",
                {"plan_id": plan_id, "db_path": str(self.settings.db_path)},
            )
        if plan["state"] == "CANCELLED":
            return {"ok": True, "plan_id": plan_id, "state": "CANCELLED", "already_cancelled": True}
        if plan["state"] not in {"READY_FOR_APPROVAL", "APPROVED"}:
            raise RedactoError(
                "plan_not_cancellable",
                "Only a plan that has not started executing can be cancelled.",
                {"plan_id": plan_id, "state": plan["state"]},
            )
        self.repo.set_plan_state(plan_id, "CANCELLED")
        self.repo.set_request_state(plan["request_id"], "CANCELLED")
        return {
            "ok": True,
            "plan_id": plan_id,
            "request_id": plan["request_id"],
            "state": "CANCELLED",
            "reason": reason,
        }

    # ----------------------------------------------------------------- apply
    # Only used when the lease owner is on another host, where PID liveness
    # cannot be checked. A live local apply is never stolen, however long it runs.
    EXECUTION_LEASE_SECONDS = 900

    def _lease_is_stale(self, lease: dict[str, Any]) -> bool:
        """Whether a lease may be taken over.

        - Same host: the owner PID decides. A live PID is never stale, no matter how
          old the lease is, so a slow apply cannot lose its lease.
        - Different host: PID liveness is unknowable, so the TTL decides.
        """
        pid = lease.get("execution_pid")
        host = lease.get("execution_host")
        if host == socket.gethostname() and pid:
            return not pid_alive(int(pid))
        started = lease.get("execution_started_at")
        if not started:
            return True
        try:
            age = datetime.now(timezone.utc) - datetime.fromisoformat(started)
        except ValueError:
            return True
        return age.total_seconds() > self.EXECUTION_LEASE_SECONDS

    def _release_stale_lease(self, plan_id: str) -> None:
        """Clear a lease whose owner is gone, whatever the plan state.

        Covers the stuck case where the process died after claiming the lease but
        before the plan moved to EXECUTING.
        """
        lease = self.repo.plan_execution_lease(plan_id)
        if lease is not None and self._lease_is_stale(lease):
            self.repo.clear_plan_execution(plan_id)

    def apply(
        self,
        *,
        plan_id: str,
        plan_version: int,
        approval_ref: str,
        confirmation_token: str,
        dry_run: bool | None = None,
    ) -> dict[str, Any]:
        """Apply an approved plan, marking an unexpected abort as FAILED."""
        simulate = self.settings.dry_run if dry_run is None else dry_run
        plan = self.repo.get_plan(plan_id)
        execution_token: str | None = None
        if (
            not simulate
            and plan is not None
            and plan["state"] in {"APPROVED", "EXECUTING", "FAILED", "PARTIAL"}
        ):
            # Validate the token before taking the lease, so a forged token can never
            # block a legitimate apply.
            ok_token, token_reason, _ = authorization.verify_approval(
                self.repo,
                plan_id=plan_id,
                plan_version=int(plan["version"]),
                approval_ref=approval_ref,
                confirmation_token=confirmation_token,
            )
            if not ok_token:
                raise RedactoError(
                    "unauthorized_apply",
                    f"Apply rejected: {token_reason}.",
                    {"reason": token_reason},
                )
            # A dead owner's lease must not block the plan forever.
            self._release_stale_lease(plan_id)
            execution_token = self.repo.claim_plan_execution(plan_id)
            if execution_token is None:
                raise RedactoError(
                    "apply_in_progress",
                    "Another apply is executing this plan.",
                    {"plan_id": plan_id},
                )
        try:
            return self._apply(
                plan_id=plan_id,
                plan_version=plan_version,
                approval_ref=approval_ref,
                confirmation_token=confirmation_token,
                dry_run=dry_run,
            )
        except RedactoError:
            raise
        except Exception as exc:
            current = self.repo.get_plan(plan_id)
            if current is not None and current["state"] == "EXECUTING":
                self.repo.set_plan_state(plan_id, "FAILED")
                self.repo.set_request_state(current["request_id"], "FAILED")
            raise RedactoError(
                "apply_failed",
                "Apply aborted unexpectedly; the plan is marked FAILED.",
                {"type": type(exc).__name__},
            ) from exc
        finally:
            if execution_token is not None:
                self.repo.release_plan_execution(plan_id, execution_token)

    def _apply(
        self,
        *,
        plan_id: str,
        plan_version: int,
        approval_ref: str,
        confirmation_token: str,
        dry_run: bool | None = None,
    ) -> dict[str, Any]:
        plan = self.repo.get_plan(plan_id)
        if plan is None:
            raise RedactoError(
                "unknown_plan",
                f"No such plan in the graph database at {self.settings.db_path}.",
                {"plan_id": plan_id, "db_path": str(self.settings.db_path)},
            )
        if plan["state"] == "CANCELLED":
            raise RedactoError(
                "plan_cancelled",
                "This plan was cancelled and cannot be applied.",
                {"plan_id": plan_id},
            )
        if plan["state"] in TERMINAL_PLAN_STATES:
            return {
                "ok": True,
                "already_completed": True,
                "plan_id": plan_id,
                "request_id": plan["request_id"],
                "plan_version": int(plan["version"]),
                "plan_state": plan["state"],
                "results": self.repo.actions_for_request(plan["request_id"]),
                "message": "This plan was already applied; no destructive work was repeated.",
            }
        if int(plan["version"]) != int(plan_version):
            raise RedactoError(
                "stale_plan",
                "The supplied plan_version does not match the stored plan version.",
                {"stored_version": int(plan["version"]), "supplied_version": plan_version},
            )

        request = self.repo.get_request(plan["request_id"])
        assert request is not None
        items = self.repo.plan_items(plan_id)
        recomputed = compute_plan_hash(
            target_id=request["target_id"],
            mode=request["mode"],
            scope=plan["scope"],
            policy=request["policy"],
            version=int(plan["version"]),
            items=items,
        )
        if recomputed != plan["plan_hash"]:
            raise RedactoError(
                "stale_plan",
                "The plan contents changed after approval; a new plan and approval are required.",
                {"plan_id": plan_id},
            )

        ok, reason, approval = authorization.verify_approval(
            self.repo,
            plan_id=plan_id,
            plan_version=int(plan["version"]),
            approval_ref=approval_ref,
            confirmation_token=confirmation_token,
        )
        if not ok:
            raise RedactoError("unauthorized_apply", f"Apply rejected: {reason}.", {"reason": reason})

        simulate = self.settings.dry_run if dry_run is None else dry_run
        if not simulate:
            # Claim the single-use approval atomically before any mutation. Two
            # concurrent applies with the same token cannot both win.
            if not self.repo.claim_approval(approval["approval_id"]):
                raise RedactoError(
                    "unauthorized_apply",
                    "Apply rejected: approval_already_used.",
                    {"reason": "approval_already_used"},
                )
            # Enter EXECUTING before any mutation; verify finalises the state.
            self.repo.set_plan_state(plan_id, "EXECUTING")
            self.repo.set_request_state(plan["request_id"], "EXECUTING")
        slots = self.adapters()
        scope_stores = set(plan["scope"].get("stores", []))
        results: list[dict[str, Any]] = []
        counts = {"succeeded": 0, "already_absent": 0, "failed": 0, "dry_run": 0, "blocked": 0}
        review_required: list[dict[str, Any]] = []

        for item in items:
            action = item["proposed_action"]
            if not item["approved"] or action not in classify.ACTIONABLE:
                if action == classify.SKIP_PRESERVE:
                    state = "preserved"
                elif action == classify.UNREACHABLE:
                    state = "unreachable"
                else:
                    state = "review_required"
                self.repo.set_item_state(item["item_id"], state)
                if state == "review_required":
                    review_required.append(
                        {
                            "item_id": item["item_id"],
                            "record_id": item["record_id"],
                            "evidence_class": item["evidence_class"],
                            "reason_redacted": item["reason_redacted"],
                        }
                    )
                continue

            # Dry runs must never satisfy the idempotency check for a real apply.
            key_prefix = "dryrun" if simulate else "applied"
            idempotency_key = f"{key_prefix}:{plan_id}:{item['item_id']}:{action}"
            existing = self.repo.get_action_by_key(idempotency_key)
            if existing is not None:
                if existing["result"] == "failed":
                    # A recovery apply retries failed actions. If the first attempt
                    # actually mutated the record, the adapter reports not_found and
                    # it is counted as already absent.
                    self.repo.delete_action_by_key(idempotency_key)
                    self.repo.set_item_state(item["item_id"], "planned")
                else:
                    results.append(existing)
                    if existing["result"] == "success":
                        counts["succeeded"] += 1
                    elif existing["result"] == "already_absent":
                        counts["already_absent"] += 1
                    elif existing["result"] == "dry_run":
                        counts["dry_run"] += 1
                    continue

            record = self.repo.get_record(item["record_id"])
            started = now_iso()
            if record is None:
                self.repo.record_action(
                    request_id=plan["request_id"],
                    item_id=item["item_id"],
                    adapter_id=None,
                    operation=action,
                    result="failed",
                    error_code="unknown_record",
                    started_at=started,
                    finished_at=now_iso(),
                    idempotency_key=idempotency_key,
                )
                self.repo.set_item_state(item["item_id"], "failed")
                counts["failed"] += 1
                results.append({"item_id": item["item_id"], "result": "failed", "error_code": "unknown_record"})
                continue

            if record["store_id"] not in scope_stores:
                self.repo.record_action(
                    request_id=plan["request_id"],
                    item_id=item["item_id"],
                    adapter_id=record["store_id"],
                    operation=action,
                    result="failed",
                    error_code="out_of_scope",
                    started_at=started,
                    finished_at=now_iso(),
                    idempotency_key=idempotency_key,
                )
                self.repo.set_item_state(item["item_id"], "failed")
                counts["failed"] += 1
                results.append({"item_id": item["item_id"], "result": "failed", "error_code": "out_of_scope"})
                continue

            if simulate:
                finished = now_iso()
                self.repo.record_action(
                    request_id=plan["request_id"],
                    item_id=item["item_id"],
                    adapter_id=record["store_id"],
                    operation=action,
                    result="dry_run",
                    error_code=None,
                    started_at=started,
                    finished_at=finished,
                    idempotency_key=idempotency_key,
                )
                counts["dry_run"] += 1
                results.append(
                    {
                        "item_id": item["item_id"],
                        "record_id": item["record_id"],
                        "adapter_id": record["store_id"],
                        "operation": action,
                        "result": "dry_run",
                    }
                )
                continue

            slot = slots.get(record["store_id"])
            if slot is None or slot.adapter is None:
                self.repo.record_action(
                    request_id=plan["request_id"],
                    item_id=item["item_id"],
                    adapter_id=record["store_id"],
                    operation=action,
                    result="failed",
                    error_code="adapter_unavailable",
                    started_at=started,
                    finished_at=now_iso(),
                    idempotency_key=idempotency_key,
                )
                self.repo.set_item_state(item["item_id"], "failed")
                counts["failed"] += 1
                results.append(
                    {"item_id": item["item_id"], "result": "failed", "error_code": "adapter_unavailable"}
                )
                continue

            # TOCTOU guard: adapters verify the plan-time fingerprint as part of the
            # mutation itself (SQLite does it under a write lock).
            expected_fingerprint = item.get("expected_fingerprint")
            expected_key = self.settings.key_for_version(
                item.get("fingerprint_key_version")
            )
            if not expected_fingerprint or expected_key is None:
                self.repo.record_action(
                    request_id=plan["request_id"],
                    item_id=item["item_id"],
                    adapter_id=record["store_id"],
                    operation=action,
                    result="failed",
                    error_code="content_unverifiable",
                    started_at=started,
                    finished_at=now_iso(),
                    idempotency_key=idempotency_key,
                )
                self.repo.set_item_state(item["item_id"], "failed")
                counts["failed"] += 1
                results.append(
                    {
                        "item_id": item["item_id"],
                        "record_id": item["record_id"],
                        "result": "failed",
                        "error_code": "content_unverifiable",
                    }
                )
                continue

            try:
                if action == classify.DELETE_RECORD:
                    slot.adapter.delete_record(
                        record["locator"],
                        expected_fingerprint=expected_fingerprint,
                        key=expected_key,
                    )
                elif action in {classify.INVALIDATE_INDEX, classify.INVALIDATE_CACHE}:
                    slot.adapter.invalidate_derived(
                        record["locator"],
                        expected_fingerprint=expected_fingerprint,
                        key=expected_key,
                    )
                else:
                    raise AdapterError(
                        f"{action} is not supported by this adapter", code="unsupported_operation"
                    )
            except AdapterError as exc:
                if exc.code == "not_found":
                    self.repo.record_action(
                        request_id=plan["request_id"],
                        item_id=item["item_id"],
                        adapter_id=record["store_id"],
                        operation=action,
                        result="already_absent",
                        error_code=None,
                        started_at=started,
                        finished_at=now_iso(),
                        idempotency_key=idempotency_key,
                    )
                    self.repo.set_item_state(item["item_id"], "already_absent")
                    self.repo.mark_record_deleted(item["record_id"])
                    counts["already_absent"] += 1
                    results.append(
                        {"item_id": item["item_id"], "result": "already_absent", "operation": action}
                    )
                else:
                    self.repo.record_action(
                        request_id=plan["request_id"],
                        item_id=item["item_id"],
                        adapter_id=record["store_id"],
                        operation=action,
                        result="failed",
                        error_code=exc.code,
                        started_at=started,
                        finished_at=now_iso(),
                        idempotency_key=idempotency_key,
                    )
                    self.repo.set_item_state(
                        item["item_id"],
                        "content_changed" if exc.code == "content_changed" else "failed",
                    )
                    counts["failed"] += 1
                    hint = ""
                    lowered = str(exc).lower()
                    if any(
                        word in lowered
                        for word in ("locked", "in use", "being used", "busy", "winerror 32")
                    ):
                        hint = " (store is locked or in use; close the writer and retry)"
                    elif "readonly" in lowered or "read-only" in lowered or "permission" in lowered:
                        hint = " (store is read-only or not writable)"
                    results.append(
                        {
                            "item_id": item["item_id"],
                            "record_id": item["record_id"],
                            "adapter_id": record["store_id"],
                            "operation": action,
                            "result": "failed",
                            "error_code": exc.code,
                            "message": str(exc) + hint,
                        }
                    )
                continue

            self.repo.record_action(
                request_id=plan["request_id"],
                item_id=item["item_id"],
                adapter_id=record["store_id"],
                operation=action,
                result="success",
                error_code=None,
                started_at=started,
                finished_at=now_iso(),
                idempotency_key=idempotency_key,
            )
            self.repo.set_item_state(item["item_id"], "done")
            self.repo.mark_record_deleted(item["record_id"])
            counts["succeeded"] += 1
            results.append(
                {
                    "item_id": item["item_id"],
                    "record_id": item["record_id"],
                    "adapter_id": record["store_id"],
                    "operation": action,
                    "result": "success",
                }
            )

        if simulate:
            final_state = plan["state"]
            message = "Dry run only: no destructive operation was performed."
        else:
            actionable = [
                i
                for i in items
                if i["approved"] and i["proposed_action"] in classify.ACTIONABLE
            ]
            if (
                counts["failed"]
                and counts["failed"] >= len(actionable)
                and counts["succeeded"] + counts["already_absent"] == 0
            ):
                final_state = "FAILED"
            elif counts["failed"]:
                final_state = "PARTIAL"
            else:
                final_state = "VERIFYING"
            self.repo.set_plan_state(plan_id, final_state, applied_at=now_iso())
            self.repo.set_request_state(plan["request_id"], final_state)
            message = "Apply completed; run redacto_verify for an honest, scoped result."

        return {
            "ok": True,
            "plan_id": plan_id,
            "request_id": plan["request_id"],
            "plan_version": int(plan["version"]),
            "plan_state": final_state,
            "dry_run": simulate,
            "results": results,
            "counts": counts,
            "review_required": review_required,
            "message": message,
        }

    # ---------------------------------------------------------------- verify
    def verify(
        self,
        *,
        request_id: str | None = None,
        receipt_id: str | None = None,
        stores: Sequence[str] | None = None,
    ) -> dict[str, Any]:
        if receipt_id:
            receipt = self.repo.get_receipt(receipt_id)
            if receipt is None:
                raise RedactoError("unknown_receipt", "No such receipt.", {"receipt_id": receipt_id})
            request_id = receipt["request_id"]
        if not request_id:
            raise RedactoError("invalid_request", "Provide request_id or receipt_id.")
        request = self.repo.get_request(request_id)
        if request is None:
            raise RedactoError("unknown_request", "No such revocation request.", {"request_id": request_id})
        plan = self.repo.latest_plan_for_request(request_id)
        if plan is None:
            raise RedactoError("unknown_plan", "No plan exists for this request.", {"request_id": request_id})

        actions = self.repo.actions_for_request(request_id)
        real_actions = [a for a in actions if a["result"] != "dry_run"]
        if plan["state"] in {"READY_FOR_APPROVAL", "APPROVED"} and not real_actions:
            raise RedactoError(
                "plan_not_applied",
                "Nothing has been applied yet; verification would be meaningless.",
                {"plan_state": plan["state"]},
            )

        scope_stores = list(plan["scope"].get("stores", []))
        if stores is None or len(stores) == 0:
            verify_stores = scope_stores
        else:
            unknown = [s for s in stores if s not in scope_stores]
            if unknown:
                raise RedactoError(
                    "out_of_scope_store",
                    "Verification can only cover stores inside the approved plan scope.",
                    {"outside_scope": unknown, "plan_scope": scope_stores},
                )
            verify_stores = list(dict.fromkeys(stores))
        partial_scope = set(verify_stores) != set(scope_stores)

        items = self.repo.plan_items(plan["plan_id"])
        planned_removals = {
            item["record_id"]
            for item in items
            if item["approved"] and item["proposed_action"] in classify.ACTIONABLE
        }
        target_record = self.repo.get_record(request["target_id"])
        if request["target_kind"] in {"fact", "secret"}:
            # Verify the value itself. The anchor record is only a lookup handle and
            # its own fingerprint must not be treated as the target.
            target_fingerprint = request.get("target_fingerprint")
        else:
            target_fingerprint = target_record["fingerprint"] if target_record else None
        # Fact/secret revocation must be verified against the value itself, not the
        # anchor record: a secret written back into any store is a residual.
        secret_tokens = (
            set(request.get("target_tokens", []))
            if request["target_kind"] in {"fact", "secret"}
            else set()
        )
        normalized_len = request.get("target_normalized_len")
        target_key_version = (
            request.get("target_key_version")
            or (target_record or {}).get("fingerprint_key_version")
            # Legacy material predates versioning and was produced with version 1.
            or 1
        )
        verify_key = self.settings.key_for_version(target_key_version)
        if target_fingerprint and verify_key is None:
            # Cannot evaluate residuals honestly without the key that produced them.
            target_fingerprint = None
            key_unavailable = True
        else:
            key_unavailable = False

        slots = self.adapters()
        store_results: list[dict[str, Any]] = []
        residual_total = 0
        seen_temp_files: set[str] = set()

        for store in verify_stores:
            slot = slots.get(store)
            checked_at = now_iso()
            if slot is None or slot.adapter is None:
                limitations = [
                    slot.unavailable_reason if slot else "store is not configured",
                    "Store could not be rescanned, so absence is not claimed.",
                ]
                self.repo.add_verification(
                    request_id=request_id,
                    adapter_id=store,
                    method="rescan",
                    outcome="unreachable",
                    residual_count=0,
                    limitations=limitations,
                    checked_at=checked_at,
                )
                store_results.append(
                    {"store_id": store, "outcome": "unreachable", "residual_count": 0, "limitations": limitations}
                )
                continue
            limit = self.settings.max_scan_records
            try:
                records = list(slot.adapter.list_records(limit=limit + 1))
            except AdapterError as exc:
                limitations = [f"rescan failed: {exc.code}"]
                self.repo.add_verification(
                    request_id=request_id,
                    adapter_id=store,
                    method="rescan",
                    outcome="not_verifiable",
                    residual_count=0,
                    limitations=limitations,
                    checked_at=checked_at,
                )
                store_results.append(
                    {
                        "store_id": store,
                        "outcome": "not_verifiable",
                        "residual_count": 0,
                        "limitations": limitations,
                    }
                )
                continue

            truncated = len(records) > limit
            if truncated:
                records = records[:limit]
            residuals: list[str] = []
            for record in records:
                if record.record_id in planned_removals:
                    residuals.append(record.record_id)
                    continue
                if target_fingerprint and verify_key and fingerprint(
                    record.content, verify_key
                ) == target_fingerprint:
                    residuals.append(record.record_id)
                    continue
                if secret_tokens and verify_key:
                    record_tokens = {
                        fingerprint(token_value, verify_key)
                        for token_value in token_set(record.content)
                    }
                    if secret_tokens.issubset(record_tokens):
                        residuals.append(record.record_id)
                        continue
                if (
                    target_fingerprint
                    and verify_key
                    and request["target_kind"] in {"fact", "secret"}
                    and normalized_len
                    and normalized_len >= MIN_VERIFIABLE_VALUE_LEN
                ):
                    if contains_normalized(
                        record.content, target_fingerprint, normalized_len, verify_key
                    ):
                        residuals.append(record.record_id)
            # A temp copy left by an interrupted rewrite holds the store as it was
            # before the delete. It is not a record, so it cannot be rescanned like
            # one, and absence is never claimed while it exists.
            leftover_temps = [
                path
                for path in slot.adapter.leftover_temp_files()
                if str(path) not in seen_temp_files
            ]
            seen_temp_files.update(str(path) for path in leftover_temps)
            residuals.extend(f"tempfile:{path.name}" for path in leftover_temps)
            residual_total += len(residuals)
            outcome = "verified" if not residuals else "residual"
            if key_unavailable or truncated:
                outcome = "not_verifiable"
            limitations = [
                "Rescan checks planned record IDs and exact/normalized copies of the target content.",
                "Paraphrased remnants cannot be proven absent by this method.",
            ]
            if request["target_kind"] in {"fact", "secret"}:
                limitations.append(
                    "Fact/secret verification rescans every reachable store for the value's "
                    "distinctive tokens. The value is never stored, so a value embedded inside "
                    "a longer token and reworded traces are not proven absent."
                )
            if truncated:
                limitations.append(
                    f"Record cap reached ({limit}); some records were not rescanned and "
                    "absence is not claimed for them."
                )
            if leftover_temps:
                limitations.append(
                    "Leftover temp copies of this store from an interrupted rewrite may hold "
                    "the revoked content; delete them and verify again: "
                    + ", ".join(str(path) for path in leftover_temps)
                )
            if key_unavailable:
                limitations.append(
                    "The HMAC key version that produced this target fingerprint is unavailable; "
                    "content fingerprints were not verified."
                )
            self.repo.add_verification(
                request_id=request_id,
                adapter_id=store,
                method="rescan",
                outcome=outcome,
                residual_count=len(residuals),
                limitations=limitations,
                checked_at=checked_at,
            )
            store_results.append(
                {
                    "store_id": store,
                    "outcome": outcome,
                    "residual_count": len(residuals),
                    "residual_record_ids": residuals,
                    "records_scanned": len(records),
                    "truncated": truncated,
                    "limit": limit,
                    "limitations": limitations,
                }
            )

        succeeded = sum(1 for a in real_actions if a["result"] == "success")
        already_absent = sum(1 for a in real_actions if a["result"] == "already_absent")
        failed = sum(1 for a in real_actions if a["result"] == "failed")
        dry_run_actions = sum(1 for a in actions if a["result"] == "dry_run")
        review_pending = sum(1 for item in items if item["proposed_action"] == classify.REVIEW_REQUIRED)
        preserved = sum(1 for item in items if item["proposed_action"] == classify.SKIP_PRESERVE)
        unreachable_stores = [s["store_id"] for s in store_results if s["outcome"] == "unreachable"]
        not_verifiable = [s["store_id"] for s in store_results if s["outcome"] == "not_verifiable"]

        if failed or residual_total or unreachable_stores or not_verifiable or partial_scope:
            status = "PARTIAL"
        elif review_pending:
            status = "NEEDS_REVIEW"
        elif succeeded + already_absent == 0 and dry_run_actions:
            raise RedactoError("plan_not_applied", "Only a dry run exists; nothing was applied.")
        else:
            status = "VERIFIED_WITHIN_SCOPE"

        limitations = list(GLOBAL_VERIFICATION_LIMITATIONS)
        if partial_scope:
            limitations.append(
                "Verification was limited to a subset of the approved scope: "
                + ", ".join(verify_stores)
            )
        if unreachable_stores:
            limitations.append("Unreachable stores, not verified: " + ", ".join(unreachable_stores))
        if not_verifiable:
            limitations.append("Stores that could not be verified: " + ", ".join(not_verifiable))
        truncated_stores = [s["store_id"] for s in store_results if s.get("truncated")]
        if truncated_stores:
            limitations.append(
                "Record cap reached in stores: "
                + ", ".join(truncated_stores)
                + "; unscanned records are not proven absent."
            )
        if key_unavailable:
            limitations.append(
                f"The HMAC key version {target_key_version} that produced the target "
                "fingerprint is unavailable; exact-copy residuals were not verified."
            )

        # Activate the tombstone only after a real apply. Source revocation needs the
        # target itself gone; fact/secret revocation guards the value even if it was
        # absent from every store at apply time.
        tombstone = None
        applied_plan = plan["state"] not in {"READY_FOR_APPROVAL", "APPROVED"}
        if status != "FAILED" and applied_plan:
            target_removed = any(
                item["record_id"] == request["target_id"]
                and item["state"] in {"done", "already_absent"}
                for item in items
            )
            if request["target_kind"] in {"fact", "secret"} or (
                target_removed and (succeeded + already_absent) > 0
            ):
                tombstone = self.activate_tombstones(request_id, plan["plan_id"])
        if tombstone is not None:
            limitations.append(
                "An active tombstone blocks re-ingestion of exact and near copies; paraphrased "
                "remnants remain a review risk."
            )

        summary = {
            "receipt_version": RECEIPT_VERSION,
            "request_id": request_id,
            "plan_id": plan["plan_id"],
            "plan_version": int(plan["version"]),
            "mode": request["mode"],
            "target": request["target_id"],
            "target_kind": request["target_kind"],
            "status": status,
            "counts": {
                "records_removed": succeeded,
                "already_absent": already_absent,
                "failed": failed,
                "review_pending": review_pending,
                "preserved": preserved,
                "residual_matches": residual_total,
            },
            "scope": {"stores": scope_stores, "verified_stores": verify_stores, "max_depth": plan["scope"].get("max_depth")},
            "stores": store_results,
            "unreachable_stores": unreachable_stores,
            "limitations": limitations,
            "model": request["policy"].get("model", {}),
            "approved_by": "application-issued-approval",
            "physical_overwrite": {
                "sqlite": "deleted rows overwritten in place (PRAGMA secure_delete=ON); WAL checkpoint attempted",
                "jsonl_vector": "files rewritten atomically with the original permission mode",
                "filesystem": "files unlinked, not overwritten",
                "note": "This receipt is evidence metadata, not proof that every copy is physically overwritten.",
            },
            "tombstone": self._tombstone_public(tombstone),
            "checked_at": now_iso(),
            "statement": _statement_for(status, review_pending, unreachable_stores, not_verifiable),
        }
        receipt_id = self.repo.save_receipt(request_id=request_id, summary=summary)
        self.repo.set_plan_state(plan["plan_id"], status)
        self.repo.set_request_state(request_id, status)

        return {
            "ok": True,
            "receipt_id": receipt_id,
            "request_id": request_id,
            "status": status,
            "counts": summary["counts"],
            "stores": store_results,
            "unreachable_stores": unreachable_stores,
            "limitations": limitations,
            "tombstone": self._tombstone_public(tombstone),
            "statement": summary["statement"],
            "receipt": summary,
        }
