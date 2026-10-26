"""Transport-independent Redacto engine.

All MCP tools, the CLI and the demo call this class, so scope checks, policy and
authorization cannot be bypassed by a different entry point.
"""

from __future__ import annotations

from typing import Any, Sequence

from redacto.adapters.base import AdapterError, Record
from redacto.adapters.registry import AdapterSlot, build_adapters
from redacto.config import Settings, load_settings
from redacto.discovery.exact import ExactMatcher, shares_entity
from redacto.discovery.normalization import fingerprint
from redacto.discovery.relationship_assessor import (
    CandidateContext,
    RelationshipAssessor,
    build_assessor,
    minimize_snippet,
)
from redacto.errors import RedactoError
from redacto.graph.repository import RECEIPT_VERSION, Repository, new_id, now_iso
from redacto.graph.traversal import traverse
from redacto.ingestion import (
    ALLOWED,
    BLOCKED,
    QUARANTINED,
    TombstoneGuard,
    TombstoneMaterial,
    summarize_guard_findings,
)
from redacto.policy import authorization, classify
from redacto.policy.plan import build_plan_items, compute_plan_hash, estimated_impact
from redacto.status import collect_status

TARGET_KINDS = {"source", "fact", "secret"}
MODES = {"source_revocation", "fact_revocation"}
TERMINAL_PLAN_STATES = {
    "EXECUTING",
    "VERIFYING",
    "VERIFIED_WITHIN_SCOPE",
    "PARTIAL",
    "NEEDS_REVIEW",
    "FAILED",
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
]


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
        self.repo = Repository(self.settings.db_path)

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
        if record is None:
            raise RedactoError(
                "unknown_record",
                "The target record is not in the configured provenance graph.",
                {"record_id": record_id},
            )
        return record

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
            fingerprint=fingerprint(record.content, self.settings.hmac_key),
            created_at=record.metadata.get("created_at") or None,
            sensitivity=sensitivity or ["unknown"],
            capabilities=capabilities,
            status="active",
        )

    def guard(self) -> TombstoneGuard:
        """Active tombstones, rebuilt from stored keyed material only."""
        return TombstoneGuard.from_repo(self.repo, self.settings.hmac_key)

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
    ) -> dict[str, Any]:
        action, approved, risk = classify.propose_action(
            record_type=record_type,
            capabilities=capabilities,
            evidence_class=evidence_class,
        )
        return {
            "record_id": record_id,
            "store_id": store_id,
            "record_type": record_type,
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
        record = self._require_record(target_id)
        scope_stores = self._scope_stores(stores)
        target_content = self._target_content(record, target_kind, target_text)

        traversal = traverse(self.repo, target_id, max_depth=depth)
        matcher = ExactMatcher(
            target_text=target_content,
            target_record_id=target_id,
            target_locator=record["locator"],
            target_kind=target_kind,
        )

        slots = self.adapters()
        guard = self.guard()
        guard_findings: list[dict[str, Any]] = []
        guarded_ids: set[str] = set()
        scanned: dict[str, Record] = {}
        coverage: list[dict[str, Any]] = []
        unreachable: list[dict[str, Any]] = []

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
            try:
                records = list(slot.adapter.list_records(limit=self.settings.max_scan_records))
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
            for scanned_record in records:
                scanned[scanned_record.record_id] = scanned_record
            coverage.append(
                {
                    "store_id": store,
                    "status": "scanned",
                    "records_scanned": len(records),
                    "limitations": [],
                }
            )
            caps = self._record_capabilities(store, slot)
            for scanned_record in records:
                # Tombstone guard runs before anything enters the provenance graph.
                decision = guard.evaluate(
                    record_id=scanned_record.record_id, content=scanned_record.content
                )
                if decision.decision != ALLOWED:
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

        for record_id, scanned_record in scanned.items():
            if record_id in guarded_ids:
                # A revoked trace reappearing in a store is reported by the guard,
                # not re-admitted as a fresh candidate.
                continue
            capabilities = self._record_capabilities(scanned_record.store_id, slots[scanned_record.store_id])
            match = matcher.match(scanned_record)
            if match is not None:
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
                )
                continue
            if record_id in descendant_by_id:
                node = descendant_by_id[record_id]
                last_edge = node.via[-1] if node.via else {}
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
                )
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
            )

        model_meta = self._assess_candidates(
            target_id=target_id,
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
                "store_id": record["store_id"],
                "kind": target_kind,
                "label": record["locator"].get("path") or record["locator"].get("id") or record["record_id"],
            },
            "scope": {"stores": scope_stores, "max_depth": depth},
            "candidates": [classify.summarize_candidate(c) | {"confirmed": c["confirmed"], "candidate_only": c["candidate_only"], "relation": c.get("relation")} for c in ordered],
            "counts": counts,
            "coverage": coverage,
            "unreachable_stores": [entry["store_id"] for entry in unreachable],
            "model": model_meta,
            "guard": {
                "active_tombstones": guard.active_count,
                "counts": summarize_guard_findings(guard_findings),
                "findings": guard_findings,
            },
            "limitations": [
                "Scan is read-only with respect to record content; only minimized graph metadata is written.",
                "Semantic candidates stay advisory; unassessed candidates are never destructive.",
                "Records matching an active tombstone are blocked or quarantined and never re-admitted to the graph.",
            ],
        }

    def _assess_candidates(
        self,
        *,
        target_id: str,
        candidates: dict[str, dict[str, Any]],
        scanned: dict[str, Record],
        candidate_edges: dict[str, dict[str, Any]],
        enabled: bool,
    ) -> dict[str, Any]:
        assessor = self.assessor()
        provider_configured = assessor.model_id != "none"
        meta: dict[str, Any] = {
            "provider": self.settings.model_provider,
            "model_id": assessor.model_id,
            "used": False,
            "assessed": 0,
            "unassessed": 0,
            "errors": {},
        }
        if not enabled or not provider_configured:
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
        outcome = assessor.assess(contexts)
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
                "store_id": graph_record.get("store_id"),
                "depth": node.depth,
                "via": node.via,
            }

        return {
            "source": {
                "record_id": record["record_id"],
                "record_type": record["record_type"],
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
        material = TombstoneMaterial.build(target_content, self.settings.hmac_key)
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
        related_fingerprints: list[str] = []
        for record_id in related_ids:
            record = self.repo.get_record(record_id)
            if record and record.get("fingerprint"):
                related_fingerprints.append(record["fingerprint"])

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

        counts = {ALLOWED: 0, BLOCKED: 0, QUARANTINED: 0}
        results: list[dict[str, Any]] = []
        for record in records:
            if store_id is not None and record.store_id != store_id:
                record = record.model_copy(update={"store_id": store_id})
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
        counts = {ALLOWED: 0, BLOCKED: 0, QUARANTINED: 0}
        findings: list[dict[str, Any]] = []
        unreachable: list[dict[str, Any]] = []

        for store in scope_stores:
            slot = slots[store]
            if slot.adapter is None:
                unreachable.append({"store_id": store, "reason": slot.unavailable_reason})
                continue
            try:
                records = list(slot.adapter.list_records(limit=self.settings.max_scan_records))
            except AdapterError as exc:
                unreachable.append({"store_id": store, "reason": f"{exc.code}: {exc}"})
                continue
            capabilities = self._record_capabilities(store, slot)
            for record in records:
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

    def resolve_quarantine(self, *, quarantine_id: str, decision: str) -> dict[str, Any]:
        if decision not in {"approved", "rejected"}:
            raise RedactoError("invalid_decision", "decision must be 'approved' or 'rejected'.")
        self.repo.set_quarantine_status(quarantine_id, decision)
        return {"ok": True, "quarantine_id": quarantine_id, "status": decision}

    # --------------------------------------------------------------- approve
    def approve_plan(self, *, plan_id: str, approval_ref: str, ttl_seconds: int = 600) -> dict[str, Any]:
        try:
            issued = authorization.issue_approval(
                self.repo, plan_id=plan_id, approval_ref=approval_ref, ttl_seconds=ttl_seconds
            )
        except ValueError as exc:
            raise RedactoError(str(exc), f"Approval could not be issued: {exc}") from exc
        return {"ok": True, **issued}

    # ----------------------------------------------------------------- apply
    def apply(
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
            raise RedactoError("unknown_plan", "No such plan.", {"plan_id": plan_id})
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
        slots = self.adapters()
        scope_stores = set(plan["scope"].get("stores", []))
        results: list[dict[str, Any]] = []
        counts = {"succeeded": 0, "already_absent": 0, "failed": 0, "dry_run": 0, "blocked": 0}
        review_required: list[dict[str, Any]] = []

        for item in items:
            action = item["proposed_action"]
            if not item["approved"] or action not in classify.ACTIONABLE:
                state = "preserved" if action == classify.SKIP_PRESERVE else "review_required"
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
                results.append(existing)
                counts["succeeded" if existing["result"] == "success" else existing["result"]] = (
                    counts.get(existing["result"], 0) + 1
                )
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

            try:
                if action == classify.DELETE_RECORD:
                    slot.adapter.delete_record(record["locator"])
                elif action in {classify.INVALIDATE_INDEX, classify.INVALIDATE_CACHE}:
                    slot.adapter.invalidate_derived(record["locator"])
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
                    self.repo.set_item_state(item["item_id"], "failed")
                    counts["failed"] += 1
                    results.append(
                        {
                            "item_id": item["item_id"],
                            "result": "failed",
                            "error_code": exc.code,
                            "message": str(exc),
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

        if approval is not None and not simulate:
            self.repo.mark_approval_used(approval["approval_id"])

        if simulate:
            final_state = plan["state"]
            message = "Dry run only: no destructive operation was performed."
        else:
            final_state = "PARTIAL" if counts["failed"] else "VERIFYING"
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
        target_fingerprint = target_record["fingerprint"] if target_record else None

        slots = self.adapters()
        store_results: list[dict[str, Any]] = []
        residual_total = 0

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
            try:
                records = list(slot.adapter.list_records(limit=self.settings.max_scan_records))
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

            residuals: list[str] = []
            for record in records:
                if record.record_id in planned_removals:
                    residuals.append(record.record_id)
                elif target_fingerprint and fingerprint(
                    record.content, self.settings.hmac_key
                ) == target_fingerprint:
                    residuals.append(record.record_id)
            residual_total += len(residuals)
            outcome = "verified" if not residuals else "residual"
            limitations = [
                "Rescan checks planned record IDs and exact/normalized copies of the target content.",
                "Paraphrased remnants cannot be proven absent by this method.",
            ]
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
