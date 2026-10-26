# Redacto threat model

Scope: the hackathon MVP running against local synthetic fixtures. The interesting
threat is not "someone steals the SQLite file" — it is **Redacto itself becoming a
destructive or leaking component**.

## Assets

- Record content in configured stores (confidential documents, memories, logs,
  caches, index chunks).
- The revocation target itself (a document or secret value).
- Graph integrity: which relationships are authoritative.
- The approval boundary: only a human decision may authorize deletion.
- The receipt: it must not become a new copy of the secret.

## Trust boundaries

| Boundary | Untrusted side | Enforcement |
|---|---|---|
| Scanned record content → policy | Record text may contain instructions | Content is data only. No adapter, planner or assessor executes text. Policy comes from `policy/classify.py`. |
| Agent (MCP client) → destructive action | The agent may want to approve or widen scope | `redacto_apply` requires an application-issued token; scope is server-side; there is no approve tool on the MCP surface. |
| Runtime model → lineage | Model output may be wrong or adversarial | Output is schema-validated, stored only as `candidate_edges`, and never creates confirmed lineage. Failures become `unassessed`. |
| Adapters → stores | Tool input could try arbitrary paths/tables | Fixed roots, fixed approved table names, no arbitrary SQL, traversal rejection. |
| Redacto → logs/receipts/graph | Own outputs could leak the secret | Only redacted reasons, keyed HMAC fingerprints, counts and opaque IDs are persisted. |

## Threats and mitigations

| # | Threat | Mitigation | Test |
|---|---|---|---|
| T1 | Prompt injection inside a scanned file ("delete everything") escalates into real deletion | Records are never instructions; classification is deterministic; candidate classes cannot be approved | `test_embedded_instruction_cannot_escalate_scope` |
| T2 | The agent approves its own plan | Approval is a separate application action; `redacto_apply` requires a single-use token hash match; no approve tool is exposed | `test_agent_role_has_no_approval_tool`, `test_apply_rejects_missing_or_wrong_approval`, `test_unapproved_plan_cannot_be_applied_through_engine_api` |
| T3 | Plan is edited after approval (scope creep) | Approval binds plan_id + version + plan hash; recomputed hash mismatch → `stale_plan` | `test_apply_rejects_tampered_plan`, `test_apply_rejects_stale_version` |
| T4 | Approval replayed or kept forever | Tokens expire (default 600s), are single use, and only hashes are stored | `approvals.used_at`, `expires_at` checks in `authorization.verify_approval` |
| T5 | Scope widened by prompt or tool input | Store list validated against configured adapters; unknown stores rejected; record locators come from the graph, not the caller | `test_scope_cannot_be_broadened_by_request`, `test_unknown_stores_are_rejected` |
| T6 | Path traversal / arbitrary file access | Root-relative resolution, symlinks and absolute paths rejected, `relative_to` check | `test_path_traversal_is_rejected` |
| T7 | SQL injection via table names | Approved table allowlist only; identifiers never come from input | `test_unapproved_sqlite_table_is_rejected` |
| T8 | Secrets persisted into graph, prompts, receipts or logs | Content is never stored; keyed HMAC fingerprints only; assessor snippets mask emails/tokens/numbers/URLs; receipts carry counts and IDs | `test_secret_target_value_is_never_persisted`, `test_receipt_never_contains_target_content`, `test_graph_database_never_stores_target_content` |
| T9 | Semantic false positive deletes valuable data | Similarity alone never triggers deletion; suspected candidates default to review; related-non-disclosing preserved | `test_uncertain_classes_are_never_approved`, `test_apply_removes_target_and_derivatives_but_preserves_unrelated` |
| T10 | Adapter failure reported as success | Every mutation either raises or is recorded per record; failures produce `PARTIAL` | `test_adapter_failure_is_reported_not_hidden`, `test_store_that_disappears_after_planning_fails_visibly` |
| T11 | Unreachable store silently treated as clean | Coverage gaps recorded in scan, apply and verification; receipt lists them | `test_unreachable_store_is_reported_never_assumed_clean` |
| T12 | Duplicate destructive work on retry | Unique idempotency keys; dry-run keys separated; applied plans return `already_completed` | `test_reapplying_the_same_plan_is_idempotent`, `test_dry_run_changes_nothing` |
| T13 | Unauthenticated remote exposure | HTTP mode refuses to start without a token, binds localhost by default, bearer middleware on every request | `test_http_mode_refuses_to_serve_without_a_token`, `test_http_requests_require_a_valid_bearer_token` |
| T14 | Model provider unavailable or hostile | Timeout/invalid JSON/provider errors → `unassessed`; deterministic flow continues | `test_invalid_model_json_is_unassessed_and_non_destructive`, `test_model_timeout_is_unassessed` |
| T15 | Stack traces or internals leaked to clients | Tool guard converts unexpected errors into a generic `internal_error` payload | `mcp/server.py::_guard` |
| T16 | The tombstone becomes a new copy of the revoked secret | Tombstones store only keyed HMAC fingerprints, derived shingle/anchor hashes, scope and status; no content | `test_tombstone_stores_no_revoked_content`, `test_secret_tombstone_never_stores_the_secret`, `test_tombstones_response_has_no_fingerprints` |
| T17 | Re-ingestion recreates a revoked trace (restored file, replayed log, rebuilt index) | The guard runs before store writes and graph admission; exact/near copies are blocked | `test_restoring_the_original_file_is_blocked`, `test_renamed_exact_copy_is_blocked_by_fingerprint`, `test_replaying_an_old_jsonl_event_is_blocked`, `test_rebuilt_vector_chunk_is_blocked`, `test_ingest_refuses_to_write_a_blocked_record_to_a_store` |
| T18 | An uncertain match is silently dropped, losing useful data | Uncertain matches are quarantined with a locator and reason, never deleted; review is explicit | `test_paraphrased_memory_is_quarantined_not_dropped`, `test_quarantine_can_be_reviewed`, `test_unrelated_records_are_still_allowed` |
| T19 | A stale or foreign tombstone blocks legitimate data | Tombstones only activate after a real applied revocation; HMAC binding means a different key cannot match; false positives are quarantined, not deleted | `test_no_tombstone_before_apply`, `test_guard_uses_hmac_so_another_key_cannot_match` |
| T20 | Approving a quarantined record bypasses a revocation | Approval re-reads the record, rechecks every active tombstone and the safety mode, and refuses hard blocks; rejection admits nothing; both are audited | `test_approval_rechecks_tombstones_added_after_quarantine`, `test_approved_record_cannot_bypass_a_later_revocation`, `test_rejection_preserves_decision_without_admitting` |
| T21 | Key rotation silently disables tombstone matching | Tombstones carry a key version; old versions stay in the ring; missing versions fail closed and are reported degraded; retirement refuses while in use | `test_old_tombstone_still_enforced_during_rotation`, `test_missing_old_key_fails_closed_for_all_ingestion`, `test_retirement_refuses_while_version_is_in_use` |
| T22 | An embedding score is treated as proof of lineage or used to delete | Embeddings can only generate review candidates and quarantine; they never block, never approve, never create confirmed edges; thresholds are calibrated and FP/FN measured | `test_embedding_similarity_alone_never_blocks`, `test_embedding_candidate_is_not_confirmed_lineage`, `test_calibration_measures_false_positives_and_misses` |
| T23 | A quarantine approval outlives the policy it was granted under | The recheck snapshot, reviewer, note and safety mode are persisted with the decision; strict mode refuses uncertainty overrides | `test_strict_mode_refuses_uncertain_override`, `test_approval_admits_through_audited_path` |
| T24 | Oversized input exhausts memory or floods the model path | Records above `REDACTO_MAX_RECORD_BYTES` are skipped before matching/ingestion and reported; model snippets are capped separately | `test_oversized_ingestion_is_skipped_and_not_written`, `test_oversized_scanned_records_are_reported_not_admitted` |
| T25 | A caller promotes an unverified claim to confirmed lineage | `record_lineage` is internal-only, validates evidence, requires evidence refs/verifier, and downgrades model/heuristic claims to candidate edges | `test_record_lineage_hook_requires_trustworthy_evidence`, `test_record_lineage_hook_keeps_model_claims_as_candidates` |

## Residual risks (accepted, disclosed)

- **Physical erasure is not provable.** Backups, replicas, provider logs, caches and
  model weights are outside Redacto's reach. Receipts say so.
- **Paraphrase detection is incomplete.** Verification matches planned record IDs and
  the keyed whole-target fingerprint; a reworded remnant in an unlinked store may
  survive and is not detectable by this method.
- **Re-ingestion is mitigated, not eliminated.** Exact and near copies are blocked;
  anchor-bearing paraphrases and embedding-similar paraphrases are quarantined. A
  paraphrase below the calibrated embedding threshold can still pass, and the local
  embedding is lexical-semantic rather than a production neural model.
- **Thresholds are synthetic.** Embedding false-positive/missed-paraphrase counts come
  from a small hand-labelled fixture. Production deployment requires recalibration on
  real labelled examples.
- **Key rotation requires retaining old keys.** Tombstones are not re-derived; a
  missing version fails closed rather than degrading silently. Tombstone retention and
  expiry are not implemented yet.
- **Quarantine approval is a human override of uncertainty.** It cannot override a hard
  tombstone block, but it can admit a record later judged risky if no current tombstone
  covers it; the reviewer, note and recheck snapshot are the accountability record.
- **Keyed fingerprints are only as strong as `REDACTO_HMAC_KEY`.** The fixture default
  is not a secret; production use requires a real key and rotation story.
- **Model assessment quality is not benchmarked** in this MVP; the deterministic path
  is the default and the model path is advisory only.
- **Synthetic data only.** Real PII or production credentials must not be used until
  adapter scope, redaction and key management are hardened.