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
| T26 | JSONL delete removes the wrong event when `event_id` is absent | Events without an id use a keyed hash of the line; deletes match that identity and prefer the recorded line | `test_event_without_event_id_is_deleted_by_content_identity` |
| T27 | Two concurrent applies reuse one approval token | Approval consumption is an atomic `UPDATE ... WHERE used_at IS NULL`; only one caller wins | `test_approval_claim_is_atomic`, `test_claimed_token_cannot_be_applied_again` |
| T28 | A malformed log line holding a secret is reported as already gone | Malformed lines are parsed as content and matched by the keyed line identity, so deletion succeeds and is verified | `test_malformed_line_holding_a_secret_is_deleted_not_reported_absent`, `test_plan_apply_deletes_a_malformed_copy_and_counts_it_as_success` |
| T29 | Scan/verify silently stop at the record cap and claim clean | Stores that reach the cap are marked `truncated`; verification becomes `not_verifiable` and the receipt is `PARTIAL` | `test_scan_reports_stores_cut_off_by_the_record_cap`, `test_verification_is_partial_when_the_record_cap_is_reached` |
| T30 | A tiny match deletes a mostly useful record | Plans expose size/match share/risk; substring matches are review-only; low overlap raises risk to high | `tests/test_hardening_collateral.py` |
| T31 | A verbatim leak is labelled non-disclosing | Source scans detect 8-word shared passages and classify them as suspected derivatives for review | `test_verbatim_sentence_inside_other_notes_is_never_nondisclosing` |
| T32 | A crashed apply is unrecoverable because its token was consumed | Re-approving an `EXECUTING` plan issues a new single-use token; completed actions are skipped by idempotency | `test_crashed_executing_plan_can_be_reapproved_and_resumed` |
| T33 | A review item can never be actioned, so a leaked key survives | `review-item` is an application action that rewrites the item to a concrete action and bumps the plan version for fresh approval | `test_review_item_approval_requires_a_new_plan_version_and_token`, `test_review_item_rejection_keeps_the_item_unapproved` |
| T34 | Spacing a secret evades exact matching | Secrets also match a separator-insensitive compact variant; the match remains review/delete by coverage, never automatic approval of unrelated content | `test_spaced_secret_is_detected_by_compact_variant`, `test_spaced_secret_file_is_a_direct_match` |
| T35 | A non-ASCII bearer header crashes the HTTP server | Header and token are compared as UTF-8 bytes; malformed headers return 401 | `test_non_ascii_bearer_is_rejected_not_a_500` |
| T36 | Key rotation loses protection for old derivative fingerprints | Related fingerprints store their producing key version; the guard evaluates each version and fails closed if one is missing | `test_related_fingerprints_are_versioned_across_rotation`, `test_missing_related_key_version_fails_closed` |
| T37 | An assessor exception escapes and breaks a scan | The assessor catches unexpected exceptions and returns unassessed; non-HTTP provider URLs are disabled | `test_assessor_unexpected_exception_is_unassessed`, `test_non_http_assessor_url_is_disabled` |
| T38 | The model prompt receives the secret target | Secret targets skip model assessment entirely; fact candidates use minimized snippets with long values masked | `test_assessor_request_never_contains_the_secret` |
| T39 | A failed apply strands the revocation | FAILED plans can be re-approved; failed action rows are cleared and retried, while successful rows are skipped | `test_failed_plan_can_be_reapproved_and_resumed`, `test_recorded_failed_actions_are_retried_after_failed_plan` |
| T40 | A cancelled plan can still be applied | Apply rejects CANCELLED with `plan_cancelled` instead of reporting already applied | `test_cancel_plan_prevents_approval_and_apply` |
| T41 | A broken key ring crashes status | Adapter construction catches keyring errors; status reports `protection_degraded` and the MCP status tool returns structured data | `test_status_survives_a_broken_key_ring`, `test_broken_keyring_status_does_not_crash` |
| T42 | Non-canonical key versions collide | Key versions must be canonical integers; leading zeros/signs and duplicate versions are rejected | `test_non_canonical_key_versions_are_rejected` |
| T43 | A raising custom assessor breaks a scan | Assessor construction and invocation are both guarded; failures become `unassessed` | `test_engine_guards_a_raising_custom_assessor` |
| T44 | A file rewritten after planning is deleted during apply | Plan items store a content fingerprint; apply re-reads and refuses with `content_changed` | `test_changed_content_is_not_deleted_on_apply` |
| T45 | Two recovery tokens both report the same work | Apply takes an exclusive DB lease; the loser gets `apply_in_progress` | `test_plan_execution_lease_is_exclusive`, `test_concurrent_recovery_tokens_cannot_both_report_the_work` |
| T46 | A hard-killed apply leaves a lease behind | The lease records owner PID/host; recovery clears it only when the owner is gone or the lease is older than 15 minutes | `test_recovery_approval_clears_a_stale_execution_lease`, `test_recovery_clears_a_lease_whose_owner_pid_is_gone` |
| T47 | A second person "recovers" a plan that is still running | Recovery approval refuses while the lease owner is alive (`apply_in_progress`) | `test_recovery_approval_refuses_a_live_lease` |
| T48 | A forged token holds the lease and blocks a real apply | The approval token is verified before the lease is claimed; forged tokens never take it | `test_forged_token_never_takes_the_lease` |
| T49 | Content changes between the re-check and the delete | Verification moved into the mutation: SQLite verifies under a write lock, the filesystem adapter re-reads and re-stats before unlink | `test_sqlite_adapter_verifies_fingerprint_atomically`, `test_filesystem_adapter_verifies_fingerprint` |
| T50 | A secret revocation deletes the anchor that never held the secret | The anchor no longer matches by identity; only records containing the value are actionable | `test_secret_anchor_without_the_secret_is_not_deleted`, `test_secret_journey_removes_secret_but_keeps_anchor` |
| T51 | Verify says clean while the secret is still in a store | Fact/secret verification rescans every reachable store for the value's tokens and reports residuals | `test_secret_written_back_before_verify_is_reported`, `test_secret_verify_catches_a_reintroduced_secret_even_when_planned_records_are_gone` |
| T52 | A secret hides in a nested tool-call argument or chunk metadata | Logs and vector chunks are matched over every string field, recursively | `test_secret_is_found_in_log_tool_arguments`, `test_secret_is_found_in_vector_metadata` |
| T53 | A reworded note with the price and closing date is labelled harmless | Weighted anchor overlap >= 4 escalates to suspected derivative for review | `test_price_and_closing_date_note_goes_to_review` |
| T54 | Deleted content survives in SQLite free pages or the WAL | `PRAGMA secure_delete=ON` plus a WAL truncate checkpoint attempt | `test_sqlite_uses_secure_delete_and_checkpoints` |
| T55 | A rewrite silently changes file permissions | Atomic rewrites restore the original mode | `test_jsonl_rewrite_preserves_file_mode`, `test_vector_rewrite_preserves_file_mode` |
| T56 | Unscanned file types create invisible gaps | Status reports unscanned files per adapter; scan documents the gap | `test_status_reports_unscanned_files` |
| T57 | Model snippets leak spelled-out amounts | Snippets mask digit and spelled-out number words | `test_snippet_masks_spelled_out_amounts` |
| T58 | The lease liveness probe interrupts the host on Windows | `OpenProcess`/`GetExitCodeProcess` on Windows; `os.kill(pid, 0)` only on POSIX | `test_liveness_does_not_use_os_kill_on_windows`, `test_posix_path_uses_os_kill` |
| T59 | A process dies after taking the lease but before EXECUTING, stranding the plan | Approval and apply clear a dead owner's lease in any plan state | `test_plan_stuck_before_executing_is_recoverable`, `test_stuck_lease_before_executing_is_cleared_by_approval` |
| T60 | A slow live apply loses its lease to the TTL | A live local owner is never stale; the TTL applies only to unknown hosts | `test_a_slow_live_apply_never_loses_its_lease` |
| T61 | An in-place file edit passes the fingerprint check | Both file identity and size/mtime must match, and content is re-hashed | `test_in_place_edit_with_same_inode_is_refused` |
| T62 | A log line appended during a rewrite is lost | The rewrite re-reads before replacing; an unsettled file raises `delete_conflict` | `test_line_appended_during_rewrite_is_not_lost`, `test_delete_conflict_is_reported_when_the_file_never_settles` |
| T63 | Verify misses `KEY=secret`, `key:secret`, `?token=secret` or a glued secret | Verification uses separator-insensitive windowed matching over the normalized record | `test_verify_flags_config_style_secret`, `test_contains_normalized_matches_config_style_forms` |
| T64 | A small secret mention is stranded after apply | `review-item` is accepted on VERIFYING/PARTIAL/NEEDS_REVIEW plans | `test_small_secret_mention_waits_for_review_then_verifies_clean` |

## Residual risks (accepted, disclosed)

- **Physical erasure is not provable.** Backups, replicas, provider logs, caches and
  model weights are outside Redacto's reach. Receipts say so.
- **Paraphrase detection is incomplete.** Verification matches planned record IDs and
  the keyed whole-target fingerprint; a reworded remnant in an unlinked store may
  survive and is not detectable by this method.
- **Secret verification is token-based.** The value is never stored, so a value embedded
  inside a longer token, and reworded traces, are not proven absent.
- **Physical removal is best effort.** Files are unlinked, and SQLite secure-delete plus a
  WAL checkpoint can be delayed by another open writer.
- **Unscanned file types.** Only configured extensions under a root are scanned; status
  reports the rest.
- **Provider transcripts are out of reach.** Pasting a secret into an agent conversation
  creates a copy at the provider.
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