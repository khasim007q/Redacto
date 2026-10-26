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

## Residual risks (accepted, disclosed)

- **Physical erasure is not provable.** Backups, replicas, provider logs, caches and
  model weights are outside Redacto's reach. Receipts say so.
- **Paraphrase detection is incomplete.** Verification matches planned record IDs and
  the keyed whole-target fingerprint; a reworded remnant in an unlinked store may
  survive and is not detectable by this method.
- **Re-ingestion can recreate a trace.** There is no tombstone check on the ingestion
  path yet; this is the highest-value next hardening item.
- **Keyed fingerprints are only as strong as `REDACTO_HMAC_KEY`.** The fixture default
  is not a secret; production use requires a real key and rotation story.
- **Model assessment quality is not benchmarked** in this MVP; the deterministic path
  is the default and the model path is advisory only.
- **Synthetic data only.** Real PII or production credentials must not be used until
  adapter scope, redaction and key management are hardened.