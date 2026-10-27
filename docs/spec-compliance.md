# REDACTO_SPEC compliance audit

Audited against `REDACTO_SPEC.md` v0.1 (26 October 2026). Status values:

- **Compliant** — implemented and exercised by tests or a documented run.
- **Partial** — implemented with a documented deviation or narrower capability.
- **Not implemented** — absent, optional, or an accepted non-goal.
- **N/A** — not required for the MVP.

Test evidence: `python -m pytest` → **233 passed**. Run `redacto evaluate` for the
fixture metrics.

## 1. Executive summary and core rule

**Compliant.** Confirmed lineage, discovery, policy and verification are separate
concerns. Model and embedding signals never create confirmed lineage. The receipt
says "verified within configured scope", not "erased".

## 2. Goals and non-goals

### 2.1 MVP goals

| Goal | Status | Evidence |
|---|---|---|
| 1. End-to-end source revocation | Compliant | `redacto demo`, `test_apply_removes_target_and_derivatives_but_preserves_unrelated` |
| 2. Provenance graph traversal | Compliant | `graph/traversal.py`, `test_graph.py` |
| 3. Historical discovery without lineage | Compliant | candidate edges + embedding candidates, `test_scan_generates_an_embedding_review_candidate` |
| 4. Distinguish confirmed/direct/suspected/unrelated | Compliant | evidence classes, `test_candidates_are_separate_from_lineage` |
| 5. Preview a revocation plan | Compliant | `redacto_plan`, `test_plan_builds_items_and_impact` |
| 6. Explicit approval before execution | Compliant | application token, `test_apply_rejects_missing_or_wrong_approval` |
| 7. Delete/invalidate and verify by rescan | Compliant | apply/verify, receipt tests |
| 8. Small MCP surface + skill | Compliant | 8 tools, `skills/redacto/SKILL.md` |
| 9. Receipt without raw sensitive values | Compliant | `test_receipt_never_contains_target_content` |
| 10. Visible limitations | Compliant | receipt limitations + unreachable stores |

### 2.2 Non-goals

**Compliant.** No universal erasure claim, no model unlearning, no direct Alan
context-graph modification, no production data.

## 3. Product principles

**Compliant.** Evidence before action; lineage separate from candidates; similarity
is not guilt; review by default; configured scope; content minimization; independent
verification; honest states; plan-before-mutation; replaceable model/embedding
providers.

## 4. User journeys

- **Journey A (source revocation): Compliant.** Covered by the demo and tests.
- **Journey B (secret/fact revocation): Partial.** Exact/normalized substring
  matching, HMAC fingerprints, redaction-by-deletion or invalidation. Precise span
  redaction and safe regeneration are not implemented for any adapter.
- **Journey C (ambiguous sibling): Compliant.** Related non-disclosing records are
  preserved; suspected derivatives are review-only.

## 5. Scope and adapters

### 5.1 Sources

**Compliant.** Filesystem, SQLite memories + response cache, JSONL logs, vector
fixture. All scope paths are explicit.

### 5.2 Adapter interface

| Operation | Status | Notes |
|---|---|---|
| `list_records(scope)` | Compliant | `limit` + configured scope |
| `read_record(locator)` | Compliant | adapter-specific, in-scope only |
| `find_exact(fingerprints, variants)` | **Partial** | Matching is centralized in `discovery/exact.py` so normalization/HMAC handling is identical across stores. There is no per-adapter `find_exact` method. |
| `delete_record(locator)` | Compliant | failure raises, never reported as success |
| `redact_record(locator, spans)` | Partial | Interface exists; no adapter claims safe span editing, so it reports unsupported |
| `invalidate_derived(locator)` | Compliant | vector index and cache |
| `verify_absent(target, scope)` | Compliant | implemented per adapter; engine uses a stronger rescan |
| `capabilities()` | Compliant | scan/delete/redact/invalidate/verify |

Adapters reject traversal, out-of-root paths, unapproved tables and unsupported
operations (`test_path_traversal_is_rejected`, `test_unapproved_sqlite_table_is_rejected`).

### 5.3 Future adapters

**N/A.** Not required.

## 6. Provenance graph

- **6.1 Semantics: Compliant.** `READ_FROM` is exposure-only; strong edges require
  instrumented/imported/human-verified evidence.
- **6.2 Node types: Partial.** Stored record types map to spec vocabulary
  (`MEMORY`, `LOG_RECORD`, `INDEX_ENTRY`, `CACHE_ENTRY`, `ARTIFACT`) and the
  scan/trace target is labelled `SOURCE` or `FACT`. `AGENT_RUN` and `STORE` are not
  materialized as graph records.
- **6.3 Relations: Compliant.** Vocabulary is validated in `Engine.record_lineage`;
  `READ_FROM` is weak; `STORED_IN` is not treated as derivation. The fixture seeds a
  subset.
- **6.4 Evidence/status: Compliant.** Only confirmable evidence creates confirmed
  edges; model/heuristic evidence creates candidates.
- **6.5 Minimum metadata: Partial.** Record ID/type/store/locator/fingerprint/timestamps/
  sensitivity/capabilities are stored. `content_version` and aliases are not.
- **6.6 Persistence schema: Compliant with extensions.** Spec tables exist. Extra
  tables: `revocation_plans`, `approvals`, `tombstones`, `ingestion_events`,
  `quarantine` (needed for approval binding, re-ingestion protection and review).

## 7. Discovery and assessment

- **7.1 Deterministic discovery: Compliant.** Record ID, locator, exact/normalized
  content, bounded fact/secret variants, keyed HMAC fingerprints. Aliases are not
  implemented.
- **7.2 Model-assisted discovery: Compliant.** Replaceable `RelationshipAssessor`,
  strict schema, bounded batch, untrusted-content framing, `unassessed` on invalid
  JSON/timeout/provider failure, candidate-only output.
- **7.3 Evidence classes: Compliant.**
- **7.4 Deletion policy: Compliant.** Direct/confirmed actionable; suspected review;
  related preserve; unreachable/unknown reported as `UNREACHABLE`/review.

## 8. Modes and execution

- **8.1 Source revocation: Compliant.**
- **8.2 Fact/secret revocation: Partial.** Only records containing the value are
  actionable; the anchor record is preserved unless it holds the value. A substring
  covering less than half of a record is held for review; at or above half the normal
  delete path applies. Verification rescans stores for the value's tokens. A reviewer
  can approve or reject a review item through `review-item`. No precise `REDACT_SPAN`
  support yet, so the reviewer still chooses whole-record deletion or rejection.
- **8.3 Action types: Partial.** All action names exist. A partial substring match is
  mapped to `REVIEW_REQUIRED`, not an automatic delete. `DELETE_RECORD`,
  `INVALIDATE_INDEX`, `INVALIDATE_CACHE`, `REVIEW_REQUIRED`, `SKIP_PRESERVE` and
  `UNREACHABLE` are used. `REDACT_SPAN` and `REGENERATE_FROM_ALLOWED_SOURCES` are
  defined but unsupported by the current adapters.
- **8.4 State machine: Partial.** `READY_FOR_APPROVAL → APPROVED → EXECUTING →
  VERIFYING → {VERIFIED_WITHIN_SCOPE, PARTIAL, NEEDS_REVIEW}` is implemented and
  `EXECUTING` is set before the first mutation (`test_apply_enters_executing_before_any_mutation`).
  `CANCELLED` is entered by `redacto cancel` before execution, `FAILED` when every
  approved action fails, and an `EXECUTING` plan can be re-approved after a crash.
  There is no editable `DRAFT` stage.
- **8.5 Verification: Compliant with stated limits.** Only configured reachable stores;
  per-store method and limitations; `not_verifiable` when the target key version is
  unavailable; fact/secret requests rescan for the value itself. Physical overwrite and
  provider-side copies remain explicit limitations.

## 9. MCP tool contract

| Tool | Status |
|---|---|
| `redacto_status` | Compliant (adds keyring/embedding health) |
| `redacto_scan` | Compliant (scope, depth, model toggle, coverage, unresolved) |
| `redacto_trace` | Compliant |
| `redacto_plan` | Compliant; policy is fixed rather than caller-supplied |
| `redacto_apply` | Compliant (version + hash + token + scope) |
| `redacto_verify` | Compliant |
| `record_lineage` | Compliant as an internal-only engine hook, not an MCP tool; requires trustworthy evidence |
| Extra read-only tools | `redacto_tombstones`, `redacto_quarantine` |

Safety: no shell/SQL/arbitrary filesystem tools; scope is server-owned; destructive
actions need a separate approval; inputs are validated; secrets are redacted; HTTP
requires a bearer token. Result size is bounded by `REDACTO_MAX_SCAN_RECORDS`
(default 500) and `REDACTO_MAX_RECORD_BYTES` (default 1 MB).

## 10. Skill contract

**Compliant.** `skills/redacto/SKILL.md` covers scan → trace → plan → approval →
apply → verify, candidate vs confirmed language, tombstone/quarantine behaviour,
keyring degradation, and the no-universal-erasure rule.

## 11. Model strategy

**Compliant.** Deterministic policy; runtime model provider configured separately
(OpenAI-compatible); the coding-agent model is not assumed to be an inference API;
invalid output is unassessed; embedding signal is local and replaceable.

## 12. Alan integration

**Partial.** Both MCP transports are verified with real clients (`scripts/mcp_smoke.py`,
`scripts/mcp_http_smoke.py`), server code and connector instructions are ready. The
Alan desktop still reports no enabled agent CLI, and no connector has been registered
from the desktop UI. This is a platform/user action, not a code gap.

## 13. UX requirements

**Partial.** Terminal flow, plan preview, action timeline and JSON/Markdown receipts
exist. Confirmed vs candidate is distinguished by evidence class and `confirmed`/
`candidate_only` flags. There is no dashboard or graph visualization; the spec makes
that optional after engine correctness.

## 14. Security and privacy

**Compliant**, with the following evidence:

- synthetic data only;
- explicit scope, traversal/table rejection;
- untrusted scanned content (embedded instructions preserved, not executed);
- keyed HMAC fingerprints + versioned key ring, fail-closed on missing keys;
- no raw secrets/passages in graph, plans, receipts, logs or model prompts;
- approval token bound to plan version/hash, single use;
- HTTPS? HTTP transport requires bearer auth and localhost bind;
- dry-run default (`REDACTO_DRY_RUN=true`);
- oversized records skipped and reported (`REDACTO_MAX_RECORD_BYTES`);
- record-cap truncation reported in scan and verification;
- JSONL identity stable without `event_id`, malformed lines matched by keyed identity;
- approval consumption is an atomic single-use claim;
- receipt explicitly disclaims universal overwrite.

## 15. Test and evaluation plan

### 15.1 Seeded workspace

**Partial.** The twelve required examples exist as data or tests: source, exact log
duplicate, generated summary, paraphrased memory, vector chunk, cached response,
same-organization note, non-disclosing sibling, confirmed descendant, no-lineage
candidate. Unreachable-store and delete-failure simulations are implemented in tests
(`test_store_that_disappears_after_planning_fails_visibly`,
`test_adapter_failure_is_reported_not_hidden`) rather than as permanent fixtures.

### 15.1a Collateral and hardening regressions

`tests/test_hardening_collateral.py` pins blast-radius fields, partial-match review,
verbatim-passage detection, unrelated-record preservation and dry-run completeness.
`tests/test_jsonl.py` pins stable event identity and malformed-line deletion.
`tests/test_execution.py` pins atomic approval claiming and record-cap reporting.

### 15.2 Required automated tests

All bullets are covered; see `tests/test_graph.py`, `test_discovery.py`,
`test_policy.py`, `test_execution.py`, `test_verification.py`, `test_security.py`,
`test_tombstones.py`, `test_quarantine.py`, `test_key_rotation.py`,
`test_embeddings.py`, `test_evaluation.py`, `test_jsonl.py`,
`test_hardening_collateral.py`, `test_recovery_and_review.py`, `test_packaging.py`,
`test_mcp_tools.py`, `test_transport.py`.

### 15.3 Demo acceptance targets

Compliant on the synthetic fixture: 2/2 direct matches, 5/5 confirmed descendants,
0 destructive actions on review items, 0 unrelated records touched, failures and
unreachable stores visible, receipts omit raw content, one test command and one demo
command.

### 15.4 Evaluation report

**Compliant.** `redacto evaluate` reports:
- direct-match precision/recall (2/2, 1.0/1.0);
- confirmed-descendant coverage (5/5, 1.0);
- semantic candidate precision/recall (2/2, 1.0/1.0);
- preserved-related recall (4/4);
- unrelated records touched (0);
- destructive actions blocked by policy (2);
- model schema validity (not measured while the provider is disabled).

## 16. Recommended stack

**Compliant.** Python 3.12, SQLite, Pydantic, MCP Python SDK, pytest. No extra graph
database or orchestration framework. HTTP uses Starlette/uvicorn.

## 17. Repository layout

**Partial.** The structure is close; `engine.py` and `cli.py` replace `app.py`, and
there is no `dashboard/` (optional). Extra modules: `ingestion.py`, `evaluation.py`,
`discovery/embeddings.py`, `docs/key-rotation.md`.

## 18. Build sequence and backlog

**P0 complete.** P1 is partially complete: embeddings, historical discovery and
tombstone re-ingestion are done; graph visualization and a failure-recovery UI are
not. P2 intentionally deferred (fact-level span redaction, real vector DBs, multi-agent
orchestration, scheduled scans).

## 19. Demo storyboard

**Compliant in content; timing is approximate.** The one-command demo covers the
storyboard, including a `[8]` re-ingestion attack. The documented narration is about
2:15, slightly over the 90–120 second target; it can be shortened by omitting the
optional keyring/calibration segment.

## 20. Definition of done

| Criterion | Status |
|---|---|
| Fresh clone setup documented | Compliant |
| Tests pass in a clean environment | Verified locally (Python 3.12, 112 tests); not re-run from a fresh clone in CI |
| Source-revocation flow end to end | Compliant |
| Confirmed vs candidate stored/displayed separately | Compliant |
| scan/trace/plan do not mutate source records | Compliant |
| apply rejects unapproved/stale/out-of-scope | Compliant |
| seeded unrelated record untouched | Compliant |
| unreachable/failing stores never false success | Compliant |
| receipt scope/limitations without secrets | Compliant |
| MCP usable by a compatible client | Compliant (stdio + HTTP) |
| README/skill/architecture/demo public and complete | Partial: repo is pushed; Alan artifacts are private, and the connector is not registered |

## 21. Risk register

**Addressed.** Model access, connector transport, semantic false positives, missing
lineage, deletion semantics, re-ingestion, receipt leakage, scope creep and API
entitlement are covered in `docs/threat-model.md` and the README limitations.

## 22. Alan setup checklist

Gates 1–3 (MCP smoke test, deterministic tools, skill) are complete. **Gate 0 is
blocked**: the desktop reports no enabled agent CLI, so connector registration must be
done by the user in Alan Settings.

## 23. References

The external links were not fetched during the audit; the product claims do not depend
on them.

## Review follow-up (post-839028c)

Fixed after the readiness review:

- runtime dependency install (`httpx`, `uvicorn` moved to main dependencies);
- README client config now includes `cwd` and `REDACTO_*` paths, plus `.mcp.json` and
  `plugin.json`;
- JSONL stable identity and malformed-line deletion;
- atomic single-use approval claim;
- record-cap truncation reporting in scan and verify;
- OS-independent traversal test plus GitHub Actions CI on Linux and Windows;
- blast-radius fields (`size_bytes`, `matched_bytes`, `match_ratio`, `risk`);
- partial substring matches held for review;
- buried verbatim passages classified as suspected derivatives.

## Second review follow-up

Fixed after the readiness/collateral review:

- crashed `EXECUTING` and failed `FAILED` plan recovery through re-approval;
- `review-item` approval/rejection with plan-version bump and audit;
- partial secret matches above 50% coverage auto-delete; below 50% are reviewable;
- non-ASCII bearer headers return 401 instead of 500;
- separator-insensitive secret matching (spaced secrets);
- current key version cannot be retired; related fingerprints are versioned;
- `CANCELLED` and `FAILED` plan states;
- assessor catches unexpected errors, rejects non-HTTP URLs, and never receives the
  secret target;
- Claude Code plugin layout (`.claude-plugin/plugin.json` + `.mcp.json` with
  `${CLAUDE_PLUGIN_ROOT}` and `uv`), explicitly not validated against Alan.

## Third review follow-up

Fixed after the MVP-readiness review:

- plan items store a plan-time content fingerprint; apply refuses to delete changed or
  unverifiable content (`content_changed` / `content_unverifiable`);
- apply takes an exclusive DB execution lease, so concurrent recovery tokens cannot
  both report the same work; recovery approval clears a stale hard-kill lease;
- a broken key ring now raises `current_key_unavailable`/`keyring_invalid` from scan
  instead of `target_unreachable`.

## Fourth review follow-up (trace completeness)

Fixed after the "does it remove every trace" audit:

- secret revocation no longer deletes the anchor unless it contains the value;
- secret verification rescans every reachable store for the value's tokens instead of the
  anchor's fingerprint;
- log events and vector chunks are matched across every string field, including nested
  tool-call arguments and metadata;
- SQLite secure delete plus WAL truncate checkpoint; receipts describe physical overwrite
  limits; JSONL/vector rewrites preserve file mode;
- unscanned file types under a configured root are reported by status;
- weighted amount/date overlap escalates reworded disclosures to review;
- model snippets mask spelled-out numbers;
- verify-and-delete is atomic per adapter (SQLite write lock, filesystem re-read/re-stat);
- execution leases record owner PID/host, refuse live-owner recovery, and validate the
  token before claiming the lease.

## Fifth review follow-up (Windows CI and lease/verify audit)

- Liveness no longer calls `os.kill(pid, 0)` on Windows (it means Ctrl+C there);
  `OpenProcess` + `GetExitCodeProcess` is used instead.
- A lease left by a process that died before EXECUTING is cleared by approval or apply.
- A live local apply is never stolen by the TTL; the TTL applies only to unknown hosts.
- The filesystem fingerprint check requires both identity and size/mtime, so in-place
  edits are refused.
- The JSONL rewrite re-reads before replacing, so concurrently appended lines survive; an
  unsettled file raises `delete_conflict`.
- Secret verification uses separator-insensitive windowed matching, so `KEY=secret`,
  `key:secret`, `?token=secret` and glued secrets are detected.
- `review-item` is accepted after apply, so a small secret mention held for review can be
  resolved instead of stranding the revocation.

## Remaining deviations worth fixing next

1. Add a per-adapter `find_exact` method if strict interface parity is required.
2. Implement editable `DRAFT` plans (CANCELLED/FAILED transitions are implemented).
3. Implement safe `REDACT_SPAN` editing, regeneration and an undo/trash window.
4. Add a graph visualization that styles confirmed vs candidate edges.
5. Register the Alan connector (user action) and publish the docs/demo publicly.