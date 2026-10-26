# Redacto — Hackathon Product & Technical Specification

**Version:** 0.1 — build-ready MVP plan  
**Prepared:** 26 October 2026  
**Target environment:** Alan AI desktop / local coding agent + MCP-compatible clients  
**Status:** Proposed implementation contract; validate Alan connector transport during setup  
**Working name:** Redacto (name availability has not been cleared)

---

## 1. Executive summary

Redacto is a **provenance-aware revocation engine for AI context**. When a user asks an AI system to forget a document, fact, secret, or other source, Redacto locates known descendants, discovers likely historical traces that were not captured in lineage, previews collateral damage, deletes or invalidates only approved records, and verifies what remains in the data stores it can reach.

The product is not a universal “erase from existence” button. It produces an evidence-backed account of what was removed, what was preserved, what needs review, and what could not be checked.

### Core architectural rule

> **Confirmed provenance establishes known lineage. Discovery finds what lineage missed. Policy determines what may be erased. Verification determines what Redacto can honestly claim was removed.**

The provenance graph is the source of truth for recorded lineage. An open-weight model may propose and explain uncertain relationships, but it may not create authoritative lineage or independently authorize destructive actions.

### Hackathon thesis

Most AI memory systems optimize for remembering useful information. Redacto explores the inverse problem: **how can an AI system safely revoke information that has already propagated through persistent memory, logs, summaries, indexes, caches, and tool outputs?** The differentiator is not fuzzy text deletion alone; it is the combination of lineage, retroactive discovery, collateral-damage analysis, controlled execution, and post-action verification.

---

## 2. Product goals

### 2.1 Goals for the hackathon MVP

1. Demonstrate one end-to-end **source revocation** workflow against a synthetic workspace.
2. Record and traverse a provenance graph connecting source records to generated derivatives.
3. Find historical candidate traces even when lineage is missing.
4. Distinguish confirmed lineage, direct matches, suspected semantic siblings, and unrelated records.
5. Preview a revocation plan before any destructive operation.
6. Require explicit approval before executing destructive actions.
7. Delete/invalidate records from connected demo stores and verify outcomes by rescanning.
8. Expose a small, permission-bounded MCP tool surface and provide a reusable skill describing the safe workflow.
9. Produce an audit receipt that never stores the raw sensitive value or full sensitive passage.
10. Make limitations and unverified stores visible instead of claiming universal deletion.

### 2.2 Non-goals for the first version

- Guaranteeing erasure from every copy, backup, model weight, provider log, or third-party system on the internet.
- Direct modification of Alan’s private/internal context graph or undocumented APIs.
- Automatically deleting every semantically similar record.
- Supporting every database, vector index, observability service, and agent framework.
- Performing model unlearning or removing a fact from a model’s trained weights.
- Scanning real customer data or production secrets in the hackathon demo.
- Unsupervised, autonomous bulk deletion without an approval boundary.
- Full legal certification of GDPR/CCPA or other data-subject deletion compliance.

### 2.3 Primary user

A developer or AI-workflow owner who uses persistent agent context and needs to revoke a document, credential, or sensitive fact while minimizing accidental loss of unrelated knowledge.

---

## 3. Product principles

1. **Evidence before action.** Every candidate has a reason, evidence category, proposed action, and locator.
2. **Lineage is not guesswork.** Instrumented or otherwise verified source-to-output relationships are separated from model-inferred candidates.
3. **Similarity is not guilt.** A semantic similarity score alone must never trigger deletion.
4. **Default to review for uncertainty.** Ambiguous descendants or facts are held for review unless an explicit policy says otherwise.
5. **Least privilege.** Adapters may only access configured paths/tables/indexes. No unrestricted filesystem or database access.
6. **Minimize sensitive data.** Do not copy full secrets into the graph, model prompts, logs, or receipts when an ID, keyed fingerprint, redacted snippet, or fact label suffices.
7. **Verify independently.** A successful delete API response is not the same as verified absence. Rescan and report adapter limitations.
8. **Honest completion states.** Use `verified_within_scope`, `partial`, `needs_review`, and `failed`; never claim universal erasure.
9. **Recoverable operations.** Generate a plan before mutation; support dry run; record per-record outcomes; retry only safe idempotent operations.
10. **Open models are replaceable.** Model calls sit behind an interface; model output is advisory and schema-validated.

---

## 4. Core user journeys

### Journey A — Revoke a source document (MVP priority)

User: “Forget everything derived from `acquisition-plan.md`, including agent memories and generated summaries. Preserve unrelated engineering knowledge.”

1. Resolve the target source by ID/path and show an unambiguous target summary.
2. Run deterministic search across configured stores.
3. Traverse confirmed lineage descendants.
4. Run historical candidate discovery for stores/records without lineage.
5. Classify results:
   - Direct match
   - Confirmed lineage descendant
   - Suspected semantic sibling
   - Unrelated / insufficient evidence
   - Unreachable / not scannable
6. Produce a revocation plan with each record, the evidence, a proposed action, and a collateral-risk note.
7. Require explicit user approval for the plan; ambiguous candidates remain excluded unless individually approved.
8. Delete direct copies; delete or safely regenerate derivatives; invalidate associated index/cache entries.
9. Rescan all reachable configured stores and report residuals.
10. Return a receipt with counts, outcomes, gaps, and a receipt ID—not the sensitive raw content.

### Journey B — Revoke an exact secret (limited second path)

User: “Remove this API key from my test workspace.”

- Store the target in memory only for the duration of the scan where possible.
- Create exact/normalized variants in a bounded matcher.
- Store only a keyed HMAC fingerprint for future matching; do not log the key.
- Find direct occurrences, then review related records that may expose the same credential.
- Redact or delete by adapter capability; invalidate derivatives.
- Verify by re-scanning; report inaccessible stores.

This path is a stretch goal after Journey A works.

### Journey C — Ambiguous sibling

A record mentions the same company as the target but does not reveal confidential information. Redacto marks it as a candidate only if evidence supports possible disclosure, shows why, and preserves it by default. It must not delete the record simply because its embedding is close to the target.

---

## 5. Scope and store adapters

### 5.1 MVP data sources

Use a local synthetic workspace with four adapters:

1. **Filesystem adapter:** Markdown documents and generated text files inside an explicitly configured root.
2. **SQLite adapter:** agent-memory-like records with stable IDs and metadata.
3. **JSONL log adapter:** synthetic conversation/tool logs, one event per line.
4. **Vector-index fixture adapter:** a small local JSON/SQLite representation of chunks and metadata; real vector-store integrations are not required for the initial demo.

Each adapter must implement the same interface and return a capability declaration.

### 5.2 Adapter interface

Required operations:

- `list_records(scope)` — enumerate only records within configured scope.
- `read_record(locator)` — return content transiently for matching, with redaction/minimization as soon as possible.
- `find_exact(fingerprints, variants)` — identify direct matches where possible.
- `delete_record(locator)` — delete an in-scope record if supported.
- `redact_record(locator, spans)` — optional; report unsupported if safe editing cannot be guaranteed.
- `invalidate_derived(locator)` — invalidate dependent index/cache entries where supported.
- `verify_absent(target, scope)` — recheck for direct matches and report method/limitations.
- `capabilities()` — enumerate scan/delete/redact/invalidate/verification support.

Adapters must reject path traversal, out-of-root paths, unapproved tables, and unsupported operations. A failed delete must not be reported as successful.

### 5.3 Future adapters (not needed to win the demo)

- Redis or other caches
- Real vector databases
- OpenTelemetry / observability logs
- Git history and build artifacts
- Hosted agent-memory APIs
- Cloud object stores
- Additional MCP servers

---

## 6. Provenance graph

### 6.1 Graph semantics

A directed edge goes **from an upstream source to a downstream record that may depend on it**. Every edge has a relation, evidence type, confidence/quality metadata, and status.

Do not treat “the agent read this document” as proof that every later output was derived from it. `READ_FROM` indicates possible exposure. `DERIVED_FROM` indicates a specific dependency established by instrumentation, an explicit transformation record, or human-verified evidence.

### 6.2 Node types

- `SOURCE` — original document, secret, or other revocation target.
- `FACT` — extracted structured fact or secret identifier.
- `AGENT_RUN` — session or process that read/transformed content.
- `MEMORY` — persistent agent memory entry.
- `ARTIFACT` — summary, report, generated file, or tool output.
- `LOG_RECORD` — conversation, action, or observability event.
- `INDEX_ENTRY` — searchable chunk or embedding metadata.
- `CACHE_ENTRY` — cached response or content.
- `STORE` — logical storage backend.

### 6.3 Edge relations

- `READ_FROM` — exposure/access relation; weak evidence of downstream content.
- `DERIVED_FROM` — output was generated using the source as an input.
- `EXTRACTED_FROM` — a fact was extracted from a source.
- `SUMMARIZED_FROM` — summary created from source material.
- `INDEXED_AS` — source/record content was represented as an index entry.
- `CACHED_AS` — content/result stored as a cache entry.
- `STORED_IN` — record resides in a logical store.
- `REGENERATED_FROM` — replacement generated using a permitted source set.

### 6.4 Edge evidence/status

Evidence types:
- `instrumented` — written by an ingestion/transformation hook that knows the input/output IDs.
- `imported_metadata` — derived from explicit existing metadata or a connector-provided lineage record.
- `human_verified` — reviewed and confirmed by a person.
- `model_inferred` — a model proposed a relationship; it is never authoritative on its own.
- `heuristic_match` — deterministic pattern/metadata signal.

Statuses:
- `confirmed`
- `candidate`
- `rejected`
- `revoked`

Only `instrumented`, `imported_metadata` with adequate evidence, or `human_verified` edges can be confirmed by policy. Model inference alone creates `candidate` edges.

### 6.5 Minimum node metadata

- `record_id` — opaque stable ID.
- `record_type`
- `store_id`
- `locator` — adapter-specific opaque location; avoid embedding raw content.
- `fingerprint` — keyed HMAC where useful; do not use unsalted raw hashes for low-entropy secrets.
- `created_at`, `observed_at`
- `sensitivity_labels` — e.g. `confidential`, `credential`, `pii`, or `unknown`.
- `content_version` or adapter version when available.
- `deletion_capability` / `verification_capability`
- `metadata` — strictly minimized and schema-validated.

### 6.6 Persistence schema (SQLite baseline)

Recommended tables:

- `records(record_id PRIMARY KEY, record_type, store_id, locator_json, fingerprint, created_at, observed_at, sensitivity_json, capabilities_json, status)`
- `lineage_edges(edge_id PRIMARY KEY, source_id, target_id, relation, evidence_type, evidence_ref, status, created_at, verified_by)`
- `candidate_edges(candidate_id PRIMARY KEY, source_id, target_id, relation_guess, evidence_summary_redacted, model_id, confidence, status, reviewed_by, created_at)`
- `revocation_requests(request_id PRIMARY KEY, target_id, target_kind, scope_json, policy_json, state, created_at, approved_at, approved_by)`
- `revocation_plan_items(item_id PRIMARY KEY, request_id, record_id, evidence_class, proposed_action, reason_redacted, risk, approved, state)`
- `actions(action_id PRIMARY KEY, request_id, item_id, adapter_id, operation, result, error_code, started_at, finished_at, idempotency_key)`
- `verification_runs(verification_id PRIMARY KEY, request_id, adapter_id, method, outcome, residual_count, limitations_json, checked_at)`
- `receipts(receipt_id PRIMARY KEY, request_id, summary_json, created_at, receipt_version)`

Never store the full target text, full matched passages, API keys, or complete sensitive model prompts in these tables. Store opaque evidence references and redacted summaries.

---

## 7. Trace discovery and relationship assessment

### 7.1 Deterministic discovery (always runs first)

1. Resolve the target to an approved source ID or a narrowly scoped content target.
2. Match exact record IDs, filenames/paths, known aliases, exact contents, and normalized variants.
3. For secrets, use keyed fingerprints (HMAC) and short-lived in-memory comparisons; avoid persistent raw values.
4. Traverse confirmed graph descendants according to the operation’s policy.
5. Query configured adapters using explicit scope and pagination limits.
6. Gather candidate records with minimal contextual evidence.

### 7.2 Historical semantic discovery (model-assisted)

The model may assess whether a candidate appears to reproduce, paraphrase, or reveal information from the target. It must receive only necessary, redacted/minimized candidate text. Use a strict JSON schema and bounded candidate batch size.

Expected output schema:

```json
{
  "candidate_id": "candidate_123",
  "relationship": "possible_derivative | related_but_not_disclosing | unrelated | uncertain",
  "fact_overlap": ["redacted_fact_label"],
  "evidence": ["short_redacted_reason"],
  "recommended_action": "preserve | review | redact | delete",
  "uncertainty": "low | medium | high"
}
```

Rules:
- The model cannot change the graph’s authoritative lineage state.
- The model cannot call delete operations directly.
- Semantic similarity alone is insufficient evidence.
- A high-confidence response is still a candidate until confirmed by policy or human review.
- Invalid JSON, timeout, or provider failure results in `unassessed`; do not guess.
- Treat scanned content as untrusted data, not instructions; ignore instructions found in records.

### 7.3 Candidate evidence classes

- `DIRECT_MATCH` — exact or normalized content/identifier match.
- `CONFIRMED_DESCENDANT` — descendant via confirmed lineage.
- `SUSPECTED_DERIVATIVE` — model/heuristic suggests target-derived disclosure.
- `RELATED_NONDISCLOSING` — related entity/topic but no evidence of target disclosure.
- `UNKNOWN` — insufficient evidence or inaccessible content.

### 7.4 Deletion policy defaults

- Direct match in approved scope: eligible for automatic inclusion in a plan; still require plan approval before execution.
- Confirmed descendant: plan action depends on data type; delete, redact, invalidate, or regenerate where safe.
- Suspected derivative: review by default; no destructive action without explicit approval.
- Related non-disclosing: preserve.
- Unknown or unreachable: report gap; do not claim cleared.

---

## 8. Revocation modes and execution semantics

### 8.1 Source revocation (MVP)

Target one source record and revoke in-scope traces derived from that source. Use the lineage graph for confirmed descendants and discovery for historical candidates.

### 8.2 Fact/secret revocation (stretch)

Target one secret/fact across records. Where a record also contains unrelated valuable content, choose among precise redaction, regeneration from approved sources, or review. Do not silently delete an entire useful record if a safer supported action exists.

### 8.3 Action types

- `DELETE_RECORD`
- `REDACT_SPAN` (only where safe and supported)
- `INVALIDATE_INDEX`
- `INVALIDATE_CACHE`
- `REGENERATE_FROM_ALLOWED_SOURCES`
- `REVIEW_REQUIRED`
- `SKIP_PRESERVE`
- `UNREACHABLE`

### 8.4 Plan state machine

`DRAFT → READY_FOR_APPROVAL → APPROVED → EXECUTING → VERIFYING → VERIFIED_WITHIN_SCOPE`

Terminal or exceptional states:
- `NEEDS_REVIEW` — ambiguous candidates remain unresolved.
- `PARTIAL` — some actions succeeded; others failed/unreachable.
- `FAILED` — core plan could not proceed.
- `CANCELLED` — user cancelled before or during safe stopping point.

Idempotency requirements: applying the same approved plan twice must not duplicate destructive work or produce misleading counts. Every action is individually recorded; retries are limited to idempotent/safe adapter operations.

### 8.5 Verification semantics

Verification checks only the configured reachable stores and the detection methods each adapter supports. A receipt must say what stores were checked, when, and with what method. If the adapter cannot prove absence, report `not_verifiable` instead of `verified`.

A deleted record may remain in backups, provider logs, replication queues, model weights, or unreachable third-party systems. Those are explicit limitations, not hidden assumptions.

---

## 9. MCP tool contract

The external tool surface should be small, explicit, read-only by default, and easy to audit.

### `redacto_status`
Returns adapter health, configured scope, model-provider availability, and current safety mode. Must not return secrets.

### `redacto_scan`
Input: target descriptor, target kind, stores/scope, scan depth.  
Output: candidate IDs, evidence classes, redacted reasons, store coverage, and unresolved count.  
Side effect: none; may write non-sensitive scan metadata.

### `redacto_trace`
Input: source record ID and optional traversal depth.  
Output: confirmed descendants, weak exposure links, candidate relationships, and provenance explanation.  
Side effect: none.

### `redacto_plan`
Input: target/source ID, revocation mode, explicit store scope, policy preferences.  
Output: `request_id`, `plan_id`, per-record proposed actions, evidence, risks, estimated impact, and an approval requirement.  
Side effect: creates a draft plan; does not delete or redact content.

### `redacto_apply`
Input: `plan_id`, explicit approval reference, and a short-lived confirmation token generated by the application.  
Output: action-level results and partial failure reasons.  
Side effect: destructive. It must reject unapproved plans, stale plans, out-of-scope locators, and approvals that do not bind to the exact plan version.

### `redacto_verify`
Input: `request_id` or `receipt_id`, stores to verify.  
Output: per-store verification results, residual matches, unsupported checks, and final status.  
Side effect: read-only verification and receipt update.

Optional internal-only hook (not necessarily exposed as a user-callable MCP tool): `record_lineage(source_ids, output_id, relation, evidence_type)` called by trusted ingestion/transformation code. Agent-provided arbitrary claims must not be marked confirmed without verification.

### MCP safety requirements

- No unrestricted `execute_shell`, arbitrary SQL, or arbitrary filesystem operations exposed.
- The tool server owns scope and authorization checks; the agent cannot broaden scope by prompt instruction.
- Destructive operations require explicit approval separate from the model's recommendation.
- Validate schemas, IDs, path roots, request state, and plan version on every tool call.
- Limit result sizes; redact sensitive content in responses.
- Use authentication for HTTP mode. Do not expose unauthenticated public endpoints or place secrets in tool descriptions.

---

## 10. Skill contract

Provide `skills/redacto/SKILL.md` containing the repeatable workflow:

1. Identify whether request is source revocation or fact/secret revocation.
2. Ask the MCP tool to scan and trace the target.
3. Inspect evidence classes; distinguish authoritative edges from inferred candidates.
4. Generate a plan and show the collateral-risk summary.
5. Ask the user to approve the exact plan. Do not invent or imply consent.
6. Apply only the approved plan.
7. Verify every reachable store and read the receipt.
8. Report removed, preserved, pending review, failed, and unverified categories separately.
9. Never claim universal erasure; clearly disclose adapter coverage and limitations.
10. Never quote the raw sensitive material in the skill response, audit, or final summary.

The skill is workflow guidance. It is not a substitute for server-side authorization and safety checks.

---

## 11. Model strategy and Alan integration

### 11.1 Use models differently for construction vs runtime

- **Build-time coding agent:** use an Alan-managed model enabled in the desktop app. Start with a capable model for architecture/implementation, and a faster Flash/Nano model for low-risk edits or summaries if quality is acceptable.
- **Runtime semantic assessment:** use a replaceable `RelationshipAssessor` interface. Do not assume the Alan-managed model list exposes an inference API to an external MCP process. Prove that access path first. If not available, use a locally configured OpenAI-compatible endpoint or local Ollama model with an explicit configuration.
- **Policy/execution:** deterministic Python code only. No LLM is required to decide whether a plan is approved or whether an adapter deletion succeeded.
- **Orchestration:** use one implementation agent first. Multi-agent parallelism is not necessary for the MVP and can add coordination/usage overhead.

### 11.2 Candidate model pool visible in provided screenshot

The screenshot shows Alan-managed models including DeepSeek V4.1 Flash, DeepSeek V4 Pro, GLM 5.3, GLM 5.3 Flash, Qwen3.8 27B, Kimi K3, Nemotron 3 Nano, and Nemotron 3 Super, plus additional models hidden behind “Show 7 more”. Exact availability and limits must be checked in the live app.

Suggested selection test:
1. Use a strong available model for initial code/spec implementation.
2. Benchmark one fast managed model on a small labelled set of synthetic sibling/negative examples if runtime inference is accessible.
3. Compare false-positive rate, false-negative rate, schema validity, latency, and usage against a local/own-provider option.
4. Choose the simplest model that meets the test thresholds; keep deterministic behavior as fallback.

### 11.3 Do not confuse a coding-agent model with a runtime API

The model selected in Alan for an agent session does not by itself give Redacto’s MCP server a programmatic endpoint or credential. The runtime provider must be configured separately and tested. The app’s “Connect provider” / custom-endpoint options may be usable for runtime inference only if a supported API and credential are explicitly provided.

---

## 12. Alan integration plan (based on the supplied screenshots)

The provided screenshots show:

1. **Settings → Plugins → MCP** with an “Add custom connector” action and no connections yet.
2. **Settings → General → Computers** showing the local runtime as ready/connected, but also “0 agents enabled” and “No agent CLIs detected”.
3. **Organisation → Models & providers** showing Alan-managed models and provider connection options.

### Integration steps

**Gate 0 — Get a coding agent working**
- Install a supported coding-agent CLI on the local computer or use a supported cloud agent.
- In Alan, rescan models, enable the CLI, whitelist a usable model, and confirm a minimal test task can read/edit/test a throwaway repository.
- Do not begin a large implementation session while the UI still reports no agent CLI.

**Gate 1 — MCP smoke test**
- Implement `redacto_status` only, returning a static version and adapter health.
- Test the server using the transport supported by the selected client.
- Inspect Settings → Plugins → MCP → Add custom connector. If the dialog expects a URL, test Streamable HTTP with authentication. If the relevant local agent supports stdio, test stdio separately via its supported MCP configuration.
- Do not assume the custom connector UI accepts a local stdio process. Do not expose a local server to the public internet without authentication.

**Gate 2 — Real deterministic tools**
- Add `redacto_scan`, `redacto_trace`, `redacto_plan`, `redacto_apply`, and `redacto_verify` incrementally.
- Confirm tool schemas appear and results are understandable in the agent's conversation.
- Keep UI/direct local CLI demonstration available as fallback if platform connection limits block the integration.

**Gate 3 — Skill**
- Include the skill file in the repo and document manual installation/use.
- Validate skill behavior with ambiguous candidates and a rejected plan; the skill must not bypass server-side safeguards.

### Transport architecture

- Prefer **stdio** for supported local CLI development if the client supports it.
- Implement **Streamable HTTP** as the deployment option for an MCP connector that requires a server URL.
- Keep transport separate from tool/business logic so either can be used without duplicating policy code.

---

## 13. UX requirements

A simple dashboard is enough; prioritize clarity over animation.

### Main screens

1. **Workspace/Adapters:** configured stores, scope roots, connectivity, available operations.
2. **Scan results:** list of candidates with evidence class, store, risk, and explanation.
3. **Lineage explorer:** source node, confirmed descendants, candidate links shown with distinct visual styles.
4. **Revocation preview:** planned deletes/redactions/invalidations, ambiguous candidates, preserved records, inaccessible stores.
5. **Execution timeline:** one row per action, timestamps, success/failure and retry action where safe.
6. **Verification receipt:** concise counts, stores checked, residual matches, limitations, and export as JSON/Markdown.

### Visual encoding

- Confirmed lineage and inferred candidates must use visibly different edge styles.
- Deletions are not represented as successful until the adapter confirms the operation.
- `needs_review` and `unreachable` must never look like green/success states.
- Always display “verified within configured scope” rather than “completely erased”.

### Accessibility and practical usability

- Readable contrast and clear status labels, not color alone.
- Filter by store, evidence class, and proposed action.
- Make the plan preview available as text so judges can understand it in a recording.

---

## 14. Security and privacy requirements

- Use synthetic demo data only for the hackathon.
- Explicitly configured roots and stores; fail closed for out-of-scope data.
- Protect against path traversal, SQL injection, malformed JSON, oversized input, and adapter-specific injection.
- Treat content being scanned as untrusted data; ignore embedded instructions.
- Never send raw API keys/passwords to a model for semantic classification.
- Redact/minimize candidate snippets and use short, bounded prompts.
- Do not write raw secrets or matched passages into logs, graph metadata, errors, screenshots, or receipts.
- Use keyed HMAC rather than plain SHA hash for low-entropy secrets when a persistent fingerprint is needed.
- No delete execution without an approved plan ID/version and server-side verification of authorization.
- Protect remote HTTP transport with bearer-token or stronger auth; bind local-only server to localhost in local mode.
- Receipt is integrity/evidence metadata, not a guarantee that all copies or backups have been physically overwritten.
- Add a dry-run flag and make dry run the default in early development.

---

## 15. Test and evaluation plan

### 15.1 Seeded test workspace

Create at least these examples:

1. Original confidential source document.
2. Exact duplicate in a log.
3. A generated summary with a direct sensitive fact.
4. A memory with the same fact paraphrased.
5. A vector-index chunk derived from the source.
6. A cached response containing the fact.
7. An unrelated engineering note mentioning the same organization.
8. A semantically similar but non-disclosing record.
9. A source whose downstream node has confirmed lineage.
10. A candidate with no lineage, to prove historical discovery works.
11. An unreachable adapter simulation.
12. A delete failure simulation.

### 15.2 Required automated tests

- Graph traversal finds every confirmed descendant in the test graph.
- `READ_FROM` alone does not automatically become a confirmed destructive descendant.
- Model-inferred relationships remain candidates until reviewed/validated.
- Exact-match scanner detects supported normalized variants.
- Semantic sibling classifier preserves at least the seeded unrelated/related-nondisclosing examples.
- Invalid model JSON and model timeouts cause `unassessed`, not destructive behavior.
- Out-of-scope paths and IDs are rejected.
- Unapproved or stale plan cannot be applied.
- Successful deletion is recorded per record; failed deletion is never counted as deleted.
- Verification scans only configured reachable stores and records limits.
- Receipt contains no raw target secret or full matched passage.
- Re-applying the same plan is idempotent or safely reports already completed operations.
- A content instruction embedded in a scanned file cannot override policy.

### 15.3 Demo acceptance targets

These are engineering targets for the synthetic fixture, not claims about production performance:

- 100% discovery of seeded exact matches in configured stores.
- 100% traversal of seeded confirmed lineage descendants.
- 0 destructive actions on unapproved ambiguous candidates.
- 0 deletion of seeded unrelated records.
- 100% of failed/unreachable adapter operations visibly reported as incomplete.
- 100% of receipts omit raw secret strings.
- One command to run tests and one documented command/path to launch the demo.

### 15.4 Evaluation report

Report counts rather than overstating a single “accuracy” score:
- Direct-match precision/recall on seeded fixtures.
- Confirmed-descendant traversal coverage.
- Semantic candidate true/false positives in the small labelled set.
- JSON-schema validity rate.
- Model latency and failure rate if inference is enabled.
- Number of destructive actions blocked by policy.

---

## 16. Recommended implementation stack

- Python 3.12+ (or the active supported Python version in the runtime).
- SQLite for graph, plans, actions, and receipts.
- NetworkX or a small adjacency/traversal module for graph reasoning; prefer simple code if dependencies are constrained.
- Pydantic for validated internal/tool schemas.
- Official MCP Python SDK or another current, maintained SDK compatible with chosen transport.
- FastAPI/ASGI only if needed for Streamable HTTP mode; keep stdio mode independent.
- React + TypeScript only if time remains after the deterministic engine; a compact UI or terminal demo is acceptable.
- Pytest for tests.
- Model provider adapter: configured OpenAI-compatible endpoint and/or local Ollama, selected by environment configuration.

Avoid adding a separate graph database, large orchestration framework, multi-agent system, hosted database, or complex authentication service for the hackathon MVP.

---

## 17. Repository layout

```text
redacto/
├── README.md
├── pyproject.toml
├── .env.example
├── src/redacto/
│   ├── app.py
│   ├── config.py
│   ├── graph/
│   │   ├── repository.py
│   │   ├── schema.py
│   │   └── traversal.py
│   ├── discovery/
│   │   ├── exact.py
│   │   ├── normalization.py
│   │   └── relationship_assessor.py
│   ├── policy/
│   │   ├── classify.py
│   │   ├── plan.py
│   │   └── authorization.py
│   ├── execution/
│   │   ├── apply.py
│   │   └── verify.py
│   ├── adapters/
│   │   ├── base.py
│   │   ├── filesystem.py
│   │   ├── sqlite_store.py
│   │   ├── jsonl_logs.py
│   │   └── vector_fixture.py
│   ├── receipts.py
│   └── mcp/
│       ├── stdio_server.py
│       └── http_server.py
├── skills/redacto/SKILL.md
├── dashboard/                  # optional; build after engine
├── fixtures/
│   ├── workspace/
│   └── expected_results.json
├── tests/
│   ├── test_graph.py
│   ├── test_discovery.py
│   ├── test_policy.py
│   ├── test_execution.py
│   ├── test_verification.py
│   └── test_mcp_tools.py
└── docs/
    ├── architecture.md
    ├── threat-model.md
    └── demo-script.md
```

Keep the architecture modular, but do not generate empty abstractions before they are needed. The order of implementation in Section 18 takes precedence over building every file in this tree.

---

## 18. Build sequence and time-boxed backlog

### P0 — Required for a credible demo

**P0.1 Setup gate**
- Confirm a working Alan coding agent or fallback local coding agent.
- Confirm repository, Python runtime, and test runner.
- Create `redacto_status` MCP smoke test for chosen transport.

**P0.2 Deterministic graph**
- Create SQLite schema and stable record IDs.
- Add lineage edges and bounded traversal.
- Seed fixtures with confirmed edges and candidate edges.

**P0.3 Deterministic discovery and plan**
- Exact matching, normalization, explicit source scope.
- Candidate result schema and revocation plan preview.
- No deletion from scan/trace/plan.

**P0.4 Safe executor and verification**
- Approval binds to a plan version.
- Adapter-level delete/invalidate operations.
- Per-action error results.
- Post-execution verification and receipt.

**P0.5 MCP tools and skill**
- Implement tool schemas incrementally.
- Expose safe, small result payloads.
- Write skill instructions and usage documentation.

**P0.6 Test/demo packaging**
- Seeded reproducible fixture.
- Tests for policy, failure cases, and false positives.
- README with setup, architecture, safety limits, demo instructions, and screenshots/video.

### P1 — High-value differentiator if the core is stable

- Open-model semantic assessment with strict JSON schema.
- Historical discovery for unlinked summaries and paraphrased facts.
- Graph visualization that visually distinguishes confirmed vs candidate edges.
- Adapter failure and recovery UI.

### P2 — Only after everything above works

- Fact-level selective redaction and safe regeneration.
- Additional vector DB / cache / logging providers.
- Multi-agent orchestration.
- Scheduled scans and continuous monitoring.
- Real production data connectors.

### Cut line

If time is short, drop the polished dashboard, second revocation mode, real vector DB, and orchestration. Do not cut approval, per-action results, false-positive tests, or truthful verification.

---

## 19. Demo storyboard (90–120 seconds)

1. Show `acquisition-plan.md` and the synthetic workspace.
2. Show the provenance graph: source → summary → memory → vector chunk/cache.
3. Ask the agent to revoke traces derived from the source.
4. Run `redacto_scan` and show a direct match, confirmed descendants, a paraphrased candidate, an unrelated engineering note, and one deliberately unreachable store.
5. Generate the plan. Show why each proposed action exists and mark the ambiguous sibling for review.
6. Approve the exact plan and apply it.
7. Show action results and the unrelated record preserved.
8. Run verification and display a receipt: records removed, record preserved, candidate pending review, store unreachable, and exact configured scope checked.
9. End with the statement: “Verified within configured scope—not a claim of universal erasure.”

The demo must work offline from a seeded fixture except for optional model assessment. If the model is unavailable, the deterministic flow must remain usable and explicitly mark semantic candidates as unassessed.

---

## 20. Definition of done

The MVP is done when:

- A fresh clone can be set up using documented commands.
- Tests pass in a clean environment.
- A user can run the source-revocation flow end to end on fixtures.
- Confirmed lineage and inferred candidates are stored and displayed separately.
- No scan/trace/plan operation mutates or deletes source records.
- `redacto_apply` rejects unapproved/stale plans and out-of-scope targets.
- The seeded unrelated record remains untouched.
- Simulated unreachable/failing stores produce a `PARTIAL` or `NEEDS_REVIEW` state, never false success.
- The verification receipt records store scope and limitations without reproducing secrets.
- MCP tools are discoverable and usable by at least one compatible client; Alan integration is documented with the exact tested transport.
- The README, skill file, architecture notes, and 90–120-second demo are public and complete.

---

## 21. Risk register

| Risk | Impact | Mitigation |
|---|---|---|
| Alan-managed models are not callable by external runtime code | Runtime semantic assessment unavailable | Model provider abstraction; test API access separately; deterministic fallback and/or configured local Ollama endpoint |
| Custom connector dialog requires remote URL | Local stdio server cannot be added through that route | Keep stdio and Streamable HTTP transports; test smoke test before building UI; only use authenticated tunnel/deployment if needed |
| Semantic false positives | Valuable unrelated records deleted | Candidate status, explicit approval, “related but non-disclosing” class, regression fixtures |
| Missing lineage | Historical traces missed | Retroactive scan of configured stores; disclose coverage gaps |
| Deletion semantics vary by store | Receipt overstates success | Adapter capabilities, per-store verification, partial states |
| Re-ingestion recreates deleted trace | Data appears after verification | Track tombstone/revocation marker and reject re-ingestion from revoked source where possible |
| Receipt/log captures the secret | Redacto creates a new sensitive copy | Redacted reason strings, keyed fingerprints, no raw match snippets in logs or receipts |
| Scope creep / build time | Unshipped core | Prioritize P0; dashboard and advanced providers are optional |
| Confusion between Alan plan usage and API entitlement | Unexpected limits or unavailable API | Validate usage in app; runtime model provider configured separately |

---

## 22. Alan setup checklist based on the supplied screenshots

1. Open the Alan desktop app and confirm the local computer is connected.
2. Install a supported coding-agent CLI (the screenshot currently shows “No agent CLIs detected”).
3. Return to the computer/agent settings, rescan, enable the CLI, and choose an available model.
4. Run a tiny task that creates and tests a file in a disposable repository.
5. Open Settings → Plugins → MCP → Add custom connector and inspect required fields/transport.
6. Implement `redacto_status`; prove MCP discovery and one successful call before adding the rest.
7. Configure runtime model inference separately; do not assume the selected coding model is an API key/endpoint.
8. Build against synthetic data only until adapter scope and security behavior are tested.

---

## 23. External references and verification notes

These links were checked on 26 October 2026. Product UI and plan terms can change; validate inside the active event account before relying on them.

- Alan pricing and included Individual plan capabilities: https://tryalan.ai/pricing/
- Alan local execution, detected CLIs, computer MCP configuration and local session workflow: https://docs.tryalan.ai/docs/cloud-and-local/local-execution
- Alan session model: runtime target, agent profile, and coding-agent CLI are separate choices: https://docs.tryalan.ai/docs/agents-and-sessions/start-a-session
- Alan quickstart and build/review workflow: https://docs.tryalan.ai/docs/get-started/quickstart
- Alan product/context graph description: https://tryalan.ai/product/

**Open question to validate in the app:** whether the “Add custom connector” dialog in Settings → Plugins → MCP accepts a local process, a remote Streamable HTTP URL, or both. Keep the tool logic independent of transport and record the successfully tested path in the README.
