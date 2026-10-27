# Redacto

**Provenance-aware revocation engine for AI context.** When a user asks an AI
system to forget a document, fact or secret, Redacto locates known descendants,
discovers historical traces that lineage missed, previews collateral damage,
deletes or invalidates only approved records, and verifies what remains in the
data stores it can actually reach.

> Confirmed provenance establishes known lineage. Discovery finds what lineage
> missed. Policy determines what may be erased. Verification determines what
> Redacto can honestly claim was removed.

Redacto is **not** a universal "erase from existence" button. It produces an
evidence-backed account of what was removed, what was preserved, what needs
review, and what could not be checked.

## Status

Hackathon MVP, working end to end on synthetic fixtures. Deterministic flow is
complete (scan, trace, plan, approval, apply, verify, receipt, tombstones,
quarantine resolution). Local embedding similarity is on by default for paraphrase
candidates. External model-assisted discovery sits behind a replaceable interface and
is **off by default**; with no provider configured its candidates are unassessed.

- 197 automated tests pass (`pytest`).
- Two MCP transports verified with real MCP clients: stdio and Streamable HTTP with bearer auth.
- Revocation tombstones block re-ingestion of exact and near copies. Uncertain matches are
  quarantined for review, never silently dropped and never auto-deleted.
- Quarantine approval is an audited application action that rechecks active tombstones and
  policy; rejection records the decision without admitting anything.
- Versioned HMAC keys keep active tombstones enforceable during rotation and fail closed if
  a required key is missing.
- Local embedding similarity generates paraphrase candidates and risk scores. It is advisory:
  embeddings never prove lineage and never block on their own.
- Secret/fact revocation deletes only records that contain the value; the anchor record is
  a lookup handle and is preserved unless it holds the value.
- Secret verification rescans every reachable store for the value itself, not the anchor,
  using separator-insensitive windowed matching, so `STRIPE_KEY=...`, `key:...`,
  `?token=...` and a value glued to other text are all detected.
- Logs and vector chunks are scanned across every string field, including nested tool-call
  arguments and chunk metadata.
- Verification is scoped and enforced by code, not by wording in a prompt.
- Plans show blast radius (record bytes, match share, collateral risk). A substring
  match inside a larger record is held for review instead of auto-deleted, and a
  verbatim passage buried in other notes is never labelled non-disclosing.
- Runtime dependencies install without dev extras; CI covers Linux + Windows and a
  runtime-only install.

## Quick start

```powershell
# 1. Environment (Python 3.12+, uv)
uv venv --python 3.12 .venv
uv pip install --python .venv\Scripts\python.exe -e ".[dev]"

# 2. Seed the synthetic workspace + provenance graph
.venv\Scripts\python.exe -m redacto seed

# 3. Test suite
.venv\Scripts\python.exe -m pytest

# 4. The full 90–120 second demo (seeds, plans, approves, applies, verifies)
.venv\Scripts\python.exe -m redacto demo
```

The demo writes `var/demo_receipt.json` and `var/demo_receipt.md`.

### Other commands

```powershell
python -m redacto status
python -m redacto trace  --source-id "fs:acquisition-plan.md"
python -m redacto scan   --target-id "fs:acquisition-plan.md"
python -m redacto plan   --target-id "fs:acquisition-plan.md"
python -m redacto approve --plan-id <PLAN_ID> --ref "operator approval"
python -m redacto review-item --plan-id <PLAN_ID> --item-id <ITEM_ID> --decision approved|rejected --reviewer "reviewer-id"
python -m redacto cancel --plan-id <PLAN_ID> --reason "operator stopped"
python -m redacto apply  --plan-id <PLAN_ID> --version 1 --ref "operator approval" --token <TOKEN> [--dry-run]
python -m redacto verify --request-id <REQUEST_ID> --out var\receipt.json --markdown var\receipt.md
python -m redacto tombstones                       # active tombstones, no content
python -m redacto ingest                           # re-run the guard over configured stores
python -m redacto quarantine                       # records held for review
python -m redacto resolve-quarantine --id <ID> --decision approved|rejected \
  --reviewer "reviewer-id" --note "why"
python -m redacto keyring                          # key versions + rotation safety
python -m redacto calibrate-embeddings             # FP / missed-paraphrase metrics
python -m redacto evaluate                         # metrics; run after `seed` on a pristine fixture
python -m redacto serve  --transport stdio   # or: --transport http
```

## MCP tools

| Tool | Destructive? | Purpose |
|---|---|---|
| `redacto_status` | no | Adapter health, configured scope, model availability, safety mode |
| `redacto_scan` | no | Candidates with evidence class, redacted reasons, coverage gaps |
| `redacto_trace` | no | Confirmed descendants vs weak exposure vs candidate relationships |
| `redacto_plan` | no | Draft plan with per-record actions, risks, estimated impact |
| `redacto_apply` | **yes** | Executes an approved plan version; requires an application-issued token |
| `redacto_verify` | no | Rescans in-scope stores and writes a scoped receipt |
| `redacto_tombstones` | no | Active tombstones: scope, policy, status (no content, no fingerprints) |
| `redacto_quarantine` | no | Records held by the ingestion guard for human review |

There is deliberately **no approve tool and no quarantine-resolution tool**.
Both are application actions (`redacto approve`, `redacto resolve-quarantine`),
so an agent can neither authorize its own deletion nor admit a record it was
warned about. Quarantine approval rechecks the guard at resolution time.

### Client configuration

stdio (any MCP client that supports a local process):

```json
{
  "mcpServers": {
    "redacto": {
      "command": "redacto-stdio",
      "cwd": "C:\\path\\to\\Redacto",
      "env": {
        "REDACTO_WORKSPACE_ROOT": "C:\\path\\to\\Redacto\\fixtures\\workspace",
        "REDACTO_DB_PATH": "C:\\path\\to\\Redacto\\var\\redacto.sqlite3",
        "REDACTO_SQLITE_PATH": "C:\\path\\to\\Redacto\\fixtures\\workspace\\agent_memory.sqlite3",
        "REDACTO_JSONL_PATH": "C:\\path\\to\\Redacto\\fixtures\\workspace\\agent_events.jsonl",
        "REDACTO_VECTOR_PATH": "C:\\path\\to\\Redacto\\fixtures\\workspace\\vector_chunks.json"
      }
    }
  }
}
```

`cwd` and the `REDACTO_*` paths matter: without them the server resolves defaults
relative to whatever folder the client launches it from and sees no stores. Replace
`C:\path\to\Redacto` with the actual clone path. If `redacto-stdio` is not on the
client's PATH, use the absolute interpreter path plus `-m redacto.mcp.stdio_server`
and keep the same `cwd`/`env`.

The repo also ships a Claude Code style plugin layout: `.claude-plugin/plugin.json`
plus `.mcp.json`. The MCP entry uses `${CLAUDE_PLUGIN_ROOT}` for every store path and
`uv run --project`, so it does not depend on the shell's working directory. `uv` must
be installed. `cwd` is deliberately absent: it is not a supported stdio MCP field.
The graph database is written under `${CLAUDE_PLUGIN_DATA}`, not the read-only plugin
root; point `REDACTO_WORKSPACE_ROOT` at your own data for real use.
This layout is **not verified against Alan's plugin format**; for Alan, register the
connector manually with the stdio or HTTP configuration above.

Streamable HTTP (for connectors that expect a URL). A bearer token is mandatory:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(32))"   # set REDACTO_HTTP_TOKEN
$env:REDACTO_HTTP_TOKEN = "<token>"
$env:REDACTO_HTTP_HOST  = "127.0.0.1"
$env:REDACTO_HTTP_PORT  = "8765"
.venv\Scripts\python.exe -m redacto.cli serve --transport http
```

Endpoint: `http://127.0.0.1:8765/mcp`, header `Authorization: Bearer <token>`.
The server refuses to start without `REDACTO_HTTP_TOKEN` and binds localhost by
default. Do not expose it publicly.

## Tested transports (exact)

| Check | Command | Result |
|---|---|---|
| stdio, real MCP client session | `.venv\Scripts\python.exe scripts\mcp_smoke.py` | PASS — discovers all 8 tools, `redacto_status` returns adapter health |
| stdio, full cycle in pytest | `.venv\Scripts\python.exe -m pytest tests/test_mcp_tools.py` | PASS — scan → plan → denied self-approval → approved apply → verify |
| Streamable HTTP + bearer auth | `.venv\Scripts\python.exe scripts\mcp_http_smoke.py` | PASS — 401 without token, discovery + status with token |

SDK: `mcp` 2.3.0 (`mcp.server.mcpserver.MCPServer`; the 2.x rename from FastMCP).
Tool logic is transport-independent, so both entry points share the same engine.

## Alan integration status

**Partial / blocked at the platform gate, not at the code gate.**

- This implementation was executed by the local coding-agent harness in this
  session against the real repository, with real test runs.
- The Alan desktop gate from the brief ("No agent CLIs detected") is **not resolved
  from here**: a PATH scan found only `aider` among common agent CLIs
  (`claude`, `codex`, `cursor-agent`, `droid`, `opencode`, `gemini`, `qwen`, `kimi`,
  `amp` are absent). Enabling a CLI in Alan Settings → Computers is a user action.
- The repo now contains a working MCP server and two verified transports. The
  remaining Alan step is registering a connector:
  - if Settings → Plugins → MCP → *Add custom connector* expects a URL, use
    Streamable HTTP with the bearer token above;
  - if the selected local agent supports stdio, add the stdio command above.
- No assumption is made that an Alan-managed model (DeepSeek, GLM, Qwen, Kimi,
  Nemotron, …) is callable as an inference API by an external process. Runtime
  assessment requires an explicitly configured OpenAI-compatible endpoint or local
  Ollama; otherwise the deterministic path runs and candidates stay unassessed.

## Architecture

Short version: one engine, two transports, four scoped adapters, one SQLite graph.
Full diagrams (component flow, ER model, revocation sequence) are in
[docs/architecture.md](docs/architecture.md).

- **Adapters**: filesystem (markdown/text under a configured root), SQLite agent
  memories **and** response cache (approved tables only), JSONL logs, and a local
  vector-index fixture. Each declares capabilities (scan/delete/redact/invalidate/verify).
- **Graph semantics**: `DERIVED_FROM`, `EXTRACTED_FROM`, `SUMMARIZED_FROM`,
  `INDEXED_AS`, `CACHED_AS`, `REGENERATED_FROM` can be confirmed by policy
  (instrumented / imported metadata / human verified). `READ_FROM` is **exposure
  only** and never authorizes deletion by itself. Model output creates
  `candidate_edges` only.
- **Evidence classes**: `DIRECT_MATCH`, `CONFIRMED_DESCENDANT`,
  `SUSPECTED_DERIVATIVE`, `RELATED_NONDISCLOSING`, `UNKNOWN`.
- **Plan lifecycle**: `READY_FOR_APPROVAL → APPROVED → EXECUTING → VERIFYING →
  VERIFIED_WITHIN_SCOPE`, with `PARTIAL`, `NEEDS_REVIEW`, `FAILED` used honestly.
- **Lineage hook**: `Engine.record_lineage` is internal-only. Instrumented, imported
  or human-verified evidence can confirm an edge; model/heuristic claims become
  candidates. It is not exposed as an MCP tool.
- **Plan states**: `READY_FOR_APPROVAL -> APPROVED -> EXECUTING -> VERIFYING` then
  `VERIFIED_WITHIN_SCOPE`, `PARTIAL` or `NEEDS_REVIEW`. `EXECUTING` is set before the
  first mutation. `CANCELLED` is available before execution and cannot be applied.
  `FAILED` is set when every approved action fails; a FAILED plan can be re-approved
  and retried, with failed action rows cleared for a safe retry. There is no editable
  `DRAFT` stage.
- **Recovery**: a crashed `EXECUTING` plan can be re-approved with a new single-use
  token; completed actions are skipped by idempotency.
- **Item review**: `review-item` is an application action. Approving rewrites the item
  to a concrete adapter action and bumps the plan version, so a fresh token is needed.
  Rejecting leaves the item unapproved. Both decisions are audited.
- **Action vocabulary**: `DELETE_RECORD`, `INVALIDATE_INDEX`, `INVALIDATE_CACHE`,
  `REVIEW_REQUIRED`, `SKIP_PRESERVE`, `UNREACHABLE` are exercised. `REDACT_SPAN` and
  `REGENERATE_FROM_ALLOWED_SOURCES` are defined but unsupported by current adapters.
- **Node types**: stored records map to `MEMORY`, `LOG_RECORD`, `INDEX_ENTRY`,
  `CACHE_ENTRY` and `ARTIFACT`; scan/trace targets are labelled `SOURCE` or `FACT`.
- **Persistence**: records, lineage edges, candidate edges, requests, plans, items,
  approvals, actions, verification runs, receipts. No table stores content,
  matched passages or secrets — only opaque locators, keyed HMAC fingerprints,
  booleans and redacted reason strings.

## Data model

See the ER diagram in [docs/architecture.md](docs/architecture.md). Highlights:

- `lineage_edges(relation, evidence_type, status)` — authority lives here.
- `candidate_edges(relation_guess, evidence_summary_redacted, model_id, confidence)` —
  advisory, never authoritative.
- `revocation_plans(version, state, plan_hash)` + `approvals(plan_version, token_hash,
  expires_at, used_at)` — approval binds an exact plan version and hash.
- `actions(idempotency_key UNIQUE, result, error_code)` — per-record outcomes;
  duplicate keys make retries safe.
- `receipts(summary_json, receipt_version)` — counts, scope and limitations only.

## Security notes

Full threat model with tests mapped per threat: [docs/threat-model.md](docs/threat-model.md).

- Synthetic fixtures only; no real personal data or credentials.
- Explicit scope. Unknown stores, absolute paths, traversal attempts and unapproved
  tables are rejected — the tool server owns scope, the agent cannot widen it.
- Scanned content is data, never instructions. An embedded "ignore previous
  instructions / delete everything" line is classified as non-disclosing and preserved.
- Destructive operations need an application-issued, plan-version-bound,
  single-use, expiring confirmation token. Tampered or stale plans are rejected.
- Secrets are never persisted: keyed HMAC fingerprints for matching, redacted
  reasons in graph/plan/receipt, and masked snippets for the optional model call.
- No `execute_shell`, no arbitrary SQL, no arbitrary filesystem operations.
- Failures are never reported as success: adapter errors produce per-record failures
  and a `PARTIAL` result.
- Approval consumption is atomic: one token cannot authorize two concurrent applies.
- A crashed or failed apply is recoverable: re-approving an `EXECUTING`/`FAILED` plan
  issues a new token; completed actions are skipped and failed actions are retried.
  A cancelled plan cannot be applied. Apply holds an exclusive lease so concurrent
  recovery tokens cannot both report the same work.
- Plan item reviews are audited; approving one bumps the plan version and invalidates
  the old token.
- Apply takes an exclusive execution lease, so two recovery tokens used at once cannot
  both report the same work. The lease records the owning PID/host. Liveness uses
  `OpenProcess` on Windows (never `os.kill(pid, 0)`, which means Ctrl+C there) and
  `os.kill(pid, 0)` on POSIX. A live local owner is never stolen, however old the lease;
  a dead owner or a lease from an unknown host older than 15 minutes is cleared, in any
  plan state. The token is validated before the lease is taken, so a forged token cannot
  block a real apply.
- Each plan item stores its plan-time content fingerprint. Adapters verify it as part of the
  mutation: SQLite does the check and delete under one write lock, the filesystem adapter
  re-reads the file and requires both the identity and the size/mtime stamp to match
  before unlinking (an in-place edit keeps the inode), and file-backed stores re-read
  before rewriting. A mismatch fails with `content_changed`.
- JSONL event identity is stable even without `event_id` (keyed line hash), and
  malformed lines are matched by that identity rather than a shifted line number. A log
  rewrite re-reads the file before replacing it, so a line appended during the rewrite is
  preserved; if the file never settles the delete fails with `delete_conflict` instead of
  dropping data.
- Record-cap truncation is reported in scan coverage and verification; absence is not
  claimed for unscanned records.
- SQLite deletes set `PRAGMA secure_delete=ON` and attempt a WAL truncate checkpoint.
  Files are unlinked, not overwritten, and JSONL/vector rewrites keep the original mode.
- Files under a configured root with other extensions are not scanned; `redacto_status`
  reports them per adapter so the gap is visible.
- Tombstones retain keyed HMAC fingerprints, derived anchors and an embedding vector.
  A different key or key version cannot match them, and the revoked content is
  unrecoverable.
- The ingestion guard fails closed: blocked records never reach the store or graph.
  If an active tombstone needs a missing key version, every ingestion is blocked
  (`key_unavailable_fail_closed`) and `redacto_status` reports degraded protection.
- Quarantine is a pointer, not a copy. Approval re-reads the record from its store,
  rechecks tombstones and policy, records the recheck, and only then admits it.
  Rejection preserves the decision without admitting anything.
- Embeddings are a risk signal, never proof. They can only quarantine; a high score
  never authorizes deletion or confirms lineage.
- Records larger than `REDACTO_MAX_RECORD_BYTES` (default 1 MB) are skipped before
  matching and reported, so oversized input cannot enter the graph or model path.
- HTTP mode requires a bearer token and refuses to start without one.

## Measured results

Test suite (`python -m pytest`, Python 3.12.0):

```
197 passed in 70.61s
```

Covering: graph traversal and `READ_FROM` semantics, normalized exact matching,
short-secret bounds, entity heuristics, model invalid-JSON/timeout →
`unassessed`, policy mapping, plan hashing, approval rejection (unapproved, stale
version, tampered plan), dry run, per-record outcomes, idempotent re-apply,
adapter failure and disappearing stores, unreachable-store reporting, receipt
redaction, scope enforcement, traversal rejection, SQL table rejection, embedded
instruction containment, secret non-persistence, HTTP auth, and re-ingestion
protection, store-write blocking, quarantine approval/rejection and rechecks,
key-ring rotation and fail-closed behaviour, and embedding calibration with
measured false positives and missed paraphrases.

### Fixture evaluation (`redacto evaluate`)

The spec asks for counts rather than one accuracy score:

| Metric | Result |
|---|---|
| Direct-match precision / recall | 1.0 / 1.0 (2 TP, 0 FP, 0 FN) |
| Confirmed-descendant coverage | 5 / 5 (1.0) |
| Semantic candidate precision / recall | 1.0 / 1.0 (2 TP, 0 FP, 0 FN) |
| Preserved-related recall | 4 / 4 (1.0) |
| Unrelated records touched | 0 |
| Destructive actions blocked by policy | 2 |
| Model JSON-schema validity | not measured while the model provider is disabled |

These are fixture-level engineering targets, not production accuracy claims.

### Collateral risk controls

- **Blast radius:** every plan item carries `size_bytes`, `matched_bytes`,
  `match_ratio`, `match_kind`, `partial_match` and a `collateral_note`. Approved
  actions whose match covers less than 34% of the record are marked `risk: high`.
- **Partial matches:** a fact/secret found as a substring covering less than half of a
  record is `REVIEW_REQUIRED`. At or above half, the normal delete path still applies,
  so a leaked key that dominates its record is removable. Reviewers can approve or
  reject a review item with `review-item`; approval bumps the plan version and requires
  a new token.
- **Buried verbatim copies:** source-mode scans compare 8-word shingles against the
  target. A record quoting a target passage inside other notes becomes
  `SUSPECTED_DERIVATIVE` for review, never `RELATED_NONDISCLOSING`.
- **Distinctive amounts/dates:** a record that shares a numeric amount or date with the
  target (score >= 4 on weighted anchors) is `SUSPECTED_DERIVATIVE` for review, so a
  reworded price+closing-date note is never labelled harmless.
- **Small mentions go to review:** a short secret inside a large record is held for review
  rather than deleting the whole file. Verification honestly reports `PARTIAL` until a
  reviewer resolves it with `review-item`, and `review-item` is accepted even after the
  plan has applied its other items.
- **Still missing:** precise `REDACT_SPAN` editing, regeneration and a timed undo/trash
  window. Those are documented as remaining work, not silently claimed.

### Embedding calibration (synthetic labelled set)

Thresholds are chosen from measurement, not guesswork. On the labelled synthetic
set (5 paraphrases, 5 unrelated/related-non-disclosing records):

| Threshold | False positives | Missed paraphrases |
|---|---|---|
| 0.25 (candidate generation) | 0 / 5 | 0 / 5 |
| 0.30 (ingestion quarantine) | 0 / 5 | 0 / 5 |
| 0.01 (deliberately low) | 5 / 5 | 0 / 5 |
| 0.60 (deliberately high) | 0 / 5 | 5 / 5 |

Observed scores: paraphrases 0.31?0.40, negatives ? 0.17. The local provider is a
deterministic lexical-semantic embedding (number-word normalization plus a small
domain concept map), not a neural model; `redacto calibrate-embeddings` reproduces
these numbers.

### Re-ingestion attack matrix (test-suite counts)

The suite exercises **9 scenarios: 6 blocked, 2 quarantined, 1 allowed**.

| # | Scenario | Expected decision | Reason code |
|---|---|---|---|
| 1 | Restore the original file | blocked | `same_target` |
| 2 | Restore under a new filename | blocked | `exact_fingerprint` |
| 3 | Replay an old JSONL event with a new id | blocked | `exact_fingerprint` |
| 4 | Replay with the original event id | blocked | `revoked_record_id` |
| 5 | Rebuild a vector chunk with copied text | blocked | `exact_derivative_fingerprint` |
| 6 | Rebuild a vector chunk with edited wording | blocked | `partial_copy` |
| 7 | Reintroduce a paraphrase with shared anchors | quarantined | `anchor_overlap` |
| 8 | Reintroduce a paraphrase with no shared anchors | quarantined | `embedding_similarity` |
| 9 | Introduce an unrelated record | allowed | `no_match` |

The demo's step `[8]` runs a **2-scenario subset** of that matrix (restored file +
no-anchor paraphrase) across two stores, so its line reads `1 blocked, 1 quarantined,
5 allowed`. Those `5 allowed` are other records in those stores, not additional
attack scenarios. The demo prints this distinction explicitly; the suite totals are
`6 blocked, 2 quarantined, 1 allowed` across 9 scenarios.

Demo (`python -m redacto demo`) on the seeded fixture:

| Metric | Result |
|---|---|
| Records seeded | 18 |
| Confirmed descendants traversed | 5 / 5 |
| Direct matches found | 2 (`fs:acquisition-plan.md`, `log:evt-dup-1`) |
| Approved actions executed | 7 (5 deletes, 2 invalidations) |
| Failed actions | 0 |
| Residual matches after verification | 0 in all 4 reachable stores |
| Candidates held for review | 2 (paraphrases with no lineage) |
| Embedding calibration (0.30) | 0 false positives, 0 missed paraphrases on 10 labelled examples |
| Preserved related records | 4 (incl. the file containing an embedded delete instruction) |
| Unrelated records touched | 0 |
| Final status | `NEEDS_REVIEW` (candidates pending) — receipt states scope explicitly |

## Limitations

- **Not universal erasure.** Backups, replicas, provider logs, caches and model
  weights are out of reach; the receipt says so. Deleted files are unlinked rather than
  overwritten, and SQLite physical removal can be delayed by another open WAL writer.
- **Asking an agent to forget a secret by pasting it adds a copy** to that agent's model
  provider conversation. Redacto cannot revoke provider-side chat history; use a managed
  secret reference instead of pasting the value.
- Verification detects planned record IDs and exact/normalized whole-target copies.
  Paraphrased remnants in unlinked stores may survive undetected.
- Re-ingestion protects exact and near copies and now quarantines embedding-similar
  paraphrases, but a paraphrase that scores below the calibrated threshold can still
  enter. The local embedding is lexical-semantic, not a production neural model.
- Embedding thresholds are calibrated on a small synthetic set, not real data; a
  production deployment must recalibrate on its own labelled examples.
- Key rotation keeps old versions enforceable, but removing a version that active
  tombstones still reference blocks ingestion until the key is restored. That is
  deliberate fail-closed behaviour, not silent degradation.
- Quarantine approval is a human/application action; approving an uncertain record
  overrides uncertainty, but can never override a hard tombstone block.
- Model assessment is unbenchmarked in this MVP and advisory only.
- No editable `DRAFT` plan stage. `CANCELLED` is available before execution,
  `FAILED` when every approved action fails (and is retryable), and `PARTIAL` when only
  some actions fail.
- `find_exact` is implemented centrally in discovery rather than per adapter, and
  `REDACT_SPAN`/regeneration have no supported adapter yet.
- Partial matches below half the record are reviewed rather than redacted in place; a
  reviewer chooses whole-record deletion or rejection. There is no undo/trash window yet.
- The plan flags collateral risk but does not automatically regenerate a descendant
  from its other parents (option 6 in the review).
- Two revocation modes exist in code; both are tested. Fact/secret revocation deletes
  records containing the value (the anchor is preserved), and verification searches for
  the value's tokens; the value is never stored, so a value embedded inside a longer token
  and reworded traces are not proven absent.
- Receipt integrity is evidence metadata, not proof of physical overwrite.

## Repository layout

```text
src/redacto/
  config.py  fixtures.py  engine.py  status.py  receipts.py  errors.py  cli.py  process.py
  graph/       schema.py repository.py traversal.py
  discovery/   normalization.py exact.py relationship_assessor.py embeddings.py
  ingestion.py  (tombstone guard, quarantine decisions, fail-closed keys)
  evaluation.py (fixture precision/recall and policy counts)
  policy/      classify.py plan.py authorization.py
  adapters/    base.py registry.py filesystem.py sqlite_store.py jsonl_logs.py vector_fixture.py
  mcp/         server.py stdio_server.py http_server.py
skills/redacto/SKILL.md
.claude-plugin/plugin.json
.mcp.json
.github/workflows/ci.yml
scripts/       mcp_smoke.py mcp_http_smoke.py
fixtures/      workspace/ expected_results.json
tests/         test_graph.py test_discovery.py test_policy.py test_execution.py
               test_verification.py test_security.py test_mcp_tools.py test_transport.py
               test_tombstones.py test_quarantine.py test_key_rotation.py test_embeddings.py
               test_evaluation.py test_jsonl.py test_hardening_collateral.py
               test_recovery_and_review.py test_packaging.py test_trace_completeness.py
               test_windows_and_lease.py
docs/          architecture.md threat-model.md demo-script.md key-rotation.md
               spec-compliance.md
```

## Spec compliance

A section-by-section audit against `REDACTO_SPEC.md`, including deviations and
evidence, is in [docs/spec-compliance.md](docs/spec-compliance.md). The headline:
all P0 requirements are implemented; the remaining deviations are an editable draft
plan stage, per-adapter `find_exact`, span redaction/regeneration, a graph
visualization, and Alan connector registration.

## Next highest-value task

Implement safe **`REDACT_SPAN` editing** for Markdown, SQLite rows and JSONL content,
then a short **undo/trash window** guarded by tombstones. That closes the remaining
collateral options: a partial match can be redacted instead of deleting the whole
record, and a mistaken deletion is recoverable during a development session.

After that, replace the local hashing embedding with a **configurable neural embedding provider**
and recalibrate on a larger labelled corpus, reporting false positives and missed
paraphrases per provider. The provider interface and quarantine default already exist;
the work is integration, cost/latency measurement and a corpus that is not synthetic.

Then, in order: tombstone retention and expiry policy; a review UI over the quarantine
queue; a benchmark of the optional model assessor on labelled siblings; and real vector
store / cache adapters behind the same interface.