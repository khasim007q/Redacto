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
complete (scan, trace, plan, approval, apply, verify, receipt). Model-assisted
discovery sits behind a replaceable interface and is **off by default**; with no
provider configured, semantic candidates are reported as unassessed.

- 55 automated tests pass (`pytest`).
- Two MCP transports verified with real MCP clients: stdio and Streamable HTTP with bearer auth.
- Verification is scoped and enforced by code, not by wording in a prompt.

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
python -m redacto apply  --plan-id <PLAN_ID> --version 1 --ref "operator approval" --token <TOKEN> [--dry-run]
python -m redacto verify --request-id <REQUEST_ID> --out var\receipt.json --markdown var\receipt.md
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

There is deliberately **no approve tool**. Approval is an application action
(`redacto approve`), so an agent cannot authorize its own deletion.

### Client configuration

stdio (any MCP client that supports a local process):

```json
{
  "mcpServers": {
    "redacto": {
      "command": "C:\\Users\\HI\\Downloads\\Redacto\\.venv\\Scripts\\python.exe",
      "args": ["-m", "redacto.mcp.stdio_server"],
      "env": { "PYTHONPATH": "C:\\Users\\HI\\Downloads\\Redacto\\src" }
    }
  }
}
```

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
| stdio, real MCP client session | `.venv\Scripts\python.exe scripts\mcp_smoke.py` | PASS — discovers all 6 tools, `redacto_status` returns adapter health |
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
- HTTP mode requires a bearer token and refuses to start without one.

## Measured results

Test suite (`python -m pytest`, Python 3.12.0):

```
55 passed in 12.16s
```

Covering: graph traversal and `READ_FROM` semantics, normalized exact matching,
short-secret bounds, entity heuristics, model invalid-JSON/timeout →
`unassessed`, policy mapping, plan hashing, approval rejection (unapproved, stale
version, tampered plan), dry run, per-record outcomes, idempotent re-apply,
adapter failure and disappearing stores, unreachable-store reporting, receipt
redaction, scope enforcement, traversal rejection, SQL table rejection, embedded
instruction containment, secret non-persistence, and HTTP auth.

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
| Preserved related records | 4 (incl. the file containing an embedded delete instruction) |
| Unrelated records touched | 0 |
| Final status | `NEEDS_REVIEW` (candidates pending) — receipt states scope explicitly |

## Limitations

- **Not universal erasure.** Backups, replicas, provider logs, caches and model
  weights are out of reach; the receipt says so.
- Verification detects planned record IDs and exact/normalized whole-target copies.
  Paraphrased remnants in unlinked stores may survive undetected.
- Re-ingestion can recreate a revoked trace; there is no tombstone check yet.
- Model assessment is unbenchmarked in this MVP and advisory only.
- Two revocation modes exist in code; **source revocation** is the tested path.
  Fact/secret revocation is functional but narrower (bounded substring matching).
- Receipt integrity is evidence metadata, not proof of physical overwrite.

## Repository layout

```text
src/redacto/
  config.py  fixtures.py  engine.py  status.py  receipts.py  errors.py  cli.py
  graph/       schema.py repository.py traversal.py
  discovery/   normalization.py exact.py relationship_assessor.py
  policy/      classify.py plan.py authorization.py
  adapters/    base.py registry.py filesystem.py sqlite_store.py jsonl_logs.py vector_fixture.py
  mcp/         server.py stdio_server.py http_server.py
skills/redacto/SKILL.md
scripts/       mcp_smoke.py mcp_http_smoke.py
fixtures/      workspace/ expected_results.json
tests/         test_graph.py test_discovery.py test_policy.py test_execution.py
               test_verification.py test_security.py test_mcp_tools.py test_transport.py
docs/          architecture.md threat-model.md demo-script.md
```

## Next highest-value task

Add a **revocation tombstone / re-ingestion guard**: persist revoked source
fingerprints and rejected derivations so a deleted trace cannot be silently
recreated by a later ingestion run. That is the biggest remaining gap between
"verified absent now" and "stays absent".

Then, in order: benchmark the model assessor on a labelled sibling set; a graph
visualisation that distinguishes confirmed from candidate edges; and real vector
store / cache adapters behind the same interface.