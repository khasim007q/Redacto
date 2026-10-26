# Redacto architecture

## Shape

Redacto is a small Python service with one engine and two transport adapters. Every
tool call — from MCP, the CLI or the demo — goes through `redacto.engine.Engine`,
so scope checks, policy and authorization cannot be bypassed by picking a
different entry point.

```mermaid
flowchart LR
    subgraph clients["Clients"]
        A["MCP stdio client"]
        B["MCP Streamable HTTP client"]
        C["CLI / demo (application role)"]
    end
    subgraph transport["Transport"]
        S["mcp/server.py<br/>6 tools + error guard"]
        H["mcp/http_server.py<br/>bearer middleware"]
    end
    E["engine.Engine"]
    subgraph core["Deterministic core"]
        G["graph/repository.py<br/>traversal.py"]
        D["discovery/exact.py<br/>normalization.py"]
        R["discovery/relationship_assessor.py"]
        P["policy/classify.py<br/>plan.py<br/>authorization.py"]
        X["execution inside Engine<br/>apply / verify"]
    end
    subgraph stores["Configured stores"]
        F["filesystem"]
        Q["sqlite memories + cache"]
        L["jsonl logs"]
        V["vector fixture"]
    end
    DB[("SQLite graph, plans,<br/>actions, receipts")]
    A --> S --> E
    B --> H --> S
    C --> E
    E --> G
    E --> D
    E --> R
    E --> P
    E --> X
    G --> DB
    E --> F
    E --> Q
    E --> L
    E --> V
```

## Module map

| Module | Responsibility |
|---|---|
| `config.py` | Explicit settings from environment; no discovery of scope at runtime. |
| `fixtures.py` | Synthetic workspace + graph seed shared by demo, CLI and tests. |
| `graph/schema.py`, `graph/repository.py` | SQLite tables and all persistence. |
| `graph/traversal.py` | Bounded BFS. Strong-only paths become confirmed descendants; `READ_FROM` becomes exposure. |
| `discovery/normalization.py` | Normalization variants and keyed HMAC fingerprints. |
| `discovery/exact.py` | Whole-document matching for sources, bounded substring matching for facts/secrets, entity heuristic. |
| `discovery/relationship_assessor.py` | Replaceable assessor: `NullAssessor` default, OpenAI-compatible implementation, strict Pydantic schema, unassessed on any failure. |
| `policy/classify.py` | Evidence classes → proposed action + approved flag + collateral risk. |
| `policy/plan.py` | Plan items, version-bound plan hash, estimated impact. |
| `policy/authorization.py` | Application-issued confirmation tokens (hash stored, short TTL, single use). |
| `engine.py` | scan / trace / plan / apply / verify orchestration and all scope checks. |
| `receipts.py` | Receipt rendering to JSON and Markdown. |
| `mcp/server.py` | Tool registration plus the error guard that never leaks stack traces. |
| `mcp/stdio_server.py`, `mcp/http_server.py` | The two transports. |
| `cli.py` | Terminal application: seed, plan, approve, apply, verify, demo. |

## Data model

```mermaid
erDiagram
    records ||--o{ lineage_edges : "source_id"
    records ||--o{ candidate_edges : "source_id"
    revocation_requests ||--o{ revocation_plans : "request_id"
    revocation_plans ||--o{ revocation_plan_items : "plan_id"
    revocation_plans ||--o{ approvals : "plan_id"
    revocation_requests ||--o{ actions : "request_id"
    revocation_requests ||--o{ verification_runs : "request_id"
    revocation_requests ||--o{ receipts : "request_id"

    records {
        text record_id PK
        text record_type
        text store_id
        text locator_json
        text fingerprint
        text sensitivity_json
        text capabilities_json
        text status
    }
    lineage_edges {
        text edge_id PK
        text relation
        text evidence_type
        text status
    }
    candidate_edges {
        text candidate_id PK
        text relation_guess
        text evidence_summary_redacted
        text model_id
        real confidence
        text status
    }
    revocation_plans {
        text plan_id PK
        int version
        text state
        text plan_hash
    }
    approvals {
        text approval_id PK
        int plan_version
        text token_hash
        text expires_at
        text used_at
    }
    actions {
        text action_id PK
        text operation
        text result
        text idempotency_key
    }
    receipts {
        text receipt_id PK
        text summary_json
        text receipt_version
    }
```

No table stores record content, matched passages, secrets or model prompts. Only
opaque locators, keyed fingerprints, booleans and redacted reason strings.

## Flow: source revocation

```mermaid
sequenceDiagram
    participant U as User
    participant Ag as Agent (MCP client)
    participant S as Redacto MCP server
    participant Ap as Application (CLI)
    U->>Ag: "Forget everything derived from acquisition-plan.md"
    Ag->>S: redacto_scan(target_id, source)
    S-->>Ag: candidates + evidence classes + coverage gaps
    Ag->>S: redacto_trace(source_record_id)
    S-->>Ag: confirmed descendants / weak exposure / candidates
    Ag->>S: redacto_plan(target_id, source_revocation)
    S-->>Ag: plan_id, version, items, approval required
    Ag->>U: show plan, ask for approval
    U->>Ap: approve plan_id (human decision)
    Ap-->>U: single-use confirmation_token
    U->>Ag: hand over token + approval_ref
    Ag->>S: redacto_apply(plan_id, version, ref, token)
    S-->>Ag: per-record results (success / already_absent / failed)
    Ag->>S: redacto_verify(request_id)
    S-->>Ag: scoped receipt + limitations
    Ag->>U: removed / preserved / review / failed / unverified
```

## Execution semantics

- **Actions**: `DELETE_RECORD`, `INVALIDATE_INDEX`, `INVALIDATE_CACHE`,
  `REDACT_SPAN` (only where an adapter advertises redaction), `REVIEW_REQUIRED`,
  `SKIP_PRESERVE`, `UNREACHABLE`.
- **Plan states**: `READY_FOR_APPROVAL → APPROVED → EXECUTING → VERIFYING →
  VERIFIED_WITHIN_SCOPE`, with `PARTIAL`, `NEEDS_REVIEW`, `FAILED` as honest
  exceptional states.
- **Idempotency**: each action has a unique key. A dry run writes keys prefixed
  `dryrun:` so a later real apply still executes. Re-applying an applied plan
  returns `already_completed` with the recorded results instead of repeating work.
- **Verification**: rescan reachable in-scope stores, check planned record IDs and
  the keyed whole-target fingerprint, and report residuals. Unreachable stores are
  reported as gaps, never as clean.

## Transport

- **stdio** (`redacto-stdio`): used by local MCP clients.
- **Streamable HTTP** (`redacto-http`): bearer-token middleware in front of the same
  server; refuses to start without `REDACTO_HTTP_TOKEN`; localhost bind by default.

Both transports call the identical engine and tool functions.