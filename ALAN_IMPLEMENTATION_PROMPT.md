# Alan implementation prompt — Redacto

Use `REDACTO_SPEC.md` as the source of truth. Your task is to implement the Redacto hackathon MVP, not to redesign the product or expand the scope.

## Operating constraints

- Inspect the repository and runtime before changing files. If the repository is empty, initialize the project structure from the spec.
- The current Alan desktop screenshot showed **“No agent CLIs detected”**. Check this setup gate first. If the current runtime cannot execute a coding agent, clearly report the blocker and do not pretend implementation or tests ran. Use a supported local coding-agent CLI if available.
- The screenshots show Alan-managed models (including DeepSeek V4.1 Flash, DeepSeek V4 Pro, GLM 5.3/Flash, Qwen3.8 27B, Kimi K3 and Nemotron 3 variants), but do not assume a managed model is callable as an external inference API. Keep model inference behind a provider interface and make the deterministic flow work without it.
- Treat the graph as authoritative for **recorded confirmed lineage**. Model-inferred relationships are candidates only.
- Do not claim universal deletion. Verification is limited to configured and reachable stores.
- Do not use real personal data or real secrets. Use synthetic fixtures only.
- Keep destructive actions gated by a server-validated, approved plan.
- No arbitrary shell, SQL, or filesystem tool exposed to the model.
- Do not create giant architecture abstractions before the MVP works. Prefer small, tested modules.
- Commit regularly with clear, truthful messages if Git is available. Never claim tests pass unless they were run.

## Implementation sequence

### Step 0 — Environment and transport smoke test
1. Inspect available languages, Python version, package tooling, installed agent CLIs and MCP options.
2. Write a short implementation plan artifact listing files, test commands, known limitations and the selected transport.
3. Build a minimal `redacto_status` MCP tool.
4. Test it using the actual MCP client/transport available. The Alan Settings → Plugins → MCP screen has “Add custom connector”; do not assume it supports local stdio. Keep stdio and Streamable HTTP business logic separate if both are implemented.
5. Do not publicly expose an unauthenticated HTTP server. Bind local mode to localhost; if remote URL is required, use authentication and synthetic data.

### Step 1 — Deterministic core first
1. Create SQLite tables for records, confirmed lineage edges, candidate edges, revocation requests, plan items, actions, verification runs and receipts.
2. Implement graph traversal and clearly separate `READ_FROM` from `DERIVED_FROM`.
3. Build filesystem, SQLite and JSONL adapters. Add the vector fixture adapter only if time permits.
4. Implement exact and normalized discovery.
5. Implement `redacto_scan`, `redacto_trace`, `redacto_plan`, `redacto_apply`, `redacto_verify`, and `redacto_status` with strict request/response schemas.
6. Keep scan, trace, and plan non-destructive. Require an explicit approval reference tied to a specific plan version before applying.
7. Implement per-record action results, idempotency, error handling and post-action verification.
8. Produce a receipt without raw secrets, full matched passages or secret-bearing model prompts.

### Step 2 — Model-assisted retroactive discovery
1. Implement `RelationshipAssessor` as a replaceable provider interface.
2. Use a configured open-weight model provider only after verifying how it is reached (Alan-managed inference endpoint, OpenAI-compatible endpoint, or local Ollama). The coding session’s selected model is not itself proof of an API endpoint.
3. Feed the model only necessary, minimized/redacted candidate data.
4. Require schema-conforming JSON. Invalid output, timeout or provider failure becomes `unassessed` and must never lead to deletion.
5. Model output creates `candidate_edges`, not confirmed edges.
6. Add labelled positive and negative sibling fixtures and prove unrelated records are preserved.

### Step 3 — Skill and user experience
1. Create `skills/redacto/SKILL.md` with the workflow: scan → trace → plan → approval → apply → verify.
2. Create a simple view or terminal flow for candidates, evidence, plan approval, action results and receipt. Do not spend more time on UI polish than on core correctness.
3. Visually distinguish confirmed lineage from candidate relationships.
4. Show “verified within configured scope” and list unreachable stores or pending candidates.

### Step 4 — Hardening and delivery
1. Add tests for the acceptance criteria in Section 15 of `REDACTO_SPEC.md`.
2. Test out-of-scope paths, stale plans, unauthorized apply, invalid model JSON, timeouts, adapter failures, idempotent retries, malicious instructions embedded in scanned content, and receipt redaction.
3. Update README with setup, architecture, data model, security notes, limitations, exact tested Alan/MCP transport, and a reproducible demo.
4. Create a demo script for the 90–120 second storyboard in the spec.
5. Run the tests and report the actual results. State gaps explicitly.

## Definition of done

A fresh user can run a synthetic source-revocation flow end to end; confirmed lineage and inferred candidates are distinct; no destructive action happens without explicit approval; the unrelated seeded note is preserved; adapter failures are visible; verification is scoped and honest; the MCP tools can be called from at least one tested client; and tests/docs/demo are included.

## Required final report

Return:
- Files created/changed.
- Architecture and transport implemented.
- Exact setup/run/test commands.
- Tests run and actual results.
- Screenshots or demo evidence if available.
- Alan integration status (verified, partial or blocked) with the reason.
- Known limitations and next highest-value task.
