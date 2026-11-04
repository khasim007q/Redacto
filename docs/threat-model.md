# Threat model

Redacto operates on explicitly configured stores under the server's OS account.
It does not unlearn model parameters, erase external backups, control arbitrary
provider logging, or isolate another process running as the same OS user.

| Threat | Implemented boundary | Remaining risk |
|---|---|---|
| Agent self-approval | No MCP approval/review tool; version-bound operator tokens | A shell-capable agent can invoke the CLI with the same OS permissions |
| Prompt injection in stored content | Scanned content is data; deterministic policy controls actions | Advisory model assessments can be wrong |
| Scope/path escape | Fixed adapter configuration, filesystem link/alias checks | OS-level access and non-cooperating direct writers remain possible |
| Stale or concurrent edits | Expected fingerprints, local coordination, adapter checks | No distributed transaction; Chroma cannot atomically compare-and-delete |
| Reintroduction | Tombstones, guarded admission/retrieval and quarantine | Unintegrated writes and unseen semantic reformulations can bypass detection |
| Incomplete verification | Unreachable/truncated scope and residual findings reported | Parser blind spots and detector false negatives can still produce overconfident results |
| Receipt tampering | Versioned HMAC signatures and key-retirement checks | Key compromise or replacing both evidence and keys defeats local integrity |
| HTTP unauthorized access | Required bearer token, host/origin allowlists, explicit CORS | TLS/identity/credential lifecycle and OAuth gateways are deployment work |

Keys and embeddings are sensitive derived data. Restrict state-file permissions.
Embeddings are not guaranteed to be non-invertible. Client configuration backups
may contain credentials from unrelated server entries and need the same protection.

Tests exercise scoped deletion, approval replay, metadata leaks, selective edits,
concurrent writers, process death, guard bypasses, transport auth and configuration
merging. Synthetic tests do not cover every malformed record or real application.
Treat parser, identity and external-store integrations as security boundaries.
