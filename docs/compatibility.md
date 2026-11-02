# Compatibility and guarantees

This is the authoritative store matrix. Configuration is explicit; discovering
a store in the same directory never grants mutation permission.

| Store | Scan | Guarded write | Revocation | Concurrency boundary |
|---|---|---|---|---|
| Filesystem | `.md`, `.txt`, `.rst` below one root | Yes | Delete, span redaction, regeneration | Participating writers share an OS lock; fingerprint/identity rechecks; external writers can still race |
| SQLite | Every column of `memories`/`response_cache` | Yes | Delete/redact/regenerate memory; invalidate cache | Content check and mutation under SQLite write transaction |
| JSONL | Configured log; nested strings/keys | Append | Delete/redact event | Participating writers share an OS lock; retry fingerprint checks and final snapshot recheck |
| JSON vector fixture | Chunks and nested metadata | Upsert | Invalidate chunk | Shared OS lock, schema/unique-ID validation, snapshot recheck |
| Persistent Chroma | Explicitly named collections | Upsert with local 512-dimensional hashing embeddings | Invalidate item plus embedding | Shared local OS lock for participating writers; no compare-and-delete transaction for external clients |
| Redis | Explicit key patterns; strings, hashes, lists, sets, sorted sets, streams | No bundled writer | Invalidate key | WATCH/MULTI/EXEC rejects concurrent modification; unknown module types fail the scan |
| Other SQLite tables | Read-only residual discovery, subject to cap | No | No | Report residuals; owning application removes them |
| Hosted vector stores, PostgreSQL, object storage, provider transcripts | No | No | No | Outside coverage; adapters are required |

The Chroma writer is intended for the reference application's hashing index. It
refuses unlabelled collections and collections with another embedding model or
dimension, including another model of the same dimension. Read/delete operations
still support explicitly scoped external collections regardless of their embedding
model. Reference collections are labelled on creation; legacy unlabelled indexes
must be deliberately rebuilt from allowed sources rather than silently relabelled.
Unsupported Redis module types produce a coverage error and a PARTIAL receipt.
Unsupported file extensions are
reported by status. No store claims physical erasure across backups or replicas.

## Runtime and installation

- Python 3.12+; fresh locked environments were exercised on Windows with Python
  3.12 and 3.14. CI also runs Python 3.12 on Linux and Windows.
- `uv sync --frozen --extra dev --extra chroma --extra redis --python 3.12`
  installs the locked test/store dependencies without neural packages. Add
  `--extra semantic` to install the optional CPU embedding provider. The lock
  selects the explicit PyTorch CPU index on Linux/Windows; macOS uses PyPI.
- MCP 2.3 API (`MCPServer`) is required. Dependencies now declare compatible major
  ranges rather than advertising the incompatible MCP 1.x API.
- MCP stdio and Streamable HTTP share the same engine; HTTP requires a bearer token.
- The stdio smoke test launches the installed package from a directory with spaces
  and no `pyproject.toml`, without a `PYTHONPATH` shim; it auto-seeds isolated demo
  stores and creates a non-destructive plan through the eight-tool MCP surface.
- CI runs real local Chroma. Redis tests use fakeredis unless
  `REDACTO_TEST_REDIS_URL` points at a real Redis instance.
- For a runtime-only installation, `pip install .` is checked in a separate CI job.

Use `uv lock --upgrade` only as an intentional dependency update, then rerun the
suite, transport smoke tests, reference journey and benchmark before committing it.

## Enforcement and verification

All cooperating processes must use the same graph DB and local lock protocol.
`Engine.write_boundary()` serializes multi-store operations with apply and verify;
it is not a distributed transaction. A partial application write can remain if a
later store fails, and reconciliation/verification must report it.

An approved real apply activates protection before releasing that boundary.
Every active tombstone is enforced; the public listing's display limit does not
cap enforcement. Direct writes outside the guard remain possible with store access.
The reference app filters retrieval and exposes `reconcile()` to detect bypasses.

Exact residuals, advisory semantic candidates, unreachable stores, oversized records
and scan truncation are reported separately. Local hashing is lexical, with exact
quantity-scale normalization; it does not establish semantic equivalence, exchange
rates, multilingual recall or provenance. Different embedding versions are not
compared; old tombstones retain their keyed fingerprint/anchor/shingle checks.
Model mismatches are now reported as degraded semantic protection in status and
ingestion results, and as incomplete semantic coverage/PARTIAL during verification.
Restore the original provider and immutable model revision to compare an old
tombstone's vectors. See [semantic-discovery.md](semantic-discovery.md) for the
optional multilingual provider and its actual evaluation results.

Receipts are HMAC authenticated using the configured key version. Keep old keys to
validate old receipts. Key retirement considers active tombstones and all retained
signed receipts, requests and plan-item fingerprints. Unreadable receipt key
references prevent a retirement recommendation. Unsigned legacy receipts remain
unsigned and are not retroactively authenticated. Exported copies that no longer
exist in this database cannot be inventoried; preserve their verification keys too.
HMAC detects edits by someone without the signing key; it is not external immutable
audit storage and does not protect against the local owner replacing both artifacts
and keys. Operator identity, OAuth/RBAC, key vaults, off-host audit retention and
distributed writer coordination remain production deployment requirements.
