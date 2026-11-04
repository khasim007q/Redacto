# Compatibility and guarantees

| Surface | Implementation | Evidence / limit |
|---|---|---|
| stdio | Standard MCP subprocess, UTF-8 JSON-RPC | Real SDK client cycle outside a project directory |
| Streamable HTTP | Authenticated `/mcp`, stateless JSON responses | Independent SDK clients; origin/host/auth/CORS tests |
| Browser HTTP | Explicit origin allowlist and CORS headers | Protocol tests; requires bearer-header support |
| Claude Desktop/Code, Cursor, VS Code | Client-specific configuration exports and registration | Schemas tested; no claim of manual GUI validation for every release |
| OAuth-only web connectors | No native OAuth provider | Requires external identity integration |
| Legacy HTTP+SSE-only clients | No legacy SSE endpoint | Use a Streamable HTTP-capable client or bridge |
| Windows, Linux, macOS | Python 3.12+; CI matrix covers 3.12/3.14 | Optional native dependencies have platform-specific availability |
| Remote/cloud workers | HTTP protocol works with appropriate hosting/auth | Local filesystem scope belongs to the server host; no access to the user's laptop by magic |

Client configuration formats are not part of the MCP wire protocol. See the
[VS Code configuration reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration),
[Claude Code MCP documentation](https://code.claude.com/docs/en/mcp) and
[Cursor MCP documentation](https://docs.cursor.com/context/model-context-protocol).
MCP transport requirements: [official specification](https://modelcontextprotocol.io/specification/latest/basic/transports).

## Stores

| Adapter | Scope | Operations / important limits |
|---|---|---|
| Filesystem | Explicit root; `.md`, `.txt`, `.rst` | Delete, UTF-8 redaction, regeneration; links/aliases rejected; other formats unscanned |
| SQLite | Explicit file, approved memories/response_cache schema | Delete/redact/regenerate memories, invalidate cache; arbitrary application schemas unsupported |
| JSONL | Explicit event file | Scan/delete/selective decoded-string redaction; entire file currently parsed in memory; parser edge cases require adversarial scrutiny |
| JSON vector adapter | Explicit JSON chunks file | Delete/invalidate records; embedding metadata is implementation-specific |
| Chroma (optional extra) | Explicit local persistence path and named collections | Delete/invalidate; no cross-call compare-and-delete transaction; writes require matching model labels |
| Redis (optional extra) | Explicit URL and key patterns | Scoped scan/invalidation; WATCH/MULTI detects concurrent changes; no remote replica erasure claim |

Profiles enable only selected stores. A missing enabled store is a coverage gap,
not silently removed. `--managed-memory` owns only the stores it creates. Existing
applications need explicit schema/write-path integration. Optional adapters use
environment configuration; profiles do not yet provide an external-store wizard.

## Runtime boundary

No source checkout, fixture directory or project file is needed after installation.
The Python runtime and dependencies must exist on the machine executing stdio.
Neural embeddings are optional and require separately installed cached/downloaded
weights. HTTP hosting, TLS, identity provisioning and client-specific network access
are deployment responsibilities. Universal compatibility with every host application,
authentication scheme or protocol version is not a testable guarantee here.
