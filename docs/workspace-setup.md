# One profile for your folder, Claude and your application

Redacto is installed once. The folder it scans can contain ordinary Markdown,
text or JSON files; it does **not** need `pyproject.toml`. That file belongs to
the Redacto source installation, not to the documents being revoked.

## Install and connect

From the cloned Redacto repository on Windows, with Python 3.12+ and uv installed:

```powershell
uv sync --frozen --python 3.12
.\.venv\Scripts\python.exe -m redacto setup --workspace "C:\Users\YOU\Documents\Agent Notes"
```

Create that documents folder first if it does not exist. Setup leaves its content
alone. It creates a per-workspace state directory under
`~/.redacto/workspaces/<workspace-hash>/` and prints:

- `profile`: the absolute path to save for operator commands and application code.
- `stores`: only `filesystem` for this command.
- `mcp_config`: a ready-to-paste `mcpServers.redacto` entry with the absolute Python
  executable and **one** environment variable, `REDACTO_PROFILE`.

Merge that server entry into Claude Desktop's existing MCP JSON configuration,
or enter the same command, arguments and environment in your MCP client's local
server settings. For Claude Code, the entry can be used in its `.mcp.json` local
server configuration. Preserve any other servers already configured. Restart or
reconnect the client. Setup prints configuration; it does not edit client files.

Keep the Redacto virtual environment at its installed path: the generated command
points to its Python executable. If you move/recreate it, rerun setup from the new
installation and replace the client entry. Linux/macOS use `.venv/bin/python`.

Check the exact same profile from any working directory:

```powershell
& "C:\path\to\Redacto\.venv\Scripts\python.exe" -m redacto --profile "C:\path\to\profile.json" doctor
```

`doctor` checks configured adapter connections and keys without scanning content,
deleting records or downloading weights. A missing enabled store is an error; it
is never silently dropped from verification scope. Rerunning setup preserves keys,
profiles and stores. It does not recreate lost stores. Conflicting scopes or an
unowned, nonempty state directory are rejected.

## An interview demo with sample data

Choose a **new or empty** folder:

```powershell
.\.venv\Scripts\python.exe -m redacto setup --workspace "$env:USERPROFILE\Downloads\Redacto Interview Demo" --demo
```

Use the printed MCP configuration. The explicit `--demo` creates synthetic files,
SQLite memory/cache, JSONL events, vector fixtures and a provenance graph. Nothing
is seeded on ordinary-folder setup or profile-based server startup.

Ask Claude to call `redacto_status`, trace `fs:acquisition-plan.md`, and plan its
revocation. Explain which items have confirmed lineage and which need review.
Approve the exact returned plan from your terminal, using **the printed profile**:

```powershell
.\.venv\Scripts\python.exe -m redacto --profile "C:\path\to\profile.json" approve --plan-id PLAN_ID --ref "interview-operator"
```

Have Claude apply with the returned version, token and approval reference, first
with `dry_run: true`, then `dry_run: false`. Verify the request and inspect the
receipt. Eight MCP tools remain exposed; approval and item review are operator
actions. A client with shell access can also run the CLI, so local CLI separation
is not an operating-system identity boundary.

## Connect application memory without optional databases

Use a different workspace/state profile from the seeded demo:

```powershell
.\.venv\Scripts\python.exe -m redacto setup --workspace "C:\path\to\Agent Notes" --managed-memory
```

This adds owned empty SQLite `memories`/`response_cache` tables and a JSONL event
store under private state. It never initializes arbitrary existing application
databases. All three stores are in scope. No Chroma, Redis, neural model or API
key is required.

In trusted Python application code:

```python
from redacto.workspace import WorkspaceClient

client = WorkspaceClient(r"C:\path\to\profile.json")
private = 'The private flight named "Azure Finch" launches after confidential clearance on Tuesday morning.'
public = "The public support guide explains log rotation and backup recovery for all operators."

client.write_document("private.md", private)
client.write_document("public.md", public)
result = client.remember(
    "mixed", private + "\n" + public,
    sources=["fs:private.md", "fs:public.md"],
)
assert result["results"][0].get("admitted"), result  # Handle refused/held writes.
client.cache("answer", private, sources=["fs:private.md"])
client.append_event("answer-1", private, sources=["fs:private.md"])
record = client.read("mem:mixed")
```

Every method guards the whole incoming envelope. Rejected/quarantined writes
return their decision and never enter these stores. Dependents cannot be written
from a missing, revoked, oversized or guard-restricted source. Reads guard current
stored content too, including direct replays that bypassed the SDK. Event IDs must
be unique; document parent folders must already exist. Other document/memory/cache
writes replace their existing identity, with lineage retained conservatively.

Use the same profile for planning, review, approval and verification. After
revoking `fs:private.md`, the mixed memory is offered for review. Choose the
planned passage edit:

```powershell
.\.venv\Scripts\python.exe -m redacto --profile "C:\path\to\profile.json" review-item --plan-id PLAN_ID --item-id ITEM_ID --decision approved --action redact --reviewer "local-operator"
```

Review changes the plan version and invalidates old tokens. Issue fresh approval
and apply that version. The private passage becomes `[REDACTED]`; the public
paragraph remains. `--action delete` explicitly chooses whole-record deletion.
Approving without `--action` selects redaction when a planned offer exists.

## Scope and limits

- Passage offers match exact source sentences/lines with case and whitespace
  variation. They require at least eight words/32 characters per passage and eight
  retained words. Up to 128 source passages and 32 span forms are considered for
  candidates within 256 KB. They do not rewrite unseen paraphrases or prove the
  rest of a record is safe. Offers exceeding a bounded window-hashing work budget
  are omitted. Survivor verification can still report residuals.
- Edits cover supported files, SQLite fields and decoded JSONL strings, including
  nested arguments. JSONL preserves values, event identity and valid JSON; raw
  formatting may change. Duplicate JSON keys, key collisions or identity-changing
  edits are refused. Caches/indexes retain their invalidation behavior.
- Source-passage offers require review even for confirmed mixed descendants.
  Optional regeneration from allowed parents remains available. Similarity alone
  never authorizes an edit.
- Direct store access can bypass these writes. The SDK filters tested replays on
  reads; `ingest`/verification report configured-store bypasses. Unknown semantic
  leaks, external stores, backups and model weights remain outside any universal
  erasure guarantee.
- Participating processes share a local lock and one graph database. Content and
  provenance stores are not a distributed transaction. `integration_write_incomplete`
  reports a known or uncertain content write when later persistence fails; inspect
  the store and repair/reconcile lineage before retrying.
- Profiles ignore ambient `REDACTO_*` overrides and cwd `.env`. Edit the strict
  profile `options` to configure embeddings/scan limits; existing environment-only
  deployments remain supported separately. HTTP/model-assessor credentials and
  external store connections use that existing configuration path.
- `keys.json` contains versioned random HMAC keys; retain old versions needed by
  tombstones and receipts. Protect the state directory with your OS account
  permissions. POSIX setup uses directory mode 0700 and JSON mode 0600; Windows
  relies on the enclosing directory's ACL. This is not encryption or a sandbox
  against another process running as your user.

For the larger persistent Chroma example, see [reference application](reference-application.md).
The automated `python scripts/profile_smoke.py` runs setup, real MCP discovery,
separate-process CLI approval, apply, verify and replay denial in temporary folders
with spaces and no `pyproject.toml`. It needs runtime dependencies only.
