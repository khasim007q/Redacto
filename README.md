# Redacto

Provenance-aware revocation for AI application context. Find source copies and
known derivatives, review uncertain matches, approve a versioned plan, remove or
redact supported records, and verify the configured scope.

## Install and connect

Python 3.12+ is required. From this repository:

```powershell
uv sync --frozen --python 3.12
.\.venv\Scripts\python.exe -m redacto setup --workspace "C:\path\to\notes" --client claude-desktop
```

The notes folder must exist. It needs no Python project file. Setup generates a
private profile and random keys, then registers the MCP server. Existing client
settings are merged with a backup; conflicting server entries require `--replace`
or another `--name`. Restart the client and call `redacto_status`.

Other clients: `--client claude-code`, `cursor`, or `vscode`. Use `--config PATH`
for an explicit client JSON file, or `--print-only` to inspect the generated entry.
With no client selected, setup prints a generic MCP configuration.

Linux/macOS: replace `.venv\Scripts\python.exe` with `.venv/bin/python`.
An installed wheel also provides the `redacto` command; launch from any directory.

## Workflow

1. Check `redacto_status` and its configured stores.
2. Use `redacto_scan`, `redacto_trace` and `redacto_plan` to assess the request.
3. Review uncertain items through the operator CLI. Approve the exact plan:

   ```powershell
   redacto approve --profile "C:\path\to\profile.json" --plan-id PLAN_ID --ref "operator-ticket"
   ```

4. Supply that approval reference, version and single-use token to `redacto_apply`.
5. Use `redacto_verify` for a signed scoped receipt. Inspect remaining review items,
   residual findings and unavailable stores.

MCP exposes eight tools: status, scan, trace, plan, apply, verify, tombstones and
quarantine. Approval and item review remain operator actions. A client with shell
access can run the operator CLI; this is not OS-level role isolation.

## Integration

Add `--managed-memory` at setup to create owned SQLite memory/cache and JSONL
stores. `WorkspaceClient(profile)` guards application writes and reads, and
records instrumented lineage when sources are supplied. External Chroma and Redis
adapters are optional. Other databases require explicit integration.

[Setup and connectivity](docs/workspace-setup.md) ·
[Compatibility and limits](docs/compatibility.md) ·
[Architecture](docs/architecture.md) · [Semantic discovery](docs/semantic-discovery.md) ·
[Key rotation](docs/key-rotation.md) · [Threat model](docs/threat-model.md)

## Development

```powershell
uv sync --frozen --extra dev --extra chroma --extra redis --python 3.12
uv run --no-sync python -m pytest -q
uv run --no-sync python tests/run_benchmark.py --out var/benchmark.json
uv run --no-sync python scripts/profile_smoke.py
uv run --no-sync python scripts/mcp_http_smoke.py
```

Synthetic regression data and labelled evaluations live under `tests/` and are
excluded from the runtime wheel. CI defines Linux/Windows/macOS checks on Python
3.12/3.14. A configured workflow is not evidence that every named client has been
manually tested.

Redacto does not unlearn model weights or erase inaccessible stores, provider
transcripts, replicas or backups. Semantic similarity is advisory. Scoped receipts
do not prove universal or semantic absence; inspect coverage and residual findings.
