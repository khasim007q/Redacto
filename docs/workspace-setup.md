# Workspace setup and connectivity

## Local clients

Install Redacto once, create a documents folder, and run:

```powershell
redacto setup --workspace "C:\path\to\notes" --client claude-desktop
```

If the command is not on PATH, use the installed virtual environment's Python:
`C:\path\to\Redacto\.venv\Scripts\python.exe -m redacto ...`.
The scanned folder needs no `pyproject.toml` and receives no sample content.

Client destinations:

| Client | Default configuration | Entry format |
|---|---|---|
| Claude Desktop | OS user Claude configuration directory | `mcpServers` |
| Claude Code | Workspace `.mcp.json` | `mcpServers` |
| Cursor | User `~/.cursor/mcp.json` | `mcpServers` |
| VS Code | Workspace `.vscode/mcp.json` | `servers`, with `type: stdio` |
| Generic | Printed only | `mcpServers` |

Use `--config PATH` if the client uses another location. JSON with comments is
not edited automatically: use `--print-only` and merge the entry in your editor.
Registration preserves unrelated values and backs up existing bytes. A different
entry with the same name needs explicit `--replace`, or choose `--name`.
Protect backups because other client entries may contain credentials.

Setup prints the profile path, by default under `~/.redacto/workspaces/`.
Reconnect that profile elsewhere without changing its scope:

```powershell
redacto connect --profile "C:\path\to\profile.json" --client cursor
redacto doctor --profile "C:\path\to\profile.json"
```

Profile flags work before or after the command. `REDACTO_PROFILE` is also supported.
The profile fixes scope and keys independently of the client's working directory
and its `.env`. The generated command uses an absolute Python executable. Rerun
connection registration if that environment moves. No client is restarted for you.

## Application integration

`setup --managed-memory` adds owned SQLite memories/cache and JSONL events. Select
this at first setup; an existing profile's mode is not silently upgraded.

```python
from redacto.workspace import WorkspaceClient
client = WorkspaceClient("/absolute/path/to/profile.json")
result = client.write_document("notes.md", "Application-provided text")
assert result["results"][0].get("admitted"), result
client.remember("summary", "Application-derived text", sources=["fs:notes.md"])
```

Route participating application writes and reads through the API. Direct access
can bypass write enforcement. Index/cache admission is not automatic for arbitrary
frameworks. Content and provenance are separate persistence operations; handle
`integration_write_incomplete` by inspecting and reconciling the store before retry.

## HTTP and browser clients

The same profile works with authenticated Streamable HTTP:

```powershell
$env:REDACTO_HTTP_TOKEN = "<strong randomly generated token>"
redacto serve --profile "C:\path\to\profile.json" --transport http
```

Endpoint: `http://127.0.0.1:8765/mcp`. Requests need `Authorization: Bearer <token>`.
HTTP settings may come from environment variables even when a profile fixes the
store scope. There is no built-in public hosting or OAuth identity service.

For a remote deployment, run behind a TLS reverse proxy, configure
`REDACTO_HTTP_ALLOWED_HOSTS` with the externally visible host (and port if sent),
and `REDACTO_HTTP_ALLOWED_ORIGINS` with exact permitted browser origins. Both are
comma-separated. CORS preflight is available for permitted origins; authentication
still applies to MCP requests. Do not expose a plain-HTTP bearer endpoint publicly.
`REDACTO_HTTP_HOST` and `REDACTO_HTTP_PORT` control the backend listener.

```powershell
redacto connect --url "https://mcp.example/mcp" --client vscode --config "C:\path\to\mcp.json"
```

HTTP exports reference a bearer-token environment variable instead of writing its
value. The MCP client's process must actually receive that environment variable.
Claude Desktop remote connectors use the application's connector UI, not the local
stdio JSON entry. Clients requiring OAuth need a compatible identity gateway; a
URL-only connector cannot use this server's bearer token automatically.

The HTTP server uses stateless JSON responses, allowing independent clients without
sticky MCP sessions. Local store locking remains single-host, not distributed.
