"""MCP stdio smoke test using a real MCP client session.

Run: .venv\\Scripts\\python.exe scripts\\mcp_smoke.py
Exits non-zero when discovery or the redacto_status call fails.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[1]


def _payload(result) -> dict:
    structured = getattr(result, "structuredContent", None)
    if structured:
        return structured
    content = getattr(result, "content", None) or []
    if content and getattr(content[0], "text", None):
        return json.loads(content[0].text)
    return {}


async def main() -> int:
    # Exercise the installed package from a folder with spaces, no pyproject.toml,
    # no PYTHONPATH shim and no fixture dependency. Nothing touches user stores.
    with tempfile.TemporaryDirectory(prefix="redacto MCP smoke ") as temp:
        root = Path(temp)
        workspace = root / "state" / "workspace"
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("REDACTO_") and k not in {"PYTHONPATH", "PYTHONHOME"}}
        env.update({
            "REDACTO_DB_PATH": str(root / "state" / "graph.sqlite3"),
            "REDACTO_WORKSPACE_ROOT": str(workspace),
            "REDACTO_SQLITE_PATH": str(workspace / "agent_memory.sqlite3"),
            "REDACTO_JSONL_PATH": str(workspace / "agent_events.jsonl"),
            "REDACTO_VECTOR_PATH": str(workspace / "vector_chunks.json"),
            "REDACTO_DEMO_SEED_IF_MISSING": "true",
        })
        params = StdioServerParameters(command=sys.executable, args=["-m", "redacto.mcp.stdio_server"],
                                      env=env, cwd=str(root))
        async with stdio_client(params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                names = {tool.name for tool in (await session.list_tools()).tools}
                expected = {f"redacto_{name}" for name in ("status", "scan", "trace", "plan", "apply", "verify", "tombstones", "quarantine")}
                status = _payload(await session.call_tool("redacto_status", {}))
                plan = _payload(await session.call_tool("redacto_plan", {"target_id": "fs:acquisition-plan.md", "use_model": False}))
                ok = (names == expected and status.get("reachable_adapter_count") == 4
                      and plan.get("ok") is True and plan.get("approval_required") is True
                      and (workspace / "acquisition-plan.md").is_file())
                print(json.dumps({"tools": sorted(names), "cwd_has_pyproject": (root / "pyproject.toml").exists(),
                                  "reachable_adapters": status.get("reachable_adapter_count"),
                                  "plan_created": plan.get("ok"), "source_preserved": (workspace / "acquisition-plan.md").exists(),
                                  "result": "PASS" if ok else "FAIL"}, indent=2))
                return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
