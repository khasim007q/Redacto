"""MCP stdio smoke test using a real MCP client session.

Run: .venv\\Scripts\\python.exe scripts\\mcp_smoke.py
Exits non-zero when discovery or the redacto_status call fails.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
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
    env = {
        **os.environ,
        "PYTHONPATH": str(ROOT / "src"),
        "REDACTO_DB_PATH": str(ROOT / "var" / "smoke.sqlite3"),
        "REDACTO_WORKSPACE_ROOT": str(ROOT / "fixtures" / "workspace"),
        "REDACTO_SQLITE_PATH": str(ROOT / "fixtures" / "workspace" / "agent_memory.sqlite3"),
        "REDACTO_JSONL_PATH": str(ROOT / "fixtures" / "workspace" / "agent_events.jsonl"),
        "REDACTO_VECTOR_PATH": str(ROOT / "fixtures" / "workspace" / "vector_chunks.json"),
    }
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "redacto.mcp.stdio_server"],
        env=env,
        cwd=str(ROOT),
    )
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = [tool.name for tool in tools.tools]
            print("tools:", names)
            if "redacto_status" not in names:
                print("FAIL: redacto_status not discoverable")
                return 1
            result = await session.call_tool("redacto_status", {})
            payload = _payload(result)
            print(json.dumps(payload, indent=2)[:4000])
            ok = payload.get("service") == "redacto" and "adapters" in payload
            print("RESULT:", "PASS" if ok else "FAIL")
            return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
