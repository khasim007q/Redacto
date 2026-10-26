"""Streamable HTTP smoke test with bearer auth using a real MCP client.

Run: .venv\\Scripts\\python.exe scripts\\mcp_http_smoke.py
Starts the server on localhost, proves 401 without a token, then discovers and
calls redacto_status with a bearer token over MCP's Streamable HTTP transport.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

ROOT = Path(__file__).resolve().parents[1]
HOST, PORT = "127.0.0.1", 8791
TOKEN = "smoke-test-token-not-a-secret"
URL = f"http://{HOST}:{PORT}/mcp"


def _port_ready() -> bool:
    with socket.socket() as sock:
        sock.settimeout(0.4)
        return sock.connect_ex((HOST, PORT)) == 0


def _start_server() -> subprocess.Popen:
    env = {
        **os.environ,
        "PYTHONPATH": str(ROOT / "src"),
        "REDACTO_HTTP_HOST": HOST,
        "REDACTO_HTTP_PORT": str(PORT),
        "REDACTO_HTTP_TOKEN": TOKEN,
        "REDACTO_DB_PATH": str(ROOT / "var" / "http-smoke.sqlite3"),
        "REDACTO_WORKSPACE_ROOT": str(ROOT / "fixtures" / "workspace"),
    }
    return subprocess.Popen(
        [sys.executable, "-m", "redacto.cli", "serve", "--transport", "http"],
        env=env,
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )


async def _mcp_call() -> dict:
    client = httpx2.AsyncClient(headers={"Authorization": f"Bearer {TOKEN}"})
    async with client:
        async with streamable_http_client(URL, http_client=client) as streams:
            read_stream, write_stream = streams
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                tools = await session.list_tools()
                names = [tool.name for tool in tools.tools]
                print("tools:", names)
                result = await session.call_tool("redacto_status", {})
                structured = getattr(result, "structuredContent", None)
                payload = structured or json.loads(result.content[0].text)
                return {"tool_names": names, "status": payload}


def main() -> int:
    process = _start_server()
    try:
        for _ in range(60):
            if _port_ready():
                break
            time.sleep(0.25)
        else:
            print("FAIL: server did not start")
            return 1

        unauthenticated = httpx.post(URL, json={}, timeout=5)
        print("unauthenticated status code:", unauthenticated.status_code)
        if unauthenticated.status_code != 401:
            print("FAIL: unauthenticated request was not rejected")
            return 1

        result = asyncio.run(_mcp_call())
        ok = "redacto_status" in result["tool_names"] and result["status"]["service"] == "redacto"
        print(json.dumps(result["status"], indent=2)[:1200])
        print("RESULT:", "PASS" if ok else "FAIL")
        return 0 if ok else 1
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover
            process.kill()


if __name__ == "__main__":
    raise SystemExit(main())