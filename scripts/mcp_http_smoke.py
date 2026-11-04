"""Runtime-only HTTP MCP interoperability check in an isolated ordinary folder."""
import asyncio
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from redacto.profiles import setup_workspace


async def inspect(url, token):
    async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"}) as http:
        async with streamable_http_client(url, http_client=http) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = {tool.name for tool in (await session.list_tools()).tools}
                result = await session.call_tool("redacto_status", {})
                data = getattr(result, "structured_content", None) or json.loads(result.content[0].text)
                assert len(tools) == 8 and "redacto_approve" not in tools
                assert data["reachable_adapter_count"] == 1


def main():
    with tempfile.TemporaryDirectory(prefix="redacto HTTP compatibility ") as directory:
        root = Path(directory)
        workspace = root / "notes"
        workspace.mkdir()
        profile = setup_workspace(workspace, state_dir=root / "private state")["profile"]
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        token = secrets.token_urlsafe(32)
        env = {k: v for k, v in os.environ.items() if not k.startswith("REDACTO_") and k not in {"PYTHONPATH", "PYTHONHOME"}}
        env.update(REDACTO_PROFILE=profile, REDACTO_HTTP_TOKEN=token, REDACTO_HTTP_PORT=str(port))
        process = subprocess.Popen([sys.executable, "-m", "redacto", "serve", "--transport", "http"],
                                   cwd=root, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        url = f"http://127.0.0.1:{port}/mcp"
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError("HTTP server exited before readiness")
                try:
                    response = httpx.post(url, json={}, timeout=0.5)
                    if response.status_code == 401:
                        break
                except httpx.TransportError:
                    pass
                time.sleep(0.1)
            else:
                raise RuntimeError("HTTP server did not become ready")
            async def multiple_clients():
                await asyncio.gather(inspect(url, token), inspect(url, token))
            asyncio.run(multiple_clients())
            print(json.dumps({"result": "PASS", "independent_clients": 2,
                              "anonymous_status": response.status_code,
                              "cwd_has_pyproject": (root / "pyproject.toml").exists(), "profile_http": True}))
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
