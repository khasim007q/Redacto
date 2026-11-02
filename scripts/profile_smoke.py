"""Real stdio client + CLI approval using a profile, outside the repository.

Runtime-only dependencies suffice: python scripts/profile_smoke.py
"""

import asyncio
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from redacto.workspace import WorkspaceClient


def payload(result):
    return (getattr(result, "structured_content", None) or getattr(result, "structuredContent", None)
            or json.loads(result.content[0].text))


async def main():
    with tempfile.TemporaryDirectory(prefix="redacto profile smoke ") as directory:
        root = Path(directory)
        workspace = root / "ordinary folder"
        workspace.mkdir()
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("REDACTO_") and k not in {"PYTHONPATH", "PYTHONHOME"}}

        def cli(*args):
            completed = subprocess.run([sys.executable, "-m", "redacto", *args],
                                       cwd=root, env=env, capture_output=True, text=True,
                                       encoding="utf-8", check=True)
            return json.loads(completed.stdout)

        setup = cli("setup", "--workspace", str(workspace), "--state-dir", str(root / "private state"),
                    "--managed-memory")
        profile = setup["profile"]
        application = WorkspaceClient(profile)
        private = "The confidential synthetic delivery code has twelve authorized reviewers before Thursday morning."
        public = "The public operator guide explains backups and log rotation for all users."
        application.write_document("private.md", private)
        application.write_document("public.md", public)
        application.cache("answer", private, sources=["fs:private.md"])
        config = setup["mcp_config"]["mcpServers"]["redacto"]
        params = StdioServerParameters(command=config["command"], args=config["args"],
                                      env={**env, **config["env"]}, cwd=str(root))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = {tool.name for tool in (await session.list_tools()).tools}
                assert len(tools) == 8 and "redacto_approve" not in tools
                status = payload(await session.call_tool("redacto_status", {}))
                assert status["reachable_adapter_count"] == 3
                plan = payload(await session.call_tool("redacto_plan", {"target_id": "fs:private.md", "use_model": False}))
                assert plan["ok"] and (workspace / "private.md").is_file()
                approval = cli("--profile", profile, "approve", "--plan-id", plan["plan_id"], "--ref", "profile-smoke-operator")
                applied = payload(await session.call_tool("redacto_apply", {
                    "plan_id": plan["plan_id"], "plan_version": plan["plan_version"],
                    "approval_ref": "profile-smoke-operator", "confirmation_token": approval["confirmation_token"],
                    "dry_run": False,
                }))
                assert applied["counts"]["failed"] == 0 and not (workspace / "private.md").exists()
                verified = payload(await session.call_tool("redacto_verify", {"request_id": plan["request_id"]}))
                assert verified["counts"]["records_removed"] == 2
                assert (workspace / "public.md").read_text(encoding="utf-8") == public
                replay = application.remember("replay", private)
                assert not replay["results"][0].get("admitted")
                print(json.dumps({"result": "PASS", "cwd_has_pyproject": (root / "pyproject.toml").exists(),
                                  "stores": setup["stores"], "tool_count": len(tools),
                                  "cli_approval_shared_with_mcp": True, "removed": 2,
                                  "public_preserved": True, "replay_denied": True}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
