"""End-to-end MCP client tests over the real stdio transport.

These prove tool discovery and a full scan -> plan -> apply -> verify cycle from
an actual MCP client session, not from direct Python calls.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from helpers import seeded_settings
from redacto.engine import Engine
from redacto.fixtures import SOURCE_ID

ROOT = Path(__file__).resolve().parents[1]


def _payload(result) -> dict:
    structured = getattr(result, "structuredContent", None)
    if structured:
        return structured
    content = getattr(result, "content", None) or []
    if content and getattr(content[0], "text", None):
        try:
            return json.loads(content[0].text)
        except json.JSONDecodeError:
            return {"raw": content[0].text}
    return {}


async def _with_session(env: dict, callback):
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "redacto.mcp.stdio_server"],
        env=env,
        cwd=str(ROOT),
    )
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            return await callback(session)


def _env_for(settings) -> dict:
    return {
        **os.environ,
        "PYTHONPATH": str(ROOT / "src"),
        "REDACTO_DB_PATH": str(settings.db_path),
        "REDACTO_WORKSPACE_ROOT": str(settings.workspace_root),
        "REDACTO_SQLITE_PATH": str(settings.sqlite_store_path),
        "REDACTO_JSONL_PATH": str(settings.jsonl_log_path),
        "REDACTO_VECTOR_PATH": str(settings.vector_fixture_path),
        "REDACTO_HMAC_KEY": settings.current_hmac_key,
        "REDACTO_HMAC_KEY_VERSION": str(settings.hmac_key_version),
        "REDACTO_DRY_RUN": "false",
    }


async def _full_cycle(settings):
    env = _env_for(settings)

    async def callback(session: ClientSession):
        tools = await session.list_tools()
        names = {tool.name for tool in tools.tools}
        assert names == {
            "redacto_status",
            "redacto_scan",
            "redacto_trace",
            "redacto_plan",
            "redacto_apply",
            "redacto_verify",
            "redacto_tombstones",
            "redacto_quarantine",
        }

        status = _payload(await session.call_tool("redacto_status", {}))
        assert status["service"] == "redacto"
        assert len(status["adapters"]) == 4

        scan = _payload(await session.call_tool("redacto_scan", {"target_id": SOURCE_ID}))
        assert scan["ok"] is True
        assert scan["counts"]["direct_match"] == 2

        trace = _payload(await session.call_tool("redacto_trace", {"source_record_id": SOURCE_ID}))
        assert len(trace["confirmed_descendants"]) == 5

        plan = _payload(await session.call_tool("redacto_plan", {"target_id": SOURCE_ID}))
        assert plan["approval_required"] is True

        denied = _payload(
            await session.call_tool(
                "redacto_apply",
                {
                    "plan_id": plan["plan_id"],
                    "plan_version": plan["plan_version"],
                    "approval_ref": "self-approved-by-agent",
                    "confirmation_token": "made-up",
                },
            )
        )
        assert denied["ok"] is False
        assert denied["error"]["code"] == "unauthorized_apply"

        approval = Engine(settings).approve_plan(
            plan_id=plan["plan_id"], approval_ref="test-operator-approval"
        )
        applied = _payload(
            await session.call_tool(
                "redacto_apply",
                {
                    "plan_id": plan["plan_id"],
                    "plan_version": plan["plan_version"],
                    "approval_ref": "test-operator-approval",
                    "confirmation_token": approval["confirmation_token"],
                },
            )
        )
        assert applied["counts"]["succeeded"] == 7

        verified = _payload(
            await session.call_tool("redacto_verify", {"request_id": applied["request_id"]})
        )
        assert verified["counts"]["residual_matches"] == 0
        assert verified["status"] in {"VERIFIED_WITHIN_SCOPE", "NEEDS_REVIEW"}

        tombstones = _payload(await session.call_tool("redacto_tombstones", {}))
        assert tombstones["count"] == 1
        assert tombstones["tombstones"][0]["target_id"] == SOURCE_ID
        assert tombstones["tombstones"][0]["status"] == "active"

        quarantine = _payload(await session.call_tool("redacto_quarantine", {}))
        assert quarantine["ok"] is True
        return verified

    return await _with_session(env, callback)


def test_stdio_client_full_cycle(tmp_path):
    settings = seeded_settings(tmp_path)
    verified = asyncio.run(_full_cycle(settings))
    assert verified["receipt"]["scope"]["verified_stores"]


def test_stdio_client_rejects_out_of_scope_store(tmp_path):
    settings = seeded_settings(tmp_path)

    async def scenario(session: ClientSession):
        return _payload(
            await session.call_tool("redacto_scan", {"target_id": SOURCE_ID, "stores": ["/etc"]})
        )

    result = asyncio.run(_with_session(_env_for(settings), scenario))
    assert result["ok"] is False
    assert result["error"]["code"] == "out_of_scope_store"


def test_status_survives_a_broken_key_ring(tmp_path):
    settings = seeded_settings(tmp_path)
    env = _env_for(settings)
    env["REDACTO_HMAC_KEYS"] = '{"2": "rotated-only"}'
    env["REDACTO_HMAC_KEY_VERSION"] = "1"

    async def scenario(session: ClientSession):
        return _payload(await session.call_tool("redacto_status", {}))

    result = asyncio.run(_with_session(env, scenario))
    assert result.get("ok") is not False
    assert result["service"] == "redacto"
    assert result["revocation"]["protection_degraded"] is True
    assert result["revocation"]["keyring_error"]
