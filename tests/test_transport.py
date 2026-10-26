"""HTTP transport: authentication is mandatory and enforced by middleware."""

from __future__ import annotations

import asyncio

import pytest

from helpers import seeded_settings


def _configure_env(monkeypatch, settings, token: str | None) -> None:
    monkeypatch.setenv("REDACTO_DB_PATH", str(settings.db_path))
    monkeypatch.setenv("REDACTO_WORKSPACE_ROOT", str(settings.workspace_root))
    monkeypatch.setenv("REDACTO_SQLITE_PATH", str(settings.sqlite_store_path))
    monkeypatch.setenv("REDACTO_JSONL_PATH", str(settings.jsonl_log_path))
    monkeypatch.setenv("REDACTO_VECTOR_PATH", str(settings.vector_fixture_path))
    monkeypatch.setenv("REDACTO_HTTP_HOST", "127.0.0.1")
    monkeypatch.setenv("REDACTO_HTTP_PORT", "8765")
    if token is None:
        monkeypatch.delenv("REDACTO_HTTP_TOKEN", raising=False)
    else:
        monkeypatch.setenv("REDACTO_HTTP_TOKEN", token)


def test_http_mode_refuses_to_serve_without_a_token(tmp_path, monkeypatch):
    settings = seeded_settings(tmp_path)
    _configure_env(monkeypatch, settings, None)
    from redacto.mcp import http_server

    with pytest.raises(RuntimeError):
        http_server.build_app()


def test_http_requests_require_a_valid_bearer_token(tmp_path, monkeypatch):
    settings = seeded_settings(tmp_path)
    _configure_env(monkeypatch, settings, "unit-test-token")
    from starlette.testclient import TestClient

    from redacto.mcp import http_server

    app, _ = http_server.build_app()
    # TestClient runs the ASGI lifespan, so authenticated requests reach the MCP layer.
    with TestClient(app) as client:
        anonymous = client.post("/mcp", json={})
        wrong_token = client.post("/mcp", json={}, headers={"Authorization": "Bearer nope"})
        authorized = client.post(
            "/mcp", json={}, headers={"Authorization": "Bearer unit-test-token"}
        )
    assert anonymous.status_code == 401
    assert wrong_token.status_code == 401
    assert authorized.status_code != 401


def test_non_ascii_bearer_is_rejected_not_a_500():
    from starlette.requests import Request
    from starlette.responses import JSONResponse

    from redacto.mcp.http_server import BearerAuthMiddleware

    async def app(scope, receive, send):  # pragma: no cover - not called on 401
        raise AssertionError("middleware should reject before calling the app")

    async def call_next(request):
        return JSONResponse({"ok": True})

    middleware = BearerAuthMiddleware(app=app, token="unit-test-token")
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "query_string": b"",
        "headers": [(b"authorization", "Bearer caf?".encode("utf-8"))],
        "scheme": "http",
        "server": ("testserver", 80),
        "client": ("testclient", 123),
        "root_path": "",
    }
    response = asyncio.run(middleware.dispatch(Request(scope), call_next))
    assert response.status_code == 401
