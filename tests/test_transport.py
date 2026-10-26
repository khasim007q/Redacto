"""HTTP transport: authentication is mandatory and enforced by middleware."""

from __future__ import annotations

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