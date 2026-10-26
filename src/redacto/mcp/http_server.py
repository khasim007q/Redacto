"""Streamable HTTP transport with bearer authentication.

Never expose this unauthenticated: without REDACTO_HTTP_TOKEN the server refuses
to start. Default bind is localhost.
"""

from __future__ import annotations

import hmac

import uvicorn
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from redacto.config import load_settings
from redacto.mcp.server import create_server


class BearerAuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, token: str):
        super().__init__(app)
        self._token = token

    async def dispatch(self, request: Request, call_next):
        header = request.headers.get("authorization", "")
        scheme, _, presented = header.partition(" ")
        # compare_digest rejects non-ASCII str; encode explicitly so a malformed
        # header is a 401, not a 500.
        presented_bytes = presented.encode("utf-8", "surrogateescape")
        token_bytes = self._token.encode("utf-8")
        if scheme.lower() != "bearer" or not hmac.compare_digest(presented_bytes, token_bytes):
            return JSONResponse(
                {"error": "unauthorized", "detail": "A valid bearer token is required."},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
        return await call_next(request)


def build_app():
    settings = load_settings()
    if not settings.http_token:
        raise RuntimeError(
            "REDACTO_HTTP_TOKEN must be set for HTTP transport; refusing to serve unauthenticated."
        )
    server = create_server(settings, transport="streamable-http")
    app = server.streamable_http_app()
    app.add_middleware(BearerAuthMiddleware, token=settings.http_token)
    return app, settings


def main() -> None:
    app, settings = build_app()
    uvicorn.run(app, host=settings.http_host, port=settings.http_port, log_level="info")


if __name__ == "__main__":
    main()
