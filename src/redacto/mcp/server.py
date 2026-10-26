"""Transport-independent MCP server definition and tool surface."""

from __future__ import annotations

import sys
from typing import Any, Sequence

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from redacto.config import Settings, load_settings
from redacto.engine import Engine
from redacto.errors import RedactoError

READ_ONLY = ToolAnnotations(read_only_hint=True)
DESTRUCTIVE = ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=True)


def _guard(callable_fn) -> dict[str, Any]:
    """Never let a stack trace or raw exception text reach the client."""
    try:
        return callable_fn()
    except RedactoError as exc:
        return exc.as_dict()
    except Exception as exc:  # pragma: no cover - defensive boundary
        print(f"redacto internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return {
            "ok": False,
            "error": {
                "code": "internal_error",
                "message": "Unexpected server error; no action was taken.",
                "details": {"type": type(exc).__name__},
            },
        }


def create_server(settings: Settings | None = None, *, transport: str = "stdio") -> MCPServer:
    """Build the MCP server.

    Tool logic lives in the engine; this function is only wiring, so stdio and
    Streamable HTTP share exactly the same policy and authorization code.
    """
    resolved = settings or load_settings()
    engine = Engine(resolved)
    mcp = MCPServer(
        "redacto",
        version="0.1.0",
        instructions=(
            "Provenance-aware revocation. scan/trace/plan/verify are read-only. apply is "
            "destructive and requires an approved plan version plus an application-issued "
            "confirmation token; the agent cannot approve a plan. Never claim universal "
            "erasure: report VERIFIED_WITHIN_SCOPE, PARTIAL, NEEDS_REVIEW and FAILED honestly, "
            "and always disclose unreachable stores and unassessed candidates."
        ),
    )

    @mcp.tool(annotations=READ_ONLY)
    def redacto_status() -> dict[str, Any]:
        """Adapter health, configured scope, model-provider availability and current safety mode.

        Read-only. Never returns secrets, tokens, record content or file contents.
        """
        return engine.status(transport=transport)

    @mcp.tool(annotations=READ_ONLY)
    def redacto_scan(
        target_id: str,
        target_kind: str = "source",
        stores: Sequence[str] | None = None,
        depth: int = 3,
        use_model: bool = True,
        target_text: str | None = None,
    ) -> dict[str, Any]:
        """Find candidates for a revocation target. Read-only: no record is modified.

        target_kind: source | fact | secret. target_text is used only for fact/secret
        targets, is never persisted, and is only ever matched transiently.
        """
        return _guard(
            lambda: {
                "ok": True,
                **engine.scan(
                    target_id=target_id,
                    target_kind=target_kind,
                    stores=list(stores) if stores else None,
                    depth=depth,
                    use_model=use_model,
                    target_text=target_text,
                ),
            }
        )

    @mcp.tool(annotations=READ_ONLY)
    def redacto_trace(source_record_id: str, depth: int = 3) -> dict[str, Any]:
        """Explain recorded lineage and candidates for a source record. Read-only.

        Confirmed descendants (instrumented/human-verified edges) are returned separately
        from weak READ_FROM exposure links and advisory candidate relationships.
        """
        return _guard(
            lambda: {"ok": True, **engine.trace(source_id=source_record_id, depth=depth)}
        )

    @mcp.tool(annotations=READ_ONLY)
    def redacto_plan(
        target_id: str,
        mode: str = "source_revocation",
        target_kind: str = "source",
        stores: Sequence[str] | None = None,
        depth: int = 3,
        use_model: bool = True,
        target_text: str | None = None,
    ) -> dict[str, Any]:
        """Create a draft revocation plan with per-record actions and collateral risk.

        Non-destructive: creates a draft plan only. Execution requires separate,
        application-issued approval bound to this plan_id and plan_version.
        """
        return _guard(
            lambda: engine.plan(
                target_id=target_id,
                mode=mode,
                target_kind=target_kind,
                stores=list(stores) if stores else None,
                depth=depth,
                use_model=use_model,
                target_text=target_text,
            )
        )

    @mcp.tool(annotations=DESTRUCTIVE)
    def redacto_apply(
        plan_id: str,
        plan_version: int,
        approval_ref: str,
        confirmation_token: str,
        dry_run: bool | None = None,
    ) -> dict[str, Any]:
        """Apply an approved plan. Destructive; rejects unapproved or stale plans.

        Requires the exact plan_version, the approval reference a human used, and the
        short-lived single-use confirmation token issued by the application. Re-applying
        the same plan reports already-completed work instead of repeating it.
        """
        return _guard(
            lambda: engine.apply(
                plan_id=plan_id,
                plan_version=plan_version,
                approval_ref=approval_ref,
                confirmation_token=confirmation_token,
                dry_run=dry_run,
            )
        )

    @mcp.tool(annotations=READ_ONLY)
    def redacto_verify(
        request_id: str | None = None,
        receipt_id: str | None = None,
        stores: Sequence[str] | None = None,
    ) -> dict[str, Any]:
        """Rescan reachable in-scope stores and return an honest, scoped receipt.

        Verification is limited to configured reachable stores and to the detection methods
        each adapter supports. Unreachable stores are reported as gaps, never as clean.
        """
        return _guard(
            lambda: engine.verify(
                request_id=request_id,
                receipt_id=receipt_id,
                stores=list(stores) if stores else None,
            )
        )

    return mcp