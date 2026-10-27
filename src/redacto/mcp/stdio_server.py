"""stdio entry point: `redacto-stdio` or `python -m redacto.mcp.stdio_server`."""

from __future__ import annotations

import os

from redacto.mcp.server import create_server


def _seed_demo_if_missing() -> None:
    """Create the synthetic demo workspace on first launch when asked to.

    The plugin layout points the stores at its writable data folder rather than at
    the fixtures it ships, so an apply never edits files inside the plugin. With
    REDACTO_DEMO_SEED_IF_MISSING=true the demo data is created there once.
    """
    if os.environ.get("REDACTO_DEMO_SEED_IF_MISSING", "").strip().lower() not in {"1", "true", "yes"}:
        return
    from redacto.config import load_settings
    from redacto.fixtures import seed_workspace

    settings = load_settings()
    if not settings.workspace_root.exists():
        seed_workspace(settings)


def main() -> None:
    _seed_demo_if_missing()
    create_server(transport="stdio").run(transport="stdio")


if __name__ == "__main__":
    main()
