"""stdio entry point: `redacto-stdio` or `python -m redacto.mcp.stdio_server`."""

from __future__ import annotations

from redacto.mcp.server import create_server


def main() -> None:
    create_server(transport="stdio").run(transport="stdio")


if __name__ == "__main__":
    main()
