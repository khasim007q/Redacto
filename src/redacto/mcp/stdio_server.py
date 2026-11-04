"""Local MCP stdio entry point. Never creates or seeds a workspace."""

from redacto.mcp.server import create_server


def main() -> None:
    create_server(transport="stdio").run(transport="stdio")


if __name__ == "__main__":
    main()
