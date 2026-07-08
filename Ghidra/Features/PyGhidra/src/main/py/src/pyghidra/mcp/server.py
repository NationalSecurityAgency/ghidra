"""Ghidra MCP Server - Core server implementation."""

import argparse
import logging
from typing import Any, Dict, Optional

from fastmcp import FastMCP

from .errors import BinaryNotLoadedError

logger = logging.getLogger(__name__)

mcp = FastMCP(
    "Ghidra MCP Server",
    instructions="""
    Ghidra MCP Server provides AI Agent access to Ghidra's binary analysis capabilities.
    
    Core workflow:
    1. load_binary - Load and analyze a binary file
    2. get_binary_info - Get binary metadata
    3. list_functions - List all functions
    4. decompile_function - Decompile to C pseudocode
    5. get_strings - Extract string references
    6. get_xrefs - Analyze cross-references
    
    Use cases:
    - Reverse engineering automation
    - Vulnerability research
    - Malware analysis
    - CTF challenge solving
    """,
)


class GhidraContext:
    """Global context for Ghidra analysis state."""

    def __init__(self):
        self.ghidra_instance: Optional[Any] = None
        self.current_binary: Optional[str] = None
        self.analysis_complete: bool = False

    def ensure_binary_loaded(self) -> None:
        """Ensure a binary is loaded before operations."""
        if not self.ghidra_instance or not self.analysis_complete:
            raise BinaryNotLoadedError()

    def reset(self) -> None:
        """Reset context for new analysis."""
        self.ghidra_instance = None
        self.current_binary = None
        self.analysis_complete = False


# Global context
_context = GhidraContext()


def get_context() -> GhidraContext:
    """Get the global Ghidra context."""
    return _context


def run_server(
    transport: str = "stdio",
    host: str = "127.0.0.1",
    port: int = 8000,
    path: str = "/mcp",
) -> None:
    """Run the MCP server.

    Args:
        transport: Transport mechanism (stdio, sse, http)
        host: Host for SSE/HTTP transport
        port: Port for SSE/HTTP transport
        path: Path for HTTP transport
    """
    logger.info(f"Starting Ghidra MCP Server with {transport} transport")

    if transport == "stdio":
        mcp.run(transport="stdio")
    elif transport == "sse":
        mcp.run(transport="sse", host=host, port=port)
    elif transport == "http":
        mcp.run(transport="http", host=host, port=port, path=path)
    else:
        raise ValueError(f"Unsupported transport: {transport}")


def main() -> None:
    """Main entry point for MCP server."""
    parser = argparse.ArgumentParser(description="Ghidra MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "http"],
        default="stdio",
        help="Transport mechanism (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host for SSE/HTTP transport (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for SSE/HTTP transport (default: 8000)",
    )
    parser.add_argument(
        "--path",
        default="/mcp",
        help="Path for HTTP transport (default: /mcp)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level (default: INFO)",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    run_server(
        transport=args.transport,
        host=args.host,
        port=args.port,
        path=args.path,
    )


if __name__ == "__main__":
    main()
