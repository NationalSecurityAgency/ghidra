"""Ghidra MCP Server - AI Agent integration for binary analysis."""

from .server import mcp
from .tools import register_all_tools

__version__ = "0.1.0"
__all__ = ["mcp", "register_all_tools"]
