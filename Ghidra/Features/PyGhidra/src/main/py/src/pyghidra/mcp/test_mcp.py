"""Core tests for Ghidra MCP Server."""

import pytest
from unittest.mock import Mock, patch

from pyghidra.mcp.errors import (
    BinaryNotLoadedError, FunctionNotFoundError, DecompilationError
)
from pyghidra.mcp.server import GhidraContext
from pyghidra.mcp import tools


class TestErrors:
    """Test error classes."""

    def test_binary_not_loaded_error(self):
        err = BinaryNotLoadedError()
        assert "No binary loaded" in str(err)

    def test_function_not_found_error(self):
        err = FunctionNotFoundError(0x401000)
        assert "0x401000" in str(err)
        assert err.address == 0x401000

    def test_decompilation_error(self):
        err = DecompilationError("main", "timeout")
        assert "main" in str(err)
        assert "timeout" in str(err)


class TestContext:
    """Test GhidraContext."""

    def test_ensure_binary_loaded_raises_when_empty(self):
        ctx = GhidraContext()
        with pytest.raises(BinaryNotLoadedError):
            ctx.ensure_binary_loaded()

    def test_ensure_binary_loaded_passes_when_loaded(self):
        ctx = GhidraContext()
        ctx.ghidra_instance = Mock()
        ctx.analysis_complete = True
        ctx.ensure_binary_loaded()


class TestUnifiedResponse:
    """Test unified response decorator."""

    def test_success_response(self):
        @tools.unified_response
        def success_func():
            return {"key": "value"}

        result = success_func()
        assert result["status"] == "success"
        assert result["data"] == {"key": "value"}
        assert result["error"] is None

    def test_error_response(self):
        @tools.unified_response
        def error_func():
            raise BinaryNotLoadedError()

        result = error_func()
        assert result["status"] == "error"
        assert result["data"] is None
        assert "No binary loaded" in result["error"]


class TestTools:
    """Test MCP tools."""

    @pytest.fixture
    def mock_context(self):
        ctx = GhidraContext()
        ctx.ghidra_instance = Mock()
        ctx.current_binary = "/test/binary"
        ctx.analysis_complete = True
        ctx._program = Mock()
        return ctx

    @patch('pyghidra.mcp.tools.get_context')
    def test_get_binary_info_no_binary(self, mock_get_context):
        ctx = GhidraContext()
        mock_get_context.return_value = ctx
        result = tools.get_binary_info()
        assert result["status"] == "error"
        assert "No binary loaded" in result["error"]

    @patch('pyghidra.mcp.tools.get_context')
    def test_decompile_function_not_found(self, mock_get_context, mock_context):
        mock_get_context.return_value = mock_context
        mock_context._program.getFunctionManager.return_value.getFunctionContaining.return_value = None
        result = tools.decompile_function(0x999999)
        assert result["status"] == "error"
        assert "Function not found" in result["error"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
