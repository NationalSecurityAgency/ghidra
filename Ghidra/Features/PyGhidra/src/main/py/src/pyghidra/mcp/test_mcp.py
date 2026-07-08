"""Tests for Ghidra MCP Server."""

import pytest
from unittest.mock import Mock, MagicMock, patch
from pathlib import Path

from pyghidra.mcp.models import (
    BinaryInfo, Function, Symbol, StringReference, CrossReference,
    DecompiledFunction, Instruction, MemoryBlock, ImportInfo, ExportInfo
)
from pyghidra.mcp.errors import (
    BinaryNotLoadedError, FunctionNotFoundError, DecompilationError
)
from pyghidra.mcp.server import GhidraContext


class TestModels:
    """Test data models."""

    def test_binary_info_to_dict(self):
        info = BinaryInfo(
            path="/test/binary",
            name="binary",
            architecture="x86",
            processor="x86:LE:64:default",
            endian="little",
            address_size=64,
            entry_point=0x400000,
            image_base=0x400000,
            language_id="x86:LE:64:default",
            compiler_spec_id="default",
            analysis_time_seconds=1.5,
            function_count=100,
            symbol_count=500,
            string_count=50,
        )
        result = info.to_dict()
        assert result["path"] == "/test/binary"
        assert result["entry_point"] == "0x400000"
        assert result["function_count"] == 100

    def test_function_to_dict(self):
        func = Function(
            address=0x401000,
            name="main",
            signature="int main(int argc, char** argv)",
            return_type="int",
            parameters=[{"name": "argc", "type": "int"}],
            local_variables=[],
            called_functions=["printf"],
            calling_functions=[],
            is_thunk=False,
            is_external=False,
            comment=None,
        )
        result = func.to_dict()
        assert result["name"] == "main"
        assert result["address"] == "0x401000"
        assert len(result["parameters"]) == 1

    def test_symbol_to_dict(self):
        sym = Symbol(
            address=0x401000,
            name="main",
            symbol_type="function",
            is_primary=True,
            is_external=False,
            namespace=None,
            comment=None,
        )
        result = sym.to_dict()
        assert result["name"] == "main"
        assert result["symbol_type"] == "function"

    def test_decompiled_function_to_dict(self):
        decomp = DecompiledFunction(
            function_name="main",
            address=0x401000,
            c_code="int main() { return 0; }",
            decompilation_time_ms=150.5,
            warnings=[],
        )
        result = decomp.to_dict()
        assert result["function_name"] == "main"
        assert "return 0" in result["c_code"]


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
        ctx.ensure_binary_loaded()  # Should not raise

    def test_reset(self):
        ctx = GhidraContext()
        ctx.ghidra_instance = Mock()
        ctx.current_binary = "/test"
        ctx.analysis_complete = True
        ctx.reset()
        assert ctx.ghidra_instance is None
        assert ctx.current_binary is None
        assert ctx.analysis_complete is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
