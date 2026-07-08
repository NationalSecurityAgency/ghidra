"""Comprehensive tests for Ghidra MCP Server."""

import pytest
from unittest.mock import Mock, MagicMock, patch
from pathlib import Path

from pyghidra.mcp.models import (
    BinaryInfo, Function, Symbol, StringReference, CrossReference,
    DecompiledFunction, Instruction, MemoryBlock, ImportInfo, ExportInfo
)
from pyghidra.mcp.errors import (
    BinaryNotLoadedError, FunctionNotFoundError, DecompilationError,
    InvalidAddressError, AnalysisError
)
from pyghidra.mcp.server import GhidraContext
from pyghidra.mcp import tools


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
        assert result["architecture"] == "x86"
        assert result["endian"] == "little"
        assert result["address_size"] == 64

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
        assert result["return_type"] == "int"
        assert result["is_thunk"] is False

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
        assert result["is_primary"] is True
        assert result["is_external"] is False

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
        assert result["decompilation_time_ms"] == 150.5
        assert result["warnings"] == []

    def test_instruction_to_dict(self):
        instr = Instruction(
            address=0x401000,
            mnemonic="mov",
            operands="eax, 1",
            bytes=[0xb8, 0x01, 0x00, 0x00, 0x00],
            length=5,
            function_name="main",
            comment=None,
        )
        result = instr.to_dict()
        assert result["mnemonic"] == "mov"
        assert result["operands"] == "eax, 1"
        assert len(result["bytes"]) == 5
        assert result["function_name"] == "main"

    def test_memory_block_to_dict(self):
        block = MemoryBlock(
            name=".text",
            start_address=0x401000,
            end_address=0x402000,
            size=0x1000,
            is_loaded=True,
            is_readable=True,
            is_writable=False,
            is_executable=True,
            block_type="CODE",
        )
        result = block.to_dict()
        assert result["name"] == ".text"
        assert result["size"] == 0x1000
        assert result["is_executable"] is True
        assert result["is_writable"] is False

    def test_import_info_to_dict(self):
        imp = ImportInfo(
            name="printf",
            library="libc.so.6",
            address=0x400000,
            ordinal=42,
            is_delayed=False,
        )
        result = imp.to_dict()
        assert result["name"] == "printf"
        assert result["library"] == "libc.so.6"
        assert result["ordinal"] == 42

    def test_export_info_to_dict(self):
        exp = ExportInfo(
            name="main",
            address=0x401000,
            ordinal=1,
            is_forwarded=False,
            forward_name=None,
        )
        result = exp.to_dict()
        assert result["name"] == "main"
        assert result["ordinal"] == 1
        assert result["is_forwarded"] is False


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
        assert err.function_name == "main"
        assert err.reason == "timeout"

    def test_invalid_address_error(self):
        err = InvalidAddressError(0x999999)
        assert "0x999999" in str(err)
        assert err.address == 0x999999

    def test_analysis_error(self):
        err = AnalysisError("Analysis failed")
        assert "Analysis failed" in str(err)


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


class TestUnifiedResponseFormat:
    """Test unified response format decorator."""

    def test_success_response(self):
        @tools.unified_response
        def success_func():
            return {"key": "value"}

        result = success_func()
        assert result["status"] == "success"
        assert result["data"] == {"key": "value"}
        assert result["error"] is None

    def test_error_response_ghidra_error(self):
        @tools.unified_response
        def error_func():
            raise BinaryNotLoadedError()

        result = error_func()
        assert result["status"] == "error"
        assert result["data"] is None
        assert "No binary loaded" in result["error"]

    def test_error_response_unexpected_error(self):
        @tools.unified_response
        def error_func():
            raise ValueError("Unexpected error")

        result = error_func()
        assert result["status"] == "error"
        assert result["data"] is None
        assert "Unexpected error" in result["error"]


class TestTools:
    """Test MCP tools with mocked Ghidra backend."""

    @pytest.fixture
    def mock_context(self):
        """Create a mock context with loaded binary."""
        ctx = GhidraContext()
        ctx.ghidra_instance = Mock()
        ctx.current_binary = "/test/binary"
        ctx.analysis_complete = True
        ctx._program = Mock()
        ctx._project = Mock()
        return ctx

    @patch('pyghidra.mcp.tools.get_context')
    def test_get_binary_info_success(self, mock_get_context, mock_context):
        mock_get_context.return_value = mock_context

        # Mock program methods
        program = mock_context._program
        program.getName.return_value = "test_binary"
        program.getLanguage.return_value.getProcessor.return_value.toString.return_value = "x86"
        program.getLanguage.return_value.getLanguageDescription.return_value.getSize.return_value = 64
        program.getLanguage.return_value.isBigEndian.return_value = False
        program.getLanguage.return_value.getLanguageID.return_value.toString.return_value = "x86:LE:64:default"
        program.getLanguage.return_value.getCompilerSpec.return_value.getCompilerSpecID.return_value.toString.return_value = "default"
        program.getSymbolTable.return_value.getExternalEntryPointIterator.return_value.hasNext.return_value = False
        program.getImageBase.return_value.getOffset.return_value = 0x400000
        program.getFunctionManager.return_value.getFunctionCount.return_value = 100
        program.getSymbolTable.return_value.getNumSymbols.return_value = 500
        program.getListing.return_value.getDefinedData.return_value.hasNext.return_value = False

        result = tools.get_binary_info()

        assert result["status"] == "success"
        assert result["data"]["name"] == "test_binary"
        assert result["data"]["function_count"] == 100
        assert result["error"] is None

    @patch('pyghidra.mcp.tools.get_context')
    def test_get_binary_info_no_binary_loaded(self, mock_get_context):
        ctx = GhidraContext()
        mock_get_context.return_value = ctx

        result = tools.get_binary_info()

        assert result["status"] == "error"
        assert result["data"] is None
        assert "No binary loaded" in result["error"]

    @patch('pyghidra.mcp.tools.get_context')
    def test_list_functions_success(self, mock_get_context, mock_context):
        mock_get_context.return_value = mock_context

        # Mock function manager
        program = mock_context._program
        func_manager = program.getFunctionManager.return_value
        func_iter = Mock()
        func_iter.hasNext.side_effect = [True, False]
        func_iter.next.return_value = Mock(
            getEntryPoint=Mock(return_value=Mock(getOffset=Mock(return_value=0x401000))),
            getName=Mock(return_value="main"),
            getSignature=Mock(return_value=Mock(toString=Mock(return_value="int main()"))),
            getReturnType=Mock(return_value=Mock(toString=Mock(return_value="int"))),
            getParameters=Mock(return_value=[]),
            getLocalVariables=Mock(return_value=[]),
            getCalledFunctions=Mock(return_value=[]),
            getCallingFunctions=Mock(return_value=[]),
            isThunk=Mock(return_value=False),
            isExternal=Mock(return_value=False),
            getComment=Mock(return_value=None),
        )
        func_manager.getFunctions.return_value = func_iter

        result = tools.list_functions(limit=10)

        assert result["status"] == "success"
        assert isinstance(result["data"], list)
        assert len(result["data"]) == 1
        assert result["data"][0]["name"] == "main"

    @patch('pyghidra.mcp.tools.get_context')
    def test_decompile_function_success(self, mock_get_context, mock_context):
        mock_get_context.return_value = mock_context

        # Mock function manager
        program = mock_context._program
        func_manager = program.getFunctionManager.return_value
        func = Mock(
            getName=Mock(return_value="main"),
        )
        func_manager.getFunctionContaining.return_value = func

        # Mock decompiler
        with patch('pyghidra.mcp.tools.DecompInterface') as mock_decomp_class:
            mock_decomp = Mock()
            mock_decomp_class.return_value = mock_decomp
            mock_result = Mock()
            mock_result.depiledFunction.return_value = True
            mock_result.getDecompiledFunction.return_value.getC.return_value = "int main() { return 0; }"
            mock_decomp.decompileFunction.return_value = mock_result

            result = tools.decompile_function(0x401000)

            assert result["status"] == "success"
            assert result["data"]["function_name"] == "main"
            assert "return 0" in result["data"]["c_code"]

    @patch('pyghidra.mcp.tools.get_context')
    def test_decompile_function_not_found(self, mock_get_context, mock_context):
        mock_get_context.return_value = mock_context

        program = mock_context._program
        func_manager = program.getFunctionManager.return_value
        func_manager.getFunctionContaining.return_value = None

        result = tools.decompile_function(0x999999)

        assert result["status"] == "error"
        assert "Function not found" in result["error"]

    @patch('pyghidra.mcp.tools.get_context')
    def test_get_strings_success(self, mock_get_context, mock_context):
        mock_get_context.return_value = mock_context

        program = mock_context._program
        listing = program.getListing.return_value
        data_iter = Mock()
        data_iter.hasNext.side_effect = [True, False]

        mock_data = Mock()
        mock_data.getAddress.return_value.getOffset.return_value = 0x402000
        mock_data.getValue.return_value.toString.return_value = "Hello, World!"
        mock_data.getDataType.return_value = "StringDataType"

        data_iter.next.return_value = mock_data
        listing.getDefinedData.return_value = data_iter

        with patch('pyghidra.mcp.tools.StringDataType', str):
            result = tools.get_strings(min_length=4, limit=10)

            assert result["status"] == "success"
            assert isinstance(result["data"], list)

    @patch('pyghidra.mcp.tools.get_context')
    def test_get_xrefs_success(self, mock_get_context, mock_context):
        mock_get_context.return_value = mock_context

        program = mock_context._program
        ref_manager = program.getReferenceManager.return_value
        ref_iter = Mock()
        ref_iter.hasNext.side_effect = [True, False]

        mock_ref = Mock()
        mock_ref.getFromAddress.return_value.getOffset.return_value = 0x401000
        mock_ref.getReferenceType.return_value.toString.return_value = "CALL"
        ref_iter.next.return_value = mock_ref
        ref_manager.getReferencesTo.return_value = ref_iter

        program.getFunctionManager.return_value.getFunctionContaining.return_value = None

        result = tools.get_xrefs(0x402000, direction="to")

        assert result["status"] == "success"
        assert isinstance(result["data"], list)
        assert len(result["data"]) == 1
        assert result["data"][0]["ref_type"] == "CALL"

    @patch('pyghidra.mcp.tools.get_context')
    def test_disassemble_success(self, mock_get_context, mock_context):
        mock_get_context.return_value = mock_context

        program = mock_context._program
        listing = program.getListing.return_value
        code_unit_iter = Mock()
        code_unit_iter.hasNext.side_effect = [True, False]

        mock_code_unit = Mock()
        mock_code_unit.getAddress.return_value.getOffset.return_value = 0x401000
        mock_code_unit.getMnemonicString.return_value = "mov"
        mock_code_unit.toString.return_value = "mov eax, 1"
        mock_code_unit.getBytes.return_value = [0xb8, 0x01, 0x00, 0x00, 0x00]
        mock_code_unit.getLength.return_value = 5
        mock_code_unit.getComment.return_value = None
        mock_code_unit.__class__ = Mock()
        mock_code_unit.__class__.__name__ = "Instruction"

        code_unit_iter.next.return_value = mock_code_unit
        listing.getCodeUnits.return_value = code_unit_iter

        program.getFunctionManager.return_value.getFunctionContaining.return_value = None

        result = tools.disassemble(0x401000, count=1)

        assert result["status"] == "success"
        assert isinstance(result["data"], list)

    @patch('pyghidra.mcp.tools.get_context')
    def test_get_memory_blocks_success(self, mock_get_context, mock_context):
        mock_get_context.return_value = mock_context

        program = mock_context._program
        memory = program.getMemory.return_value

        mock_block = Mock()
        mock_block.getName.return_value = ".text"
        mock_block.getStart.return_value.getOffset.return_value = 0x401000
        mock_block.getEnd.return_value.getOffset.return_value = 0x402000
        mock_block.getSize.return_value = 0x1000
        mock_block.isLoaded.return_value = True
        mock_block.isRead.return_value = True
        mock_block.isWrite.return_value = False
        mock_block.isExecute.return_value = True
        mock_block.getType.return_value.toString.return_value = "CODE"

        memory.getBlocks.return_value = [mock_block]

        result = tools.get_memory_blocks()

        assert result["status"] == "success"
        assert isinstance(result["data"], list)
        assert len(result["data"]) == 1
        assert result["data"][0]["name"] == ".text"
        assert result["data"][0]["is_executable"] is True

    @patch('pyghidra.mcp.tools.get_context')
    def test_get_symbols_success(self, mock_get_context, mock_context):
        mock_get_context.return_value = mock_context

        program = mock_context._program
        symbol_table = program.getSymbolTable.return_value
        symbol_iter = Mock()
        symbol_iter.hasNext.side_effect = [True, False]

        mock_symbol = Mock()
        mock_symbol.getName.return_value = "main"
        mock_symbol.getAddress.return_value.getOffset.return_value = 0x401000
        mock_symbol.getSymbolType.return_value.toString.return_value = "function"
        mock_symbol.isPrimary.return_value = True
        mock_symbol.isExternal.return_value = False
        mock_symbol.getParentNamespace.return_value = None
        mock_symbol.getComment.return_value = None

        symbol_iter.next.return_value = mock_symbol
        symbol_table.getAllSymbols.return_value = symbol_iter

        result = tools.get_symbols(limit=10)

        assert result["status"] == "success"
        assert isinstance(result["data"], list)
        assert len(result["data"]) == 1
        assert result["data"][0]["name"] == "main"

    @patch('pyghidra.mcp.tools.get_context')
    def test_search_strings_success(self, mock_get_context, mock_context):
        mock_get_context.return_value = mock_context

        program = mock_context._program
        listing = program.getListing.return_value
        data_iter = Mock()
        data_iter.hasNext.side_effect = [True, False]

        mock_data = Mock()
        mock_data.getValue.return_value.toString.return_value = "Hello, World!"
        mock_data.getAddress.return_value.getOffset.return_value = 0x402000
        mock_data.getDataType.return_value = "StringDataType"

        data_iter.next.return_value = mock_data
        listing.getDefinedData.return_value = data_iter

        with patch('pyghidra.mcp.tools.StringDataType', str):
            result = tools.search_strings("Hello", case_sensitive=False, limit=10)

            assert result["status"] == "success"
            assert isinstance(result["data"], list)

    @patch('pyghidra.mcp.tools.get_context')
    def test_get_imports_success(self, mock_get_context, mock_context):
        mock_get_context.return_value = mock_context

        program = mock_context._program
        ext_manager = program.getExternalManager.return_value
        ext_iter = Mock()
        ext_iter.hasNext.side_effect = [True, False]

        mock_lib = Mock()
        mock_lib.getName.return_value = "libc.so.6"
        mock_lib.getIterator.return_value.hasNext.side_effect = [True, False]
        mock_lib.getIterator.return_value.next.return_value = Mock(
            getName=Mock(return_value="printf"),
            getAddress=Mock(return_value=Mock(getOffset=Mock(return_value=0x400000))),
        )

        ext_iter.next.return_value = mock_lib
        ext_manager.getExternalLibraryIterator.return_value = ext_iter

        result = tools.get_imports()

        assert result["status"] == "success"
        assert isinstance(result["data"], list)
        assert len(result["data"]) == 1
        assert result["data"][0]["name"] == "printf"

    @patch('pyghidra.mcp.tools.get_context')
    def test_get_exports_success(self, mock_get_context, mock_context):
        mock_get_context.return_value = mock_context

        program = mock_context._program
        symbol_table = program.getSymbolTable.return_value
        entry_iter = Mock()
        entry_iter.hasNext.side_effect = [True, False]

        mock_addr = Mock()
        mock_addr.getOffset.return_value = 0x401000
        entry_iter.next.return_value = mock_addr

        mock_symbol = Mock()
        mock_symbol.getName.return_value = "main"
        symbol_table.getPrimarySymbol.return_value = mock_symbol

        symbol_table.getExternalEntryPointIterator.return_value = entry_iter

        result = tools.get_exports()

        assert result["status"] == "success"
        assert isinstance(result["data"], list)
        assert len(result["data"]) == 1
        assert result["data"][0]["name"] == "main"


class TestLoadBinary:
    """Test load_binary tool."""

    @patch('pyghidra.mcp.tools.pyghidra')
    @patch('pyghidra.mcp.tools.get_context')
    def test_load_binary_file_not_found(self, mock_get_context, mock_pyghidra):
        ctx = GhidraContext()
        mock_get_context.return_value = ctx
        mock_pyghidra.started.return_value = True

        result = tools.load_binary("/nonexistent/binary")

        assert result["status"] == "error"
        assert "not found" in result["error"].lower() or "No such file" in result["error"]

    @patch('pyghidra.mcp.tools.pyghidra')
    @patch('pyghidra.mcp.tools.get_context')
    @patch('pyghidra.mcp.tools.Path')
    def test_load_binary_success(self, mock_path_class, mock_get_context, mock_pyghidra, tmp_path):
        ctx = GhidraContext()
        mock_get_context.return_value = ctx
        mock_pyghidra.started.return_value = True

        # Create a temporary file
        binary_file = tmp_path / "test_binary"
        binary_file.write_bytes(b"\x00" * 100)

        with patch('pyghidra.mcp.tools._setup_project') as mock_setup, \
             patch('pyghidra.mcp.tools.FlatProgramAPI') as mock_flat_api, \
             patch('pyghidra.mcp.tools._analyze_program') as mock_analyze, \
             patch('pyghidra.mcp.tools._extract_binary_info') as mock_extract:

            mock_program = Mock()
            mock_setup.return_value = (Mock(), mock_program)
            mock_flat_api_instance = Mock()
            mock_flat_api.return_value = mock_flat_api_instance
            mock_extract.return_value = BinaryInfo(
                path=str(binary_file),
                name="test_binary",
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

            result = tools.load_binary(str(binary_file))

            assert result["status"] == "success"
            assert result["data"]["name"] == "test_binary"
            assert ctx.analysis_complete is True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=pyghidra.mcp", "--cov-report=term-missing"])
