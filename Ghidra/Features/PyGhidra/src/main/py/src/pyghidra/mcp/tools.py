"""Ghidra MCP tools - Simplified implementation using PyGhidra API."""

import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from functools import wraps

from .server import mcp, get_context
from .errors import (
    BinaryNotLoadedError, FunctionNotFoundError,
    DecompilationError, GhidraMCPError
)


def unified_response(func):
    """Decorator to wrap tool responses in unified format."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
            return {"status": "success", "data": result, "error": None}
        except GhidraMCPError as e:
            return {"status": "error", "data": None, "error": str(e)}
        except Exception as e:
            return {"status": "error", "data": None, "error": f"Unexpected error: {str(e)}"}
    return wrapper


@mcp.tool()
@unified_response
def load_binary(
    binary_path: str,
    project_location: Optional[str] = None,
    project_name: Optional[str] = None,
    analyze: bool = True,
    language: Optional[str] = None,
    compiler: Optional[str] = None,
) -> Dict[str, Any]:
    """Load a binary file into Ghidra for analysis.

    Args:
        binary_path: Path to the binary file to analyze
        project_location: Optional Ghidra project directory
        project_name: Optional project name
        analyze: Whether to run auto-analysis (default True)
        language: Optional LanguageID override
        compiler: Optional CompilerSpecID override

    Returns:
        Binary metadata including architecture, entry point, function count, etc.
    """
    import pyghidra

    ctx = get_context()

    if not pyghidra.started():
        pyghidra.start()

    binary_path = Path(binary_path)
    if not binary_path.exists():
        raise FileNotFoundError(f"Binary not found: {binary_path}")

    # Use PyGhidra's public API
    from ghidra.program.flatapi import FlatProgramAPI

    # Create project using PyGhidra's launcher
    launcher = pyghidra.Launcher(
        binary_path,
        project_location=project_location,
        project_name=project_name,
        language=language,
        compiler=compiler,
    )
    program = launcher.getProgram()
    flat_api = FlatProgramAPI(program)

    # Run analysis if requested
    start_time = time.time()
    if analyze:
        from ghidra.app.services import AnalyzerService
        from ghidra.util.task import TaskMonitor
        analyzer = launcher.getState().getTool().getService(AnalyzerService)
        analyzer.reAnalyzeAll(program, program.getMemory(), TaskMonitor.DUMMY)
    analysis_time = time.time() - start_time

    # Store context
    ctx.ghidra_instance = flat_api
    ctx.current_binary = str(binary_path)
    ctx.analysis_complete = True
    ctx._launcher = launcher
    ctx._program = program

    return _extract_binary_info(program, str(binary_path), analysis_time)


def _extract_binary_info(program, binary_path: str, analysis_time: float) -> Dict[str, Any]:
    """Extract binary metadata from Ghidra program."""
    language = program.getLanguage()
    sym_table = program.getSymbolTable()

    entry_points = sym_table.getExternalEntryPointIterator()
    entry_point = entry_points.next().getOffset() if entry_points.hasNext() else 0

    return {
        "path": binary_path,
        "name": program.getName(),
        "architecture": language.getProcessor().toString(),
        "processor": language.getLanguageID().toString(),
        "endian": "big" if language.isBigEndian() else "little",
        "address_size": language.getLanguageDescription().getSize(),
        "entry_point": hex(entry_point),
        "image_base": hex(program.getImageBase().getOffset()),
        "language_id": language.getLanguageID().toString(),
        "compiler_spec_id": language.getCompilerSpec().getCompilerSpecID().toString(),
        "analysis_time_seconds": round(analysis_time, 2),
        "function_count": program.getFunctionManager().getFunctionCount(),
        "symbol_count": sym_table.getNumSymbols(),
    }


@mcp.tool()
@unified_response
def get_binary_info() -> Dict[str, Any]:
    """Get metadata about the currently loaded binary."""
    ctx = get_context()
    ctx.ensure_binary_loaded()
    return _extract_binary_info(ctx._program, ctx.current_binary, 0.0)


@mcp.tool()
@unified_response
def list_functions(
    name_filter: Optional[str] = None,
    address_filter: Optional[int] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """List functions in the binary.

    Args:
        name_filter: Optional substring to filter function names
        address_filter: Optional address to get function at that address
        limit: Maximum number of functions to return (default 100)
    """
    ctx = get_context()
    ctx.ensure_binary_loaded()

    program = ctx._program
    func_manager = program.getFunctionManager()
    functions = []

    if address_filter is not None:
        addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address_filter)
        func = func_manager.getFunctionContaining(addr)
        if func:
            functions.append(func)
    else:
        func_iter = func_manager.getFunctions(True)
        count = 0
        while func_iter.hasNext() and count < limit:
            func = func_iter.next()
            if name_filter and name_filter not in func.getName():
                continue
            functions.append(func)
            count += 1

    return [_function_to_dict(f) for f in functions]


def _function_to_dict(func) -> Dict[str, Any]:
    """Convert Ghidra function to dictionary."""
    params = [{"name": p.getName(), "type": p.getDataType().toString(), "ordinal": p.getOrdinal()}
              for p in func.getParameters()]
    locals_list = [{"name": v.getName(), "type": v.getDataType().toString()}
                   for v in func.getLocalVariables()]
    called = [f.getName() for f in func.getCalledFunctions(None)]
    calling = [f.getName() for f in func.getCallingFunctions(None)]

    return {
        "address": hex(func.getEntryPoint().getOffset()),
        "name": func.getName(),
        "signature": func.getSignature().toString(),
        "return_type": func.getReturnType().toString(),
        "parameters": params,
        "local_variables": locals_list,
        "called_functions": called,
        "calling_functions": calling,
        "is_thunk": func.isThunk(),
        "is_external": func.isExternal(),
        "comment": func.getComment(),
    }


@mcp.tool()
@unified_response
def decompile_function(address: int, timeout_seconds: int = 30) -> Dict[str, Any]:
    """Decompile a function to C-like pseudocode.

    Args:
        address: Address of the function to decompile
        timeout_seconds: Maximum time for decompilation (default 30)
    """
    ctx = get_context()
    ctx.ensure_binary_loaded()

    program = ctx._program
    addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address)
    func = program.getFunctionManager().getFunctionContaining(addr)

    if not func:
        raise FunctionNotFoundError(address)

    start_time = time.time()
    try:
        from ghidra.app.decompiler import DecompInterface

        decomp = DecompInterface()
        decomp.openProgram(program)
        result = decomp.decompileFunction(func, timeout_seconds, None)
        decomp_time = (time.time() - start_time) * 1000

        if result.depiledFunction():
            c_code = result.getDecompiledFunction().getC()
        else:
            raise DecompilationError(func.getName(), result.getErrorMessage())

        decomp.dispose()

        return {
            "function_name": func.getName(),
            "address": hex(address),
            "c_code": c_code,
            "decompilation_time_ms": round(decomp_time, 2),
            "warnings": [],
        }
    except DecompilationError:
        raise
    except Exception as e:
        raise DecompilationError(func.getName(), str(e))


@mcp.tool()
@unified_response
def get_strings(min_length: int = 4, limit: int = 100) -> List[Dict[str, Any]]:
    """Extract string references from the binary.

    Args:
        min_length: Minimum string length (default 4)
        limit: Maximum number of strings to return (default 100)
    """
    ctx = get_context()
    ctx.ensure_binary_loaded()

    program = ctx._program
    strings = []

    from ghidra.program.model.data import StringDataType
    data_iter = program.getListing().getDefinedData(True)

    count = 0
    while data_iter.hasNext() and count < limit:
        data = data_iter.next()
        if isinstance(data.getDataType(), StringDataType):
            value = data.getValue().toString()
            if len(value) >= min_length:
                refs = []
                ref_iter = program.getReferenceManager().getReferencesTo(data.getAddress())
                while ref_iter.hasNext():
                    refs.append(hex(ref_iter.next().getFromAddress().getOffset()))

                strings.append({
                    "address": hex(data.getAddress().getOffset()),
                    "value": value,
                    "length": len(value),
                    "encoding": "utf-8",
                    "references": refs[:10],
                })
                count += 1

    return strings


@mcp.tool()
@unified_response
def get_xrefs(address: int, direction: str = "to") -> List[Dict[str, Any]]:
    """Get cross-references to or from an address.

    Args:
        address: Address to get references for
        direction: "to" for references to address, "from" for references from address
    """
    ctx = get_context()
    ctx.ensure_binary_loaded()

    program = ctx._program
    addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address)
    ref_manager = program.getReferenceManager()
    xrefs = []

    if direction == "to":
        ref_iter = ref_manager.getReferencesTo(addr)
        while ref_iter.hasNext():
            ref = ref_iter.next()
            func = program.getFunctionManager().getFunctionContaining(ref.getFromAddress())
            xrefs.append({
                "from_address": hex(ref.getFromAddress().getOffset()),
                "to_address": hex(address),
                "ref_type": ref.getReferenceType().toString(),
                "is_from_external": False,
                "function_name": func.getName() if func else None,
            })
    elif direction == "from":
        ref_iter = ref_manager.getReferencesFrom(addr)
        while ref_iter.hasNext():
            ref = ref_iter.next()
            xrefs.append({
                "from_address": hex(address),
                "to_address": hex(ref.getToAddress().getOffset()),
                "ref_type": ref.getReferenceType().toString(),
                "is_from_external": False,
                "function_name": None,
            })

    return xrefs


@mcp.tool()
@unified_response
def disassemble(address: int, count: int = 10) -> List[Dict[str, Any]]:
    """Disassemble instructions at an address.

    Args:
        address: Starting address
        count: Number of instructions to disassemble (default 10)
    """
    ctx = get_context()
    ctx.ensure_binary_loaded()

    program = ctx._program
    addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address)
    code_unit_iter = program.getListing().getCodeUnits(addr, True)

    instructions = []
    for _ in range(count):
        if not code_unit_iter.hasNext():
            break

        code_unit = code_unit_iter.next()
        if not hasattr(code_unit, 'getMnemonicString'):
            continue

        operands = code_unit.toString().split(maxsplit=1)
        func = program.getFunctionManager().getFunctionContaining(code_unit.getAddress())

        instructions.append({
            "address": hex(code_unit.getAddress().getOffset()),
            "mnemonic": code_unit.getMnemonicString(),
            "operands": operands[1] if len(operands) > 1 else "",
            "bytes": [b & 0xFF for b in code_unit.getBytes()],
            "length": code_unit.getLength(),
            "function_name": func.getName() if func else None,
            "comment": code_unit.getComment(0),
        })

    return instructions


@mcp.tool()
@unified_response
def get_memory_blocks() -> List[Dict[str, Any]]:
    """Get memory block/section information."""
    ctx = get_context()
    ctx.ensure_binary_loaded()

    return [{
        "name": block.getName(),
        "start_address": hex(block.getStart().getOffset()),
        "end_address": hex(block.getEnd().getOffset()),
        "size": block.getSize(),
        "is_loaded": block.isLoaded(),
        "is_readable": block.isRead(),
        "is_writable": block.isWrite(),
        "is_executable": block.isExecute(),
        "block_type": block.getType().toString(),
    } for block in ctx._program.getMemory().getBlocks()]


@mcp.tool()
@unified_response
def get_symbols(
    symbol_type: Optional[str] = None,
    name_filter: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Get symbols from the symbol table.

    Args:
        symbol_type: Filter by symbol type (function, label, etc.)
        name_filter: Substring to filter symbol names
        limit: Maximum number of symbols to return
    """
    ctx = get_context()
    ctx.ensure_binary_loaded()

    program = ctx._program
    symbols = []
    symbol_iter = program.getSymbolTable().getAllSymbols(True)

    count = 0
    while symbol_iter.hasNext() and count < limit:
        symbol = symbol_iter.next()
        name = symbol.getName()

        if name_filter and name_filter not in name:
            continue

        sym_type = symbol.getSymbolType().toString()
        if symbol_type and symbol_type != sym_type:
            continue

        symbols.append({
            "address": hex(symbol.getAddress().getOffset()),
            "name": name,
            "symbol_type": sym_type,
            "is_primary": symbol.isPrimary(),
            "is_external": symbol.isExternal(),
            "namespace": symbol.getParentNamespace().toString() if symbol.getParentNamespace() else None,
            "comment": symbol.getComment(),
        })
        count += 1

    return symbols


@mcp.tool()
@unified_response
def search_strings(
    pattern: str,
    case_sensitive: bool = False,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Search for strings matching a pattern.

    Args:
        pattern: String pattern to search for
        case_sensitive: Case-sensitive search (default False)
        limit: Maximum results to return
    """
    ctx = get_context()
    ctx.ensure_binary_loaded()

    program = ctx._program
    results = []

    from ghidra.program.model.data import StringDataType
    data_iter = program.getListing().getDefinedData(True)

    count = 0
    while data_iter.hasNext() and count < limit:
        data = data_iter.next()
        if isinstance(data.getDataType(), StringDataType):
            value = data.getValue().toString()
            match = pattern in value if case_sensitive else pattern.lower() in value.lower()

            if match:
                results.append({
                    "address": hex(data.getAddress().getOffset()),
                    "value": value,
                    "length": len(value),
                    "encoding": "utf-8",
                    "references": [],
                })
                count += 1

    return results


@mcp.tool()
@unified_response
def get_imports() -> List[Dict[str, Any]]:
    """Get imported functions/variables."""
    ctx = get_context()
    ctx.ensure_binary_loaded()

    program = ctx._program
    imports = []
    ext_iter = program.getExternalManager().getExternalLibraryIterator()

    while ext_iter.hasNext():
        lib = ext_iter.next()
        lib_name = lib.getName()
        func_iter = lib.getIterator()

        while func_iter.hasNext():
            ext_loc = func_iter.next()
            imports.append({
                "name": ext_loc.getName(),
                "library": lib_name,
                "address": hex(ext_loc.getAddress().getOffset()) if ext_loc.getAddress() else None,
                "ordinal": None,
                "is_delayed": False,
            })

    return imports


@mcp.tool()
@unified_response
def get_exports() -> List[Dict[str, Any]]:
    """Get exported functions/variables."""
    ctx = get_context()
    ctx.ensure_binary_loaded()

    program = ctx._program
    symbol_table = program.getSymbolTable()
    entry_iter = symbol_table.getExternalEntryPointIterator()
    exports = []

    while entry_iter.hasNext():
        addr = entry_iter.next()
        symbol = symbol_table.getPrimarySymbol(addr)
        if symbol:
            exports.append({
                "name": symbol.getName(),
                "address": hex(addr.getOffset()),
                "ordinal": None,
                "is_forwarded": False,
                "forward_name": None,
            })

    return exports
