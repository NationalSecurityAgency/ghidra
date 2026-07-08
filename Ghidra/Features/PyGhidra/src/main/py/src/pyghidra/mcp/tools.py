"""Ghidra MCP tools - Real implementation using PyGhidra API."""

import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .server import mcp, get_context
from .models import (
    BinaryInfo, Function, Symbol, StringReference, CrossReference,
    DecompiledFunction, Instruction, MemoryBlock, ImportInfo, ExportInfo
)
from .errors import (
    BinaryNotLoadedError, AnalysisError, FunctionNotFoundError,
    InvalidAddressError, DecompilationError
)


def register_all_tools():
    """Register all MCP tools. Called at module import."""
    pass


@mcp.tool()
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
        project_location: Optional Ghidra project directory (defaults to binary's parent)
        project_name: Optional project name (defaults to binary_name + "_ghidra")
        analyze: Whether to run auto-analysis (default True)
        language: Optional LanguageID override
        compiler: Optional CompilerSpecID override

    Returns:
        Binary metadata including architecture, entry point, function count, etc.
    """
    import pyghidra

    ctx = get_context()

    # Start Ghidra if not already started
    if not pyghidra.started():
        pyghidra.start()

    # Setup project and load binary
    binary_path = Path(binary_path)
    if not binary_path.exists():
        raise FileNotFoundError(f"Binary not found: {binary_path}")

    # Use PyGhidra's internal setup
    from pyghidra.core import _setup_project, _analyze_program
    from ghidra.program.flatapi import FlatProgramAPI

    project, program = _setup_project(
        binary_path,
        project_location,
        project_name,
        language,
        compiler,
        None,  # loader
        None,  # program_name
        True   # nested_project_location
    )

    flat_api = FlatProgramAPI(program)

    # Run analysis if requested
    start_time = time.time()
    if analyze:
        _analyze_program(flat_api, program)
    analysis_time = time.time() - start_time

    # Store context
    ctx.ghidra_instance = flat_api
    ctx.current_binary = str(binary_path)
    ctx.analysis_complete = True
    ctx._project = project
    ctx._program = program

    # Extract binary info
    info = _extract_binary_info(program, flat_api, str(binary_path), analysis_time)

    return info.to_dict()


def _extract_binary_info(program, flat_api, binary_path: str, analysis_time: float) -> BinaryInfo:
    """Extract binary metadata from Ghidra program."""
    # Get basic info
    name = program.getName()
    language = program.getLanguage()
    processor = language.getProcessor().toString()
    arch = language.getLanguageDescription().getSize()
    endian = "big" if language.isBigEndian() else "little"
    address_size = language.getLanguageDescription().getSize()

    # Get entry point
    entry_points = program.getSymbolTable().getExternalEntryPointIterator()
    entry_point = 0
    if entry_points.hasNext():
        entry_point = entry_points.next().getOffset()

    # Get image base
    image_base = program.getImageBase().getOffset()

    # Count functions
    func_count = program.getFunctionManager().getFunctionCount()

    # Count symbols
    symbol_count = program.getSymbolTable().getNumSymbols()

    # Count strings (defined strings)
    string_count = 0
    try:
        from ghidra.program.model.data import StringDataType
        data_iter = program.getListing().getDefinedData(True)
        while data_iter.hasNext():
            data = data_iter.next()
            if isinstance(data.getDataType(), StringDataType):
                string_count += 1
    except:
        pass

    return BinaryInfo(
        path=binary_path,
        name=name,
        architecture=processor,
        processor=language.getLanguageID().toString(),
        endian=endian,
        address_size=address_size,
        entry_point=entry_point,
        image_base=image_base,
        language_id=language.getLanguageID().toString(),
        compiler_spec_id=language.getCompilerSpec().getCompilerSpecID().toString(),
        analysis_time_seconds=analysis_time,
        function_count=func_count,
        symbol_count=symbol_count,
        string_count=string_count,
    )


@mcp.tool()
def get_binary_info() -> Dict[str, Any]:
    """Get metadata about the currently loaded binary.

    Returns:
        Binary metadata including architecture, entry point, function count, etc.
    """
    ctx = get_context()
    ctx.ensure_binary_loaded()

    program = ctx._program
    flat_api = ctx.ghidra_instance

    info = _extract_binary_info(program, flat_api, ctx.current_binary, 0.0)
    return info.to_dict()


@mcp.tool()
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

    Returns:
        List of function metadata dictionaries
    """
    ctx = get_context()
    ctx.ensure_binary_loaded()

    program = ctx._program
    func_manager = program.getFunctionManager()

    functions = []

    if address_filter is not None:
        # Get function at specific address
        addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address_filter)
        func = func_manager.getFunctionContaining(addr)
        if func:
            functions.append(func)
    else:
        # Iterate all functions
        func_iter = func_manager.getFunctions(True)
        count = 0
        while func_iter.hasNext() and count < limit:
            func = func_iter.next()
            if name_filter and name_filter not in func.getName():
                continue
            functions.append(func)
            count += 1

    return [_function_to_dict(f, program) for f in functions]


def _function_to_dict(func, program) -> Dict[str, Any]:
    """Convert Ghidra function to dictionary."""
    address = func.getEntryPoint().getOffset()
    name = func.getName()
    signature = func.getSignature().toString()
    return_type = func.getReturnType().toString()

    # Parameters
    params = []
    for param in func.getParameters():
        params.append({
            "name": param.getName(),
            "type": param.getDataType().toString(),
            "ordinal": param.getOrdinal(),
        })

    # Local variables
    locals_list = []
    for var in func.getLocalVariables():
        locals_list.append({
            "name": var.getName(),
            "type": var.getDataType().toString(),
        })

    # Called functions
    called = []
    for ref in func.getCalledFunctions(None):
        called.append(ref.getName())

    # Calling functions
    calling = []
    for ref in func.getCallingFunctions(None):
        calling.append(ref.getName())

    return {
        "address": hex(address),
        "name": name,
        "signature": signature,
        "return_type": return_type,
        "parameters": params,
        "local_variables": locals_list,
        "called_functions": called,
        "calling_functions": calling,
        "is_thunk": func.isThunk(),
        "is_external": func.isExternal(),
        "comment": func.getComment(),
    }


@mcp.tool()
def decompile_function(
    address: int,
    timeout_seconds: int = 30,
) -> Dict[str, Any]:
    """Decompile a function to C-like pseudocode.

    Args:
        address: Address of the function to decompile
        timeout_seconds: Maximum time for decompilation (default 30)

    Returns:
        Decompiled C code and metadata
    """
    ctx = get_context()
    ctx.ensure_binary_loaded()

    program = ctx._program

    # Get function at address
    addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address)
    func_manager = program.getFunctionManager()
    func = func_manager.getFunctionContaining(addr)

    if not func:
        raise FunctionNotFoundError(address)

    # Use Ghidra's decompiler
    start_time = time.time()
    try:
        from ghidra.app.decompiler import DecompInterface

        decomp = DecompInterface()
        decomp.openProgram(program)

        result = decomp.decompileFunction(func, timeout_seconds, None)
        decomp_time = (time.time() - start_time) * 1000

        if result.depiledFunction():
            c_code = result.getDecompiledFunction().getC()
            warnings = []
        else:
            raise DecompilationError(func.getName(), result.getErrorMessage())

        decomp.dispose()

        return {
            "function_name": func.getName(),
            "address": hex(address),
            "c_code": c_code,
            "decompilation_time_ms": round(decomp_time, 2),
            "warnings": warnings,
        }

    except Exception as e:
        raise DecompilationError(func.getName(), str(e))


@mcp.tool()
def get_strings(
    min_length: int = 4,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Extract string references from the binary.

    Args:
        min_length: Minimum string length (default 4)
        limit: Maximum number of strings to return (default 100)

    Returns:
        List of string reference dictionaries
    """
    ctx = get_context()
    ctx.ensure_binary_loaded()

    program = ctx._program
    strings = []

    # Get defined strings
    from ghidra.program.model.data import StringDataType
    listing = program.getListing()
    data_iter = listing.getDefinedData(True)

    count = 0
    while data_iter.hasNext() and count < limit:
        data = data_iter.next()
        if isinstance(data.getDataType(), StringDataType):
            addr = data.getAddress().getOffset()
            value = data.getValue().toString()
            if len(value) >= min_length:
                # Find references to this string
                refs = []
                ref_iter = program.getReferenceManager().getReferencesTo(data.getAddress())
                while ref_iter.hasNext():
                    refs.append(ref_iter.next().getFromAddress().getOffset())

                strings.append({
                    "address": hex(addr),
                    "value": value,
                    "length": len(value),
                    "encoding": "utf-8",
                    "references": [hex(r) for r in refs[:10]],  # Limit refs
                })
                count += 1

    return strings


@mcp.tool()
def get_xrefs(
    address: int,
    direction: str = "to",
) -> List[Dict[str, Any]]:
    """Get cross-references to or from an address.

    Args:
        address: Address to get references for
        direction: "to" for references to address, "from" for references from address

    Returns:
        List of cross-reference dictionaries
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
            from_addr = ref.getFromAddress().getOffset()
            ref_type = ref.getReferenceType().toString()

            # Get function name if in a function
            func_name = None
            func = program.getFunctionManager().getFunctionContaining(ref.getFromAddress())
            if func:
                func_name = func.getName()

            xrefs.append({
                "from_address": hex(from_addr),
                "to_address": hex(address),
                "ref_type": ref_type,
                "is_from_external": False,
                "function_name": func_name,
            })

    elif direction == "from":
        ref_iter = ref_manager.getReferencesFrom(addr)
        while ref_iter.hasNext():
            ref = ref_iter.next()
            to_addr = ref.getToAddress().getOffset()
            ref_type = ref.getReferenceType().toString()

            xrefs.append({
                "from_address": hex(address),
                "to_address": hex(to_addr),
                "ref_type": ref_type,
                "is_from_external": False,
                "function_name": None,
            })

    return xrefs


@mcp.tool()
def disassemble(
    address: int,
    count: int = 10,
) -> List[Dict[str, Any]]:
    """Disassemble instructions at an address.

    Args:
        address: Starting address
        count: Number of instructions to disassemble (default 10)

    Returns:
        List of instruction dictionaries
    """
    ctx = get_context()
    ctx.ensure_binary_loaded()

    program = ctx._program
    addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address)
    listing = program.getListing()

    instructions = []
    code_unit_iter = listing.getCodeUnits(addr, True)

    for i in range(count):
        if not code_unit_iter.hasNext():
            break

        code_unit = code_unit_iter.next()
        if not hasattr(code_unit, 'getMnemonicString'):
            continue

        instr_addr = code_unit.getAddress().getOffset()
        mnemonic = code_unit.getMnemonicString()
        operands = code_unit.toString().split(maxsplit=1)
        operands_str = operands[1] if len(operands) > 1 else ""

        # Get bytes
        bytes_list = []
        for byte in code_unit.getBytes():
            bytes_list.append(byte & 0xFF)

        # Get function name
        func_name = None
        func = program.getFunctionManager().getFunctionContaining(code_unit.getAddress())
        if func:
            func_name = func.getName()

        instructions.append({
            "address": hex(instr_addr),
            "mnemonic": mnemonic,
            "operands": operands_str,
            "bytes": bytes_list,
            "length": code_unit.getLength(),
            "function_name": func_name,
            "comment": code_unit.getComment(0),
        })

    return instructions


@mcp.tool()
def get_memory_blocks() -> List[Dict[str, Any]]:
    """Get memory block/section information.

    Returns:
        List of memory block dictionaries
    """
    ctx = get_context()
    ctx.ensure_binary_loaded()

    program = ctx._program
    memory = program.getMemory()

    blocks = []
    for block in memory.getBlocks():
        blocks.append({
            "name": block.getName(),
            "start_address": hex(block.getStart().getOffset()),
            "end_address": hex(block.getEnd().getOffset()),
            "size": block.getSize(),
            "is_loaded": block.isLoaded(),
            "is_readable": block.isRead(),
            "is_writable": block.isWrite(),
            "is_executable": block.isExecute(),
            "block_type": block.getType().toString(),
        })

    return blocks


@mcp.tool()
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

    Returns:
        List of symbol dictionaries
    """
    ctx = get_context()
    ctx.ensure_binary_loaded()

    program = ctx._program
    symbol_table = program.getSymbolTable()

    symbols = []
    symbol_iter = symbol_table.getAllSymbols(True)

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

    Returns:
        List of matching string dictionaries
    """
    ctx = get_context()
    ctx.ensure_binary_loaded()

    program = ctx._program
    results = []

    from ghidra.program.model.data import StringDataType
    listing = program.getListing()
    data_iter = listing.getDefinedData(True)

    count = 0
    while data_iter.hasNext() and count < limit:
        data = data_iter.next()
        if isinstance(data.getDataType(), StringDataType):
            value = data.getValue().toString()

            if case_sensitive:
                match = pattern in value
            else:
                match = pattern.lower() in value.lower()

            if match:
                addr = data.getAddress().getOffset()
                results.append({
                    "address": hex(addr),
                    "value": value,
                    "length": len(value),
                    "encoding": "utf-8",
                    "references": [],
                })
                count += 1

    return results


@mcp.tool()
def get_imports() -> List[Dict[str, Any]]:
    """Get imported functions/variables.

    Returns:
        List of import dictionaries
    """
    ctx = get_context()
    ctx.ensure_binary_loaded()

    program = ctx._program
    imports = []

    # Get external references
    ext_manager = program.getExternalManager()
    ext_iter = ext_manager.getExternalLibraryIterator()

    while ext_iter.hasNext():
        lib = ext_iter.next()
        lib_name = lib.getName()

        # Get functions from this library
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
def get_exports() -> List[Dict[str, Any]]:
    """Get exported functions/variables.

    Returns:
        List of export dictionaries
    """
    ctx = get_context()
    ctx.ensure_binary_loaded()

    program = ctx._program
    exports = []

    # Get external entry points
    symbol_table = program.getSymbolTable()
    entry_iter = symbol_table.getExternalEntryPointIterator()

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
