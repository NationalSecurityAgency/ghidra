"""Ghidra MCP data models for structured JSON output."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class BinaryInfo:
    """Binary metadata from Ghidra analysis."""

    path: str
    name: str
    architecture: str
    processor: str
    endian: str
    address_size: int
    entry_point: int
    image_base: int
    language_id: str
    compiler_spec_id: str
    analysis_time_seconds: float
    function_count: int
    symbol_count: int
    string_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "name": self.name,
            "architecture": self.architecture,
            "processor": self.processor,
            "endian": self.endian,
            "address_size": self.address_size,
            "entry_point": hex(self.entry_point),
            "image_base": hex(self.image_base),
            "language_id": self.language_id,
            "compiler_spec_id": self.compiler_spec_id,
            "analysis_time_seconds": round(self.analysis_time_seconds, 2),
            "function_count": self.function_count,
            "symbol_count": self.symbol_count,
            "string_count": self.string_count,
        }


@dataclass
class Function:
    """Function representation from Ghidra."""

    address: int
    name: str
    signature: str
    return_type: str
    parameters: List[Dict[str, str]]
    local_variables: List[Dict[str, str]]
    called_functions: List[str]
    calling_functions: List[str]
    is_thunk: bool
    is_external: bool
    comment: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": hex(self.address),
            "name": self.name,
            "signature": self.signature,
            "return_type": self.return_type,
            "parameters": self.parameters,
            "local_variables": self.local_variables,
            "called_functions": self.called_functions,
            "calling_functions": self.calling_functions,
            "is_thunk": self.is_thunk,
            "is_external": self.is_external,
            "comment": self.comment,
        }


@dataclass
class Symbol:
    """Symbol from Ghidra symbol table."""

    address: int
    name: str
    symbol_type: str  # function, data, label, etc.
    is_primary: bool
    is_external: bool
    namespace: Optional[str]
    comment: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": hex(self.address),
            "name": self.name,
            "symbol_type": self.symbol_type,
            "is_primary": self.is_primary,
            "is_external": self.is_external,
            "namespace": self.namespace,
            "comment": self.comment,
        }


@dataclass
class StringReference:
    """String reference found in binary."""

    address: int
    value: str
    length: int
    encoding: str
    references: List[int]  # addresses that reference this string

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": hex(self.address),
            "value": self.value,
            "length": self.length,
            "encoding": self.encoding,
            "references": [hex(ref) for ref in self.references],
        }


@dataclass
class CrossReference:
    """Cross-reference between addresses."""

    from_address: int
    to_address: int
    ref_type: str  # call, jump, data, read, write
    is_from_external: bool
    function_name: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_address": hex(self.from_address),
            "to_address": hex(self.to_address),
            "ref_type": self.ref_type,
            "is_from_external": self.is_from_external,
            "function_name": self.function_name,
        }


@dataclass
class DecompiledFunction:
    """Decompiled function output."""

    function_name: str
    address: int
    c_code: str
    decompilation_time_ms: float
    warnings: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "function_name": self.function_name,
            "address": hex(self.address),
            "c_code": self.c_code,
            "decompilation_time_ms": round(self.decompilation_time_ms, 2),
            "warnings": self.warnings,
        }


@dataclass
class Instruction:
    """Disassembled instruction."""

    address: int
    mnemonic: str
    operands: str
    bytes: List[int]
    length: int
    function_name: Optional[str]
    comment: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": hex(self.address),
            "mnemonic": self.mnemonic,
            "operands": self.operands,
            "bytes": [hex(b) for b in self.bytes],
            "length": self.length,
            "function_name": self.function_name,
            "comment": self.comment,
        }


@dataclass
class MemoryBlock:
    """Memory block/section information."""

    name: str
    start_address: int
    end_address: int
    size: int
    is_loaded: bool
    is_readable: bool
    is_writable: bool
    is_executable: bool
    block_type: str  # CODE, DATA, BSS, etc.

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "start_address": hex(self.start_address),
            "end_address": hex(self.end_address),
            "size": self.size,
            "is_loaded": self.is_loaded,
            "is_readable": self.is_readable,
            "is_writable": self.is_writable,
            "is_executable": self.is_executable,
            "block_type": self.block_type,
        }


@dataclass
class ImportInfo:
    """Imported function/variable."""

    name: str
    library: str
    address: int
    ordinal: Optional[int]
    is_delayed: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "library": self.library,
            "address": hex(self.address),
            "ordinal": self.ordinal,
            "is_delayed": self.is_delayed,
        }


@dataclass
class ExportInfo:
    """Exported function/variable."""

    name: str
    address: int
    ordinal: Optional[int]
    is_forwarded: bool
    forward_name: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "address": hex(self.address),
            "ordinal": self.ordinal,
            "is_forwarded": self.is_forwarded,
            "forward_name": self.forward_name,
        }
