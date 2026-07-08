# Ghidra MCP Server

AI Agent integration for Ghidra binary analysis through Model Context Protocol (MCP).

## Overview

The Ghidra MCP Server provides AI Agents with programmatic access to Ghidra's powerful binary analysis capabilities, enabling automated reverse engineering, vulnerability research, and malware analysis workflows.

## Installation

The MCP server is included with PyGhidra. Install with the `mcp` extra:

```bash
pip install pyghidra[mcp]
```

Or from the Ghidra source:

```bash
cd Ghidra/Features/PyGhidra/src/main/py
pip install -e ".[mcp]"
```

## Quick Start

### Start the MCP Server

```bash
# Using stdio transport (default)
python -m pyghidra.mcp

# Using HTTP transport
python -m pyghidra.mcp --transport http --host 0.0.0.0 --port 8000

# Using SSE transport
python -m pyghidra.mcp --transport sse --host 127.0.0.1 --port 8080
```

### Configure AI Agent

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": ["-m", "pyghidra.mcp"],
      "transport": "stdio"
    }
  }
}
```

## Available Tools

### Binary Loading

#### `load_binary`
Load a binary file into Ghidra for analysis.

**Parameters:**
- `binary_path` (str): Path to the binary file
- `project_location` (str, optional): Ghidra project directory
- `project_name` (str, optional): Project name
- `analyze` (bool): Run auto-analysis (default: true)
- `language` (str, optional): LanguageID override
- `compiler` (str, optional): CompilerSpecID override

**Returns:** Binary metadata including architecture, entry point, function count, etc.

**Example:**
```json
{
  "binary_path": "/path/to/binary",
  "analyze": true
}
```

### Analysis

#### `get_binary_info`
Get metadata about the currently loaded binary.

**Returns:** Binary metadata dictionary.

#### `list_functions`
List functions in the binary.

**Parameters:**
- `name_filter` (str, optional): Filter by function name substring
- `address_filter` (int, optional): Get function at specific address
- `limit` (int): Maximum results (default: 100)

**Returns:** List of function metadata.

#### `decompile_function`
Decompile a function to C-like pseudocode.

**Parameters:**
- `address` (int): Function address
- `timeout_seconds` (int): Decompilation timeout (default: 30)

**Returns:** Decompiled C code and metadata.

#### `disassemble`
Disassemble instructions at an address.

**Parameters:**
- `address` (int): Starting address
- `count` (int): Number of instructions (default: 10)

**Returns:** List of instruction dictionaries.

### Data Extraction

#### `get_strings`
Extract string references from the binary.

**Parameters:**
- `min_length` (int): Minimum string length (default: 4)
- `limit` (int): Maximum results (default: 100)

**Returns:** List of string references with addresses and cross-references.

#### `search_strings`
Search for strings matching a pattern.

**Parameters:**
- `pattern` (str): Search pattern
- `case_sensitive` (bool): Case-sensitive search (default: false)
- `limit` (int): Maximum results (default: 50)

**Returns:** List of matching strings.

#### `get_symbols`
Get symbols from the symbol table.

**Parameters:**
- `symbol_type` (str, optional): Filter by type (function, label, etc.)
- `name_filter` (str, optional): Filter by name substring
- `limit` (int): Maximum results (default: 100)

**Returns:** List of symbol dictionaries.

### Cross-References

#### `get_xrefs`
Get cross-references to or from an address.

**Parameters:**
- `address` (int): Target address
- `direction` (str): "to" or "from" (default: "to")

**Returns:** List of cross-reference dictionaries.

### Memory Layout

#### `get_memory_blocks`
Get memory block/section information.

**Returns:** List of memory block dictionaries with permissions and sizes.

### Imports/Exports

#### `get_imports`
Get imported functions/variables.

**Returns:** List of import dictionaries.

#### `get_exports`
Get exported functions/variables.

**Returns:** List of export dictionaries.

## Use Cases

### Automated Vulnerability Research

```python
# Load binary
binary_info = mcp.call("load_binary", {"binary_path": "/path/to/target"})

# Find interesting functions
functions = mcp.call("list_functions", {"name_filter": "parse"})

# Decompile and analyze
for func in functions:
    decomp = mcp.call("decompile_function", {"address": int(func["address"], 16)})
    # Analyze decompiled code for vulnerabilities
```

### Malware Analysis

```python
# Load malware sample
mcp.call("load_binary", {"binary_path": "/path/to/malware"})

# Extract strings for IOC detection
strings = mcp.call("get_strings", {"min_length": 8})

# Find suspicious API calls
imports = mcp.call("get_imports")
suspicious = [i for i in imports if "VirtualAlloc" in i["name"]]

# Trace cross-references
for api in suspicious:
    xrefs = mcp.call("get_xrefs", {"address": int(api["address"], 16)})
    # Analyze usage patterns
```

### CTF Challenge Solving

```python
# Load challenge binary
mcp.call("load_binary", {"binary_path": "challenge"})

# Get program structure
info = mcp.call("get_binary_info")
functions = mcp.call("list_functions")

# Find main function
main_funcs = [f for f in functions if "main" in f["name"]]

# Decompile and analyze logic
if main_funcs:
    decomp = mcp.call("decompile_function", {"address": int(main_funcs[0]["address"], 16)})
    # Extract algorithm/flag logic
```

## Architecture

The MCP server uses PyGhidra's Python API to interact with Ghidra's Java backend through JPype. Key components:

- **server.py**: FastMCP server implementation with context management
- **tools.py**: MCP tool implementations using Ghidra's FlatProgramAPI
- **models.py**: Data models for structured JSON output
- **errors.py**: Custom error types for MCP operations

## Requirements

- Python 3.8+
- Ghidra 11.0+
- PyGhidra (included with Ghidra)
- fastmcp >= 2.3.0

## Development

### Running Tests

```bash
cd Ghidra/Features/PyGhidra/src/main/py
pytest src/pyghidra/mcp/test_mcp.py -v
```

### Adding New Tools

1. Add tool function to `tools.py` with `@mcp.tool()` decorator
2. Define return type using models from `models.py`
3. Add proper error handling with custom exceptions
4. Update documentation

## Troubleshooting

### "No binary loaded" Error
Ensure you call `load_binary` before other analysis tools.

### Decompilation Timeout
Increase `timeout_seconds` parameter or simplify the function by breaking it into smaller pieces.

### Memory Issues with Large Binaries
Use `limit` parameters in list functions to reduce memory usage.

## License

Apache License 2.0 (same as Ghidra)

## Contributing

Contributions welcome! Please follow Ghidra's contribution guidelines.

## Resources

- [Ghidra Documentation](https://ghidra-sre.org/)
- [PyGhidra API Reference](https://ghidra-sre.org/api/)
- [MCP Protocol](https://modelcontextprotocol.io/)
