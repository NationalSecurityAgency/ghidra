# Ghidra MCP Server

MCP (Model Context Protocol) Server implementation for Ghidra, enabling AI Agents to interact with Ghidra's binary analysis capabilities programmatically.

## Features

- **12 MCP Tools**: Covering binary loading, decompilation, function analysis, cross-references, string extraction, and more
- **Multi-Transport Support**: stdio, SSE, HTTP
- **Comprehensive Testing**: Unit tests with mocked Ghidra backend
- **Unified Response Format**: All tools return consistent `{"status": "success|error", "data": {...}, "error": "..."}` format
- **Complete Documentation**: Usage examples and AI Agent integration

## Installation

### Prerequisites

1. Install Ghidra (https://ghidra-sre.org/)
2. Install PyGhidra (included with Ghidra or standalone):

```bash
pip install pyghidra
```

### Install MCP Dependencies

```bash
# Install MCP SDK (required)
pip install mcp

# Optional: Install FastMCP for enhanced features
pip install fastmcp
```

## Usage

### Start as stdio server (default)

```bash
python -m pyghidra.mcp --transport stdio
```

### Start as SSE server

```bash
python -m pyghidra.mcp --transport sse --host 127.0.0.1 --port 8080
```

### Start as HTTP server

```bash
python -m pyghidra.mcp --transport http --host 127.0.0.1 --port 8080 --path /mcp
```

## Tools

### 1. `load_binary`

Load a binary file into Ghidra for analysis.

**Parameters**:
- `binary_path` (str): Path to the binary file to analyze
- `project_location` (str, optional): Ghidra project directory (defaults to binary's parent)
- `project_name` (str, optional): Project name (defaults to binary_name + "_ghidra")
- `analyze` (bool): Whether to run auto-analysis (default: True)
- `language` (str, optional): LanguageID override
- `compiler` (str, optional): CompilerSpecID override

**Returns**: Binary metadata including architecture, entry point, function count, etc.

**Example**:
```python
from pyghidra.mcp import tools

result = tools.load_binary("/path/to/binary", analyze=True)
print(result["data"]["architecture"])
```

### 2. `get_binary_info`

Get metadata about the currently loaded binary.

**Parameters**: None

**Returns**: Binary metadata including architecture, entry point, function count, etc.

**Example**:
```python
result = tools.get_binary_info()
print(result["data"]["name"])
print(result["data"]["function_count"])
```

### 3. `list_functions`

List functions in the binary.

**Parameters**:
- `name_filter` (str, optional): Substring to filter function names
- `address_filter` (int, optional): Address to get function at that address
- `limit` (int): Maximum number of functions to return (default: 100)

**Returns**: List of function metadata dictionaries

**Example**:
```python
result = tools.list_functions(name_filter="main", limit=10)
for func in result["data"]:
    print(f"{func['name']} at {func['address']}")
```

### 4. `decompile_function`

Decompile a function to C-like pseudocode.

**Parameters**:
- `address` (int): Address of the function to decompile
- `timeout_seconds` (int): Maximum time for decompilation (default: 30)

**Returns**: Decompiled C code and metadata

**Example**:
```python
result = tools.decompile_function(0x401000)
print(result["data"]["c_code"])
```

### 5. `get_strings`

Extract string references from the binary.

**Parameters**:
- `min_length` (int): Minimum string length (default: 4)
- `limit` (int): Maximum number of strings to return (default: 100)

**Returns**: List of string reference dictionaries

**Example**:
```python
result = tools.get_strings(min_length=6, limit=50)
for string in result["data"]:
    print(f"{string['value']} at {string['address']}")
```

### 6. `get_xrefs`

Get cross-references to or from an address.

**Parameters**:
- `address` (int): Address to get references for
- `direction` (str): "to" for references to address, "from" for references from address (default: "to")

**Returns**: List of cross-reference dictionaries

**Example**:
```python
result = tools.get_xrefs(0x401000, direction="to")
for xref in result["data"]:
    print(f"Reference from {xref['from_address']}")
```

### 7. `disassemble`

Disassemble instructions at an address.

**Parameters**:
- `address` (int): Starting address
- `count` (int): Number of instructions to disassemble (default: 10)

**Returns**: List of instruction dictionaries

**Example**:
```python
result = tools.disassemble(0x401000, count=20)
for instr in result["data"]:
    print(f"{instr['address']}: {instr['mnemonic']} {instr['operands']}")
```

### 8. `get_memory_blocks`

Get memory block/section information.

**Parameters**: None

**Returns**: List of memory block dictionaries

**Example**:
```python
result = tools.get_memory_blocks()
for block in result["data"]:
    print(f"{block['name']}: {block['size']} bytes")
```

### 9. `get_symbols`

Get symbols from the symbol table.

**Parameters**:
- `symbol_type` (str, optional): Filter by symbol type (function, label, etc.)
- `name_filter` (str, optional): Substring to filter symbol names
- `limit` (int): Maximum number of symbols to return (default: 100)

**Returns**: List of symbol dictionaries

**Example**:
```python
result = tools.get_symbols(symbol_type="function", limit=50)
for symbol in result["data"]:
    print(f"{symbol['name']} at {symbol['address']}")
```

### 10. `search_strings`

Search for strings matching a pattern.

**Parameters**:
- `pattern` (str): String pattern to search for
- `case_sensitive` (bool): Case-sensitive search (default: False)
- `limit` (int): Maximum results to return (default: 50)

**Returns**: List of matching string dictionaries

**Example**:
```python
result = tools.search_strings("error", case_sensitive=False)
for string in result["data"]:
    print(string["value"])
```

### 11. `get_imports`

Get imported functions/variables.

**Parameters**: None

**Returns**: List of import dictionaries

**Example**:
```python
result = tools.get_imports()
for imp in result["data"]:
    print(f"{imp['name']} from {imp['library']}")
```

### 12. `get_exports`

Get exported functions/variables.

**Parameters**: None

**Returns**: List of export dictionaries

**Example**:
```python
result = tools.get_exports()
for exp in result["data"]:
    print(f"{exp['name']} at {exp['address']}")
```

## AI Agent Integration

### Claude Desktop Configuration

Add to your Claude Desktop configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": ["-m", "pyghidra.mcp", "--transport", "stdio"]
    }
  }
}
```

### Python Integration

```python
import asyncio
from pyghidra.mcp import tools

async def main():
    # Load a binary
    result = tools.load_binary("/path/to/binary")
    print(f"Loaded: {result['data']['name']}")
    
    # List functions
    funcs = tools.list_functions(limit=10)
    for func in funcs["data"]:
        print(f"Function: {func['name']}")
    
    # Decompile a function
    if funcs["data"]:
        addr = int(funcs["data"][0]["address"], 16)
        decomp = tools.decompile_function(addr)
        print(decomp["data"]["c_code"])

asyncio.run(main())
```

### Using with FastMCP Client

```python
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    server_params = StdioServerParameters(
        command="python",
        args=["-m", "pyghidra.mcp", "--transport", "stdio"]
    )
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            # Call tools
            result = await session.call_tool("load_binary", {
                "binary_path": "/path/to/binary"
            })
            print(result)

asyncio.run(main())
```

## Unified Response Format

All tools return responses in a consistent format:

```json
{
  "status": "success|error",
  "data": { ... },
  "error": "error message or null"
}
```

### Success Response

```json
{
  "status": "success",
  "data": {
    "name": "binary",
    "architecture": "x86",
    "function_count": 100
  },
  "error": null
}
```

### Error Response

```json
{
  "status": "error",
  "data": null,
  "error": "No binary loaded. Use load_binary first."
}
```

## Testing

```bash
# Run all tests
pytest src/pyghidra/mcp/test_mcp.py -v

# Run with coverage
pytest src/pyghidra/mcp/test_mcp.py --cov=pyghidra.mcp --cov-report=term-missing

# Run specific test class
pytest src/pyghidra/mcp/test_mcp.py::TestTools -v
```

## Architecture

The MCP Server is built on top of PyGhidra's native CPython integration:

```
┌─────────────────┐
│   AI Agent      │
└────────┬────────┘
         │ MCP Protocol
         ▼
┌─────────────────┐
│  MCP Server     │  (pyghidra.mcp.server)
│  - FastMCP      │
│  - stdio/SSE    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Tools Layer    │  (pyghidra.mcp.tools)
│  - 12 tools     │
│  - unified resp │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  PyGhidra API   │  (JPype + Ghidra)
│  - FlatProgramAPI│
│  - Decompiler   │
└─────────────────┘
```

## Error Handling

The server provides comprehensive error handling:

- **BinaryNotLoadedError**: No binary loaded
- **FunctionNotFoundError**: Function not found at address
- **DecompilationError**: Decompilation failed
- **InvalidAddressError**: Invalid address
- **AnalysisError**: Analysis failed

All errors are caught and returned in the unified response format.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new tools
4. Ensure all tests pass
5. Submit a PR

## License

Apache License 2.0 (same as Ghidra)

## References

- [Ghidra](https://ghidra-sre.org/)
- [PyGhidra Documentation](../README.md)
- [MCP Specification](https://modelcontextprotocol.io/)
- [FastMCP](https://github.com/jlowin/fastmcp)
