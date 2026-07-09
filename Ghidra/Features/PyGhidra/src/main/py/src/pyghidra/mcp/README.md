# Ghidra MCP Server

MCP (Model Context Protocol) Server for Ghidra binary analysis, enabling AI Agents to programmatically interact with Ghidra's reverse engineering capabilities.

## Features

- 12 MCP tools covering binary loading, decompilation, function analysis, cross-references, and more
- Multi-transport support: stdio, SSE, HTTP
- Unified response format for all tools
- Built on PyGhidra's native CPython integration

## Installation

```bash
# Install Ghidra from https://ghidra-sre.org/
pip install pyghidra mcp
```

## Quick Start

Start the MCP server:

```bash
# stdio transport (default)
python -m pyghidra.mcp

# SSE transport
python -m pyghidra.mcp --transport sse --host 127.0.0.1 --port 8080
```

Configure in Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": ["-m", "pyghidra.mcp"]
    }
  }
}
```

## Available Tools

### Binary Management
- `load_binary(binary_path, analyze=True)` - Load binary and run analysis
- `get_binary_info()` - Get binary metadata (architecture, entry point, etc.)

### Function Analysis
- `list_functions(name_filter=None, limit=100)` - List functions with optional filtering
- `decompile_function(address)` - Decompile function to C pseudocode

### Data Extraction
- `get_strings(min_length=4, limit=100)` - Extract string references
- `search_strings(pattern, case_sensitive=False)` - Search strings by pattern
- `get_xrefs(address, direction="to")` - Get cross-references
- `disassemble(address, count=10)` - Disassemble instructions

### Symbol & Memory
- `get_symbols(symbol_type=None, limit=100)` - Get symbols from symbol table
- `get_memory_blocks()` - Get memory sections (.text, .data, etc.)
- `get_imports()` - Get imported functions
- `get_exports()` - Get exported functions

## Response Format

All tools return:

```json
{
  "status": "success|error",
  "data": { ... },
  "error": "message or null"
}
```

## Example Usage

```python
from pyghidra.mcp import tools

# Load binary
result = tools.load_binary("/path/to/binary")
print(f"Architecture: {result['data']['architecture']}")

# List functions
funcs = tools.list_functions(limit=10)
for func in funcs["data"]:
    print(f"{func['name']} at {func['address']}")

# Decompile
addr = int(funcs["data"][0]["address"], 16)
decomp = tools.decompile_function(addr)
print(decomp["data"]["c_code"])
```

## Architecture

```
AI Agent → MCP Server (FastMCP) → Tools Layer → PyGhidra API → Ghidra
```

## Testing

```bash
pytest src/pyghidra/mcp/test_mcp.py -v
```

## License

Apache License 2.0
