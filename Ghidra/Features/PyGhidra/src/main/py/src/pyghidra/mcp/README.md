# Ghidra MCP Server

AI Agent 接口，用于通过 Model Context Protocol 访问 Ghidra 的反汇编和逆向工程功能。

## 功能特性

- **二进制加载**: 加载和分析二进制文件
- **函数列表**: 列出所有函数
- **反编译**: 将函数反编译为 C 伪代码
- **字符串提取**: 从二进制中提取字符串
- **交叉引用**: 分析函数调用和数据引用
- **符号管理**: 管理函数和变量符号
- **内存块分析**: 分析内存布局

## 工具列表

### 1. `load_binary`
加载二进制文件进行分析。

```python
result = load_binary(binary_path="/path/to/binary")
# 返回: {"binary_path": "/path/to/binary", "architecture": "x86:LE:64:default", ...}
```

### 2. `get_functions`
列出所有函数。

```python
result = get_functions()
# 返回: {"functions": [{"name": "main", "address": "0x401000", "size": 100}, ...]}

# 使用过滤器
result = get_functions(filter_pattern="main")
```

### 3. `decompile_function`
反编译函数为 C 伪代码。

```python
result = decompile_function(address="0x401000")
# 返回: {"decompiled": "int main() { ... }"}
```

### 4. `get_strings`
从二进制中提取字符串。

```python
result = get_strings()
# 返回: {"strings": [{"value": "Hello", "address": "0x402000", "length": 5}, ...]}
```

### 5. `get_xrefs`
获取交叉引用信息。

```python
result = get_xrefs(address="0x401000")
# 返回: {"xrefs": [{"from": "0x401100", "to": "0x401000", "type": "CALL"}, ...]}
```

### 6. `get_binary_info`
获取二进制元数据。

```python
result = get_binary_info()
# 返回: {"architecture": "x86", "bits": 64, "entry_point": "0x401000", ...}
```

### 7. `rename_function`
重命名函数。

```python
result = rename_function(address="0x401000", new_name="vulnerable_func")
# 返回: {"status": "success", "message": "Function renamed"}
```

### 8. `add_comment`
添加注释。

```python
result = add_comment(address="0x401000", comment="This is vulnerable to buffer overflow")
# 返回: {"status": "success"}
```

## 安装

```bash
pip install pyghidra mcp
```

## 使用方法

### 作为独立服务器运行

```bash
python -m pyghidra.mcp.server --stdio
```

### 传输方式

支持三种传输方式：

1. **stdio**（默认）:
   ```bash
   python -m pyghidra.mcp.server --stdio
   ```

2. **SSE**:
   ```bash
   python -m pyghidra.mcp.server --sse --host 127.0.0.1 --port 8000
   ```

3. **HTTP**:
   ```bash
   python -m pyghidra.mcp.server --http --host 127.0.0.1 --port 8000
   ```

## AI Agent 集成示例

### Claude Desktop 配置

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": ["-m", "pyghidra.mcp.server", "--stdio"]
    }
  }
}
```

### 使用示例

```python
from mcp import Client

async def reverse_engineer():
    async with Client("ghidra") as client:
        # 加载二进制
        binary = await client.call_tool("load_binary", {
            "binary_path": "/path/to/binary"
        })
        
        # 列出函数
        functions = await client.call_tool("get_functions", {})
        for func in functions["functions"]:
            print(f"{func['name']} @ {func['address']}")
        
        # 反编译函数
        decompiled = await client.call_tool("decompile_function", {
            "address": "0x401000"
        })
        print(decompiled["decompiled"])
```

## 常见使用场景

### 1. 自动化逆向工程

```python
# 1. 加载二进制
await client.call_tool("load_binary", {"binary_path": "target.exe"})

# 2. 获取所有函数
functions = await client.call_tool("get_functions", {})

# 3. 反编译每个函数
for func in functions["functions"]:
    decompiled = await client.call_tool("decompile_function", {
        "address": func["address"]
    })
    
    # 分析反编译代码
    if "strcpy" in decompiled["decompiled"]:
        print(f"Potential vulnerability in {func['name']}")
        await client.call_tool("add_comment", {
            "address": func["address"],
            "comment": "Uses unsafe strcpy function"
        })
```

### 2. 漏洞研究

```python
# 1. 加载二进制
await client.call_tool("load_binary", {"binary_path": "vulnerable.exe"})

# 2. 查找危险函数调用
xrefs = await client.call_tool("get_xrefs", {
    "address": "strcpy_address"
})

# 3. 分析调用位置
for xref in xrefs["xrefs"]:
    decompiled = await client.call_tool("decompile_function", {
        "address": xref["from"]
    })
    print(f"Called from: {xref['from']}")
    print(decompiled["decompiled"])
```

### 3. 恶意软件分析

```python
# 1. 加载恶意软件样本
await client.call_tool("load_binary", {"binary_path": "malware.exe"})

# 2. 提取字符串
strings = await client.call_tool("get_strings", {})

# 3. 查找可疑字符串
for s in strings["strings"]:
    if "http" in s["value"].lower() or "cmd" in s["value"].lower():
        print(f"Suspicious: {s['value']} @ {s['address']}")
        
        # 查找引用
        xrefs = await client.call_tool("get_xrefs", {
            "address": s["address"]
        })
        for xref in xrefs["xrefs"]:
            decompiled = await client.call_tool("decompile_function", {
                "address": xref["from"]
            })
            print(f"Used in function at {xref['from']}")
```

## 测试

运行测试套件：

```bash
pytest ghidra/tests/test_mcp_tools.py -v
```

测试覆盖率：80%

## 错误处理

所有工具返回统一的错误格式：

```python
{
    "status": "success",
    "data": {...},
    "error": null
}
```

或：

```python
{
    "status": "error",
    "data": null,
    "error": "Error description"
}
```

## 依赖项

- Python 3.8+
- pyghidra
- Ghidra
- mcp (Model Context Protocol SDK)

## 许可证

与 Ghidra 项目相同。

## 相关链接

- [Ghidra 项目](https://github.com/NationalSecurityAgency/ghidra)
- [PyGhidra](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/PyGhidra)
- [Model Context Protocol](https://modelcontextprotocol.io/)
