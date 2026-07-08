---
tool_name: ghidra
mcp_server: ghidra.mcp.server
version: 1.0
author: AI Assistant
created: 2026-07-08
updated: 2026-07-08
tags: [reverse-engineering, decompiler, static-analysis, disassembler]
---

# Ghidra MCP Skill

## 概述

Ghidra 是 NSA 开源的逆向工程框架，提供强大的反编译器和静态分析能力。通过 MCP Server，AI Agent 可以自动化二进制分析、反编译函数、提取字符串和分析交叉引用。

### 主要功能

- **二进制加载**: 加载各种格式的二进制文件
- **函数分析**: 列出、反编译和分析函数
- **反编译**: 将机器码转换为 C 伪代码
- **字符串提取**: 从二进制中提取字符串
- **交叉引用**: 分析函数调用和数据引用
- **符号管理**: 管理函数和变量符号
- **内存块分析**: 分析内存布局

### 适用场景

- CTF Reverse 题分析
- 恶意代码逆向分析
- 二进制漏洞研究
- 软件安全审计
- 协议逆向工程

## 工具选择指南

### 何时使用 Ghidra

- 需要反编译二进制为可读的 C 代码
- 需要分析函数的控制流和数据流
- 需要提取和分析字符串引用
- 需要理解函数的调用关系
- 需要进行静态代码审计

### 与其他工具的对比

| 工具 | 类型 | 优势 | 劣势 |
|------|------|------|------|
| Ghidra | 静态分析 | 反编译质量高、免费 | 启动慢、资源占用大 |
| IDA Pro | 静态分析 | 反编译质量最高 | 商业软件、价格昂贵 |
| radare2 | 静态/动态 | 轻量级、命令行友好 | 反编译质量不如 Ghidra |
| Binary Ninja | 静态分析 | 现代化界面 | 商业软件 |

### 典型使用场景

1. **CTF Reverse**: 反编译加密算法、理解验证逻辑
2. **漏洞分析**: 审计函数实现、发现潜在漏洞
3. **恶意代码分析**: 理解恶意行为、提取 C2 配置
4. **协议逆向**: 分析网络协议实现、提取数据结构

## 支持的工具

### 核心工具

- `load_binary` - 加载二进制文件
- `get_functions` - 列出所有函数
- `decompile_function` - 反编译函数
- `disassemble` - 反汇编指令
- `get_strings` - 提取字符串
- `get_xrefs` - 获取交叉引用
- `get_sections` - 获取内存段
- `rename_function` - 重命名函数
- `add_comment` - 添加注释
- `get_imports` - 获取导入函数
- `get_exports` - 获取导出函数

## 参数最佳实践

### load_binary

```python
# 推荐：指定分析选项
result = load_binary(
    binary_path="/path/to/binary",
    analyze=True,  # 自动分析
    language_id="x86:LE:64:default"  # 指定架构
)

# 对于大型二进制，禁用自动分析
result = load_binary(
    binary_path="/path/to/large_binary",
    analyze=False
)
```

### decompile_function

```python
# 推荐：使用函数地址
result = decompile_function(address="0x401000")

# 使用函数名称
result = decompile_function(address="main")

# 反编译多个函数
for func in functions["functions"]:
    decompiled = await decompile_function(address=func["address"])
    print(f"Function: {func['name']}")
    print(decompiled["decompiled"])
```

### get_strings

```python
# 推荐：设置最小长度过滤
result = get_strings(min_length=4)

# 过滤特定段
result = get_strings(section=".rodata")

# 使用正则表达式过滤
result = get_strings(pattern="flag|password|key")
```

### get_xrefs

```python
# 推荐：指定引用类型
result = get_xrefs(
    address="0x401000",
    ref_type="call"  # 只获取调用引用
)

# 获取所有引用
result = get_xrefs(address="0x401000")
```

## 错误处理

参考 [MCP_ERROR_HANDLING.md](../MCP_ERROR_HANDLING.md) 中的错误码定义。

### 二进制分析错误 (2000-2999)

| 错误码 | 名称 | 解决方案 |
|--------|------|----------|
| 2001 | BINARY_LOAD_FAILED | 检查文件格式是否支持 |
| 2002 | INVALID_BINARY_FORMAT | 确认是有效的可执行文件 |
| 2003 | ARCHITECTURE_NOT_SUPPORTED | 检查架构是否在支持列表中 |
| 2005 | SYMBOL_NOT_FOUND | 使用地址而非符号名称 |
| 2006 | ADDRESS_INVALID | 检查地址是否在有效范围内 |
| 2007 | DISASSEMBLY_FAILED | 确认地址指向有效指令 |
| 2008 | DECOMPILATION_FAILED | 尝试反汇编而非反编译 |

### 常见错误及解决方案

**错误 1: 反编译失败**
```
Error: DECOMPILATION_FAILED - Cannot decompile function at 0x...
```
解决方案：
- 使用 `disassemble` 获取汇编代码
- 检查函数是否被正确识别
- 尝试手动定义函数边界

**错误 2: 符号未找到**
```
Error: SYMBOL_NOT_FOUND - Symbol 'main' not found
```
解决方案：
- 使用 `get_functions` 列出可用函数
- 使用函数地址而非名称
- 检查二进制是否被 strip

**错误 3: 地址无效**
```
Error: ADDRESS_INVALID - Address 0x... is not valid
```
解决方案：
- 使用 `get_sections` 获取有效地址范围
- 检查地址是否对齐
- 确认地址指向代码或数据

## Workflow 示例

### 基础工作流：CTF Reverse 分析

```python
async def analyze_ctf_reverse(binary_path):
    # 1. 加载二进制
    binary = await load_binary(binary_path=binary_path)
    print(f"Architecture: {binary['architecture']}")
    
    # 2. 提取字符串
    strings = await get_strings(min_length=4)
    interesting = [s for s in strings["strings"] 
                  if any(kw in s["value"].lower() for kw in ["flag", "password", "key"])]
    print(f"Found {len(interesting)} interesting strings")
    
    # 3. 列出函数
    functions = await get_functions()
    main_func = next((f for f in functions["functions"] if f["name"] == "main"), None)
    
    if main_func:
        # 4. 反编译 main 函数
        decompiled = await decompile_function(address=main_func["address"])
        print(f"Main function:\n{decompiled['decompiled']}")
        
        # 5. 分析交叉引用
        xrefs = await get_xrefs(address=main_func["address"])
        print(f"Called by {len(xrefs['xrefs'])} functions")
```

### 高级工作流：漏洞审计

```python
async def audit_vulnerabilities(binary_path):
    # 1. 加载二进制
    await load_binary(binary_path=binary_path)
    
    # 2. 获取危险函数导入
    imports = await get_imports()
    dangerous = [i for i in imports["imports"] 
                if i["name"] in ["strcpy", "strcat", "sprintf", "gets", "scanf"]]
    
    print(f"Found {len(dangerous)} dangerous imports")
    
    # 3. 分析每个危险函数的引用
    for func in dangerous:
        xrefs = await get_xrefs(address=func["address"])
        
        for xref in xrefs["xrefs"]:
            # 反编译调用位置
            decompiled = await decompile_function(address=xref["from"])
            
            # 检查是否存在漏洞
            if check_vulnerability(decompiled["decompiled"]):
                print(f"Potential vulnerability in {xref['from']}")
                print(f"Calling {func['name']}")
```

### 多工具协作：结合动态分析

```python
async def combined_static_dynamic(binary_path):
    # 1. Ghidra 静态分析
    await load_binary(binary_path=binary_path)
    functions = await get_functions()
    
    # 2. 识别加密函数
    crypto_funcs = [f for f in functions["functions"] 
                   if any(kw in f["name"].lower() for kw in ["encrypt", "decrypt", "aes", "rsa"])]
    
    # 3. 反编译加密函数
    for func in crypto_funcs:
        decompiled = await decompile_function(address=func["address"])
        
        # 4. 使用 pwndbg 动态验证
        # 在加密函数设置断点
        await pwndbg_client.call_tool(
            "manage_breakpoint",
            {"action": "add", "location": hex(func["address"])}
        )
    
    # 5. 运行程序并收集密钥
    await pwndbg_client.call_tool("execute_command", {"command": "run"})
    
    # 6. 在断点处检查寄存器
    regs = await pwndbg_client.call_tool("get_registers", {})
    print(f"Encryption key in registers: {regs}")
```

## Prompt 模板

### 基础调用模板

```python
# 调用 Ghidra MCP 工具
async def analyze_with_ghidra():
    # 加载二进制
    result = await mcp_client.call_tool(
        tool_name="load_binary",
        arguments={"binary_path": "/path/to/binary"}
    )
    
    if result["status"] == "success":
        binary = result["data"]
        print(f"Loaded: {binary['architecture']}")
    else:
        print(f"Error: {result['error_message']}")
```

### 高级分析模板

```python
# 自动化逆向分析
async def automated_reverse_engineering(binary_path):
    """
    自动化逆向分析流程：
    1. 加载二进制
    2. 提取关键字符串
    3. 识别关键函数
    4. 反编译分析
    """
    # 加载
    await mcp_client.call_tool("load_binary", {"binary_path": binary_path})
    
    # 提取字符串
    strings = await mcp_client.call_tool("get_strings", {"min_length": 4})
    interesting = [s for s in strings["data"]["strings"] 
                  if "flag" in s["value"].lower()]
    
    # 获取函数列表
    functions = await mcp_client.call_tool("get_functions", {})
    
    # 反编译关键函数
    for func in functions["data"]["functions"][:10]:
        decompiled = await mcp_client.call_tool(
            "decompile_function",
            {"address": func["address"]}
        )
        print(f"Function: {func['name']}")
        print(decompiled["data"]["decompiled"][:200])
```

### 自动化脚本模板

```python
#!/usr/bin/env python3
"""
Ghidra MCP 自动化分析脚本
"""
import asyncio
from mcp import Client

async def main():
    async with Client("ghidra") as client:
        # 加载二进制
        binary = await client.call_tool("load_binary", {
            "binary_path": "challenge"
        })
        print(f"Architecture: {binary['data']['architecture']}")
        
        # 提取字符串
        strings = await client.call_tool("get_strings", {"min_length": 4})
        for s in strings["data"]["strings"][:10]:
            print(f"String: {s['value']}")
        
        # 列出函数
        functions = await client.call_tool("get_functions", {})
        print(f"Found {len(functions['data']['functions'])} functions")
        
        # 反编译 main
        main_func = next(f for f in functions["data"]["functions"] if f["name"] == "main")
        decompiled = await client.call_tool("decompile_function", {
            "address": main_func["address"]
        })
        print(f"Main:\n{decompiled['data']['decompiled']}")

if __name__ == "__main__":
    asyncio.run(main())
```

## 最佳实践

### 性能优化建议

1. **控制分析范围**
   - 对大型二进制禁用自动分析
   - 优先分析关键函数
   - 使用函数过滤器

2. **缓存分析结果**
   - 缓存函数列表
   - 缓存反编译结果
   - 避免重复分析

3. **批量操作**
   - 批量反编译多个函数
   - 批量提取字符串
   - 减少 MCP 调用次数

### 安全注意事项

1. **隔离环境**
   - 在虚拟机中运行 Ghidra
   - 避免分析恶意构造的文件
   - 限制文件系统访问

2. **数据保护**
   - 不要将敏感二进制的分析结果上传
   - 安全存储分析结果
   - 注意知识产权保护

3. **结果验证**
   - 交叉验证反编译结果
   - 使用动态调试验证静态分析
   - 不要完全依赖自动分析

### 常见问题解答

**Q: 如何提高反编译质量？**
A: 确保函数边界正确定义，使用 `analyze` 工具重新分析，手动修复类型信息。

**Q: 如何处理被 strip 的二进制？**
A: 使用 `get_functions` 查找函数，根据特征识别关键函数，手动重命名。

**Q: 如何分析大型二进制？**
A: 分段分析，优先分析导入/导出函数，使用过滤器减少分析范围。

**Q: 如何处理混淆代码？**
A: 结合动态调试（pwndbg）找到解密后的代码，使用符号执行（angr）自动化分析。

**Q: 如何提取加密密钥？**
A: 使用动态调试在加密函数处中断，检查寄存器和内存中的密钥材料。

---

**相关资源**
- [Ghidra 项目](https://github.com/NationalSecurityAgency/ghidra)
- [MCP 协议](https://modelcontextprotocol.io/)
- [错误处理规范](../MCP_ERROR_HANDLING.md)
