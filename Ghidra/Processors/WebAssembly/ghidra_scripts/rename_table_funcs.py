## ###
#  IP: GHIDRA
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  
#       http://www.apache.org/licenses/LICENSE-2.0
#  
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
##

# Rename dynamically-callable functions from the function table.
# This is useful for analyzing programs where table indices are used as
# function pointers, e.g. programs compiled with LLVM.
# Note: if you have "dynCall_" functions that contain arithmetic operations
# (AND, ADD, etc.) you may want to use analyze_dyncalls.py instead.
# @author nneonneo
# @category Analysis.Wasm
# @keybinding
# @menupath
# @toolbar

from __future__ import print_function
from wasm.analysis import WasmAnalysis
from ghidra.program.model.symbol import SourceType

progspace = currentProgram.addressFactory.getAddressSpace("ram")
tablespace = currentProgram.addressFactory.getAddressSpace("table")
dynCallNamespace = currentProgram.symbolTable.getOrCreateNameSpace(currentProgram.globalNamespace, "dynCall", SourceType.USER_DEFINED)

def getTableFunction(offset):
    funcAddr = getInt(tablespace.getAddress(offset * 4)) & 0xffffffff
    return getFunctionAt(progspace.getAddress(funcAddr))

count = WasmAnalysis.getState(currentProgram).module.nonImportedTables[0].limits.initial
for i in range(1, count):
    func = getTableFunction(i)
    if func:
        name = "func_%d" % i
        if func.name.startswith("unnamed_function_"):
            func.setName(name, SourceType.ANALYSIS)
        currentProgram.symbolTable.createLabel(func.entryPoint, name, dynCallNamespace, SourceType.USER_DEFINED)
