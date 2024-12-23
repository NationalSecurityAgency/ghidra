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

# Analyze Emscripten export::dynCall_* functions to identify which table
# elements they call, and rename functions listed in the table by their dynCall
# type and index. These dynCall indices are often used as function pointers in
# compiled C/C++ code.
# This script should only be used if your dynCall_ functions contain binary AND
# operations (i.e. i32.and), indicating that the table is segmented into type-
# specific power-of-two-sized chunks.
# @author nneonneo
# @category Analysis.Wasm
# @keybinding
# @menupath
# @toolbar

from __future__ import print_function
from ghidra.program.model.symbol import SourceType

l0 = currentProgram.getRegister("l0")
progspace = currentProgram.addressFactory.getAddressSpace("ram")
tablespace = currentProgram.addressFactory.getAddressSpace("table")
# We insert every dynCall index into a special namespace so that function pointers
# can be easily resolved.
# The format is dynCall::func_{calltype}_{index}.
dynCallNamespace = currentProgram.symbolTable.getOrCreateNameSpace(currentProgram.globalNamespace, "dynCall", SourceType.USER_DEFINED)
dynCalls = {}

def getConst(inst):
    if inst.mnemonicString != "i32.const":
        raise Exception("Expected a constant")
    return inst.getOpObjects(0)[0].value

def getTableFunction(offset):
    funcAddr = getInt(tablespace.getAddress(offset * 4)) & 0xffffffff
    return getFunctionAt(progspace.getAddress(funcAddr))

def analyzeDyncall(function, calltype=None):
    if calltype is None:
        calltype = function.name.split("_", 1)[1]
    # Iterate instructions backwards
    instIterator = currentProgram.listing.getInstructions(function.body, False)
    for inst in instIterator:
        if inst.mnemonicString == "call_indirect":
            break
        elif inst.mnemonicString == "call":
            # forwarding to another function
            addr = inst.getOpObjects(0)[0]
            func = getFunctionAt(addr)
            # Note: name the new function in the global namespace,
            # unlike the parent function which is in the export namespace
            func.setName("dynCall_" + calltype, SourceType.USER_DEFINED)
            return analyzeDyncall(func, calltype)
    else:
        raise Exception("call_indirect not found")

    offset = 0
    mask = 0xffffffff
    while 1:
        inst = next(instIterator)
        if inst.mnemonicString == "i32.add":
            offset = getConst(next(instIterator))
        elif inst.mnemonicString == "i32.and":
            mask = getConst(next(instIterator))
        elif inst.mnemonicString == "i32.const":
            offset = getConst(inst)
            mask = 0
            break
        elif inst.mnemonicString == "local.get":
            if inst.getRegister(0) != l0:
                raise Exception("source is not l0?")
            break
        else:
            raise Exception("Unrecognized instruction " + str(inst))

    dynCalls[calltype] = (offset, mask)

def renameDyncalls(calltype):
    offset, mask = dynCalls.get(calltype, (0, 0))
    nullFunc = getTableFunction(offset)
    if nullFunc:
        nullFunc.setName("nullFuncPtr_" + calltype, SourceType.USER_DEFINED)
    else:
        print("Warning: table index %d is invalid - has the table been loaded?" % offset)
    monitor.setMessage("Renaming " + calltype + " functions")
    monitor.initialize(mask)
    for i in range(mask+1):
        monitor.setProgress(i)
        func = getTableFunction(offset + i)
        if func:
            name = "func_" + calltype + "_%d" % i
            if func.name.startswith("unnamed_function_"):
                func.setName(name, SourceType.ANALYSIS)
            currentProgram.symbolTable.createLabel(func.entryPoint, name, dynCallNamespace, SourceType.USER_DEFINED)
        else:
            print("Warning: table index %d is invalid - has the table been loaded?" % (offset + i))

for function in currentProgram.functionManager.getFunctions(True):
    if function.parentNamespace.name == "export" and function.name.startswith("dynCall_"):
        monitor.setMessage("Analyzing " + function.name)
        try:
            analyzeDyncall(function)
        except Exception as e:
            print("Failed to analyze %s: %s" % (function, e))

for calltype in dynCalls:
    renameDyncalls(calltype)
