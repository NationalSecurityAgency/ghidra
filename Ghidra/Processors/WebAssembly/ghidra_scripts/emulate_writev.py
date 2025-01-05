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

# A sample script to demonstrate emulation and function hooking with Wasm programs.
# @author nneonneo
# @category Analysis.Wasm
# @keybinding
# @menupath
# @toolbar

from __future__ import print_function
from ghidra.app.emulator import EmulatorHelper
from ghidra.program.emulation import WasmEmulationHelper
import struct

main = currentProgram.listing.getFunctions("export", "main")[0]
emuHelper = EmulatorHelper(currentProgram)
emuHelper.writeRegister(emuHelper.getPCRegister(), main.entryPoint.offset)
wasmHelper = WasmEmulationHelper(emuHelper.language)
ramSpace = currentProgram.addressFactory.defaultAddressSpace

syscall3Addr = currentProgram.listing.getFunctions("import::env", "__syscall3")[0].entryPoint
emuHelper.setBreakpoint(syscall3Addr)
while 1:
    if not emuHelper.run(monitor):
        raise Exception("Emulation stopped: " + emuHelper.lastError)
    if emuHelper.executionAddress == syscall3Addr:
        l0 = emuHelper.readRegister("l0")
        l1 = emuHelper.readRegister("l1")
        l2 = emuHelper.readRegister("l2")
        l3 = emuHelper.readRegister("l3")
        if l0 == 146: # writev
            # Read iovec array
            data = emuHelper.readMemory(ramSpace.getAddress(l2), l3 * 8)
            iovecs = [struct.unpack_from("<II", data.tostring(), 8 * i) for i in range(l3)]
            msg = []
            for io_base, io_len in iovecs:
                if io_len:
                    msg.append(emuHelper.readMemory(ramSpace.getAddress(io_base), io_len).tostring())
            msg = "".join(msg)
            print("writev:", repr(msg))
            wasmHelper.simulateReturn(emuHelper.emulator, len(msg))
        else:
            wasmHelper.simulateReturn(emuHelper.emulator, -1)
