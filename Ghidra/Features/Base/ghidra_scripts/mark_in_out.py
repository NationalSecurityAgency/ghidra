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
# Sets up IOPORT IN/OUT references for the Program
#@category Instructions
# Before running this script, you should have created an OVERLAY memory
# space called IOMEM, starting at address 0, size 0x10000.
#
# Note:  This script is rather sloppy and should probably be cleaned up.

from ghidra.program.model.lang.OperandType import SCALAR, REGISTER
from ghidra.program.model.symbol.RefType import READ, WRITE
from ghidra.program.model.symbol.SourceType import *


def add_io_reference(instruction, opIndex, refType):
    """Creates an I/O memory reference for the given scalar operand
    of the given instruction."""
    # delete all current references from the port address field
    for ref in refMgr.getReferences(instruction.address, opIndex):
        print "  Deleting reference to address", ref.toAddress
        refMgr.delete(ref)
    # must use int() to avoid creating a long...
    # we only have 16 bits of I/O address space, and a long
    # would append an 'L' to the hex address
    ioAddr = int(instruction.getOpObjects(opIndex)[0].value)
    ioAddress = addrFactory.getAddress("IOMEM::" + hex(ioAddr))
    print "  Adding", refType, "reference from", instruction.address, \
          "to address", ioAddress
    # from, to, type, sourceType, opIndex
    refMgr.addMemoryReference(instruction.address, ioAddress,
                              refType, ANALYSIS, opIndex)


refMgr = currentProgram.referenceManager
addrFactory = currentProgram.addressFactory

# True means min->max as opposed to listing the Program backwards...
instructions = currentProgram.listing.getInstructions(True)

for instruction in instructions:
    if instruction.mnemonicString == "IN":
        #print "IN @", instruction.address
        if (instruction.getOperandType(1) & SCALAR) != 0:
            add_io_reference(instruction, 1, READ)
        # no absolute address?  okay, let's see if it was set above
        prevInstructionAddr = instruction.fallFrom
        if prevInstructionAddr is None:
            # could be the first instruction in a function, for example
            continue
        prevInstruction = getInstructionAt(prevInstructionAddr)
        if prevInstruction.mnemonicString == "MOV":
            # did we move an absolute address into EDX?
            if (prevInstruction.getOperandType(1) & SCALAR) != 0:
                # we moved a scalar...
                if (prevInstruction.getOperandType(0) & REGISTER) != 0:
                    # okay, we moved into a register...
                    register = prevInstruction.getOpObjects(0)[0]
                    if register.getBaseRegister().name == "EDX":
                        # hooray!
                        add_io_reference(prevInstruction, 1, READ)
    elif instruction.mnemonicString == "OUT":
        #print "OUT @", instruction.address
        if (instruction.getOperandType(0) & SCALAR) != 0:
            add_io_reference(instruction, 0, WRITE)
        # no absolute address?  okay, let's see if it was set above
        prevInstructionAddr = instruction.fallFrom
        if prevInstructionAddr is None:
            # could be the first instruction in a function, for example
            continue
        prevInstruction = getInstructionAt(prevInstructionAddr)
        if prevInstruction.mnemonicString == "MOV":
            # did we move an absolute address into EDX?
            if (prevInstruction.getOperandType(1) & SCALAR) != 0:
                # we moved a scalar...
                if (prevInstruction.getOperandType(0) & REGISTER) != 0:
                    # okay, we moved into a register...
                    register = prevInstruction.getOpObjects(0)[0]
                    if register.getBaseRegister().name == "EDX":
                        # hooray!
                        add_io_reference(prevInstruction, 1, WRITE)
                    elif register.getBaseRegister().name == "EAX":
                        # d'oh, we were writing to EAX (the value to write to
                        # the port)!  one more try...
                        try:
                            prevInstr = getInstructionAt(prevInstruction.fallFrom)
                            if prevInstr.mnemonicString == "MOV":
                                # did we move an absolute address into EDX?
                                if (prevInstr.getOperandType(1) & SCALAR) != 0:
                                    # we moved a scalar...
                                    if (prevInstr.getOperandType(0) &
                                        REGISTER) != 0:
                                        # okay, we moved into a register...
                                        register = prevInstr.getOpObjects(0)[0]
                                        if register.getBaseRegister().name == \
                                               "EDX":
                                            # hooray!
                                            add_io_reference(prevInstr, 1, WRITE)
                        except:
                            # oh well
                            pass

