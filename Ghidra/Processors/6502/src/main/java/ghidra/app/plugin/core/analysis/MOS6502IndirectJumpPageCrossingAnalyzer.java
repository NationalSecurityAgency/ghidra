/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.plugin.core.analysis;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/*

The NMOS version of the 6502 has an hardware bug in which indirect jumps whose effective address lies across two
256-bytes pages, the higher byte of the address is fetched in the same page as the lower byte rather than the following
one.  For example, assume the instruction being analysed is at $1000 and once decoded turns into "JMP ($10FF)", and
memory at $10FF and $1100 contains $00 and $20 respectively.  One may assume the address being fetched from memory
would be $2000 and then the program counter would be set to that address.  In fact what happens is that bytes at $10FF
and $1000 would be fetched to obtain the effective target, which in this case would turn into $6C00 ($6C being the
opcode for indirect JMP).

CMOS versions and some clones did fix this mistake, but quite a few clones still keep this behaviour to be bug-for-bug
compatible with the original.

 */

public class MOS6502IndirectJumpPageCrossingAnalyzer extends AbstractAnalyzer {

    private static final String NAME = "Emulate indirect jump bug";
    private static final String DESCRIPTION =
            "Compute the correct effective indirect jump target on page boundary crossings.";

    public MOS6502IndirectJumpPageCrossingAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
        setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after().after().after());
    }

    @Override
    public boolean canAnalyze(Program program) {
        LanguageID languageID = program.getLanguageID();
        return languageID.equals(new LanguageID("6502:LE:16:default"));
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {

        AddressFactory addressFactory = program.getAddressFactory();
        Memory memory = program.getMemory();
        AddressSpace addressSpace = addressFactory.getDefaultAddressSpace();
        ReferenceManager referenceManager = program.getReferenceManager();

        InstructionIterator instIter = program.getListing().getInstructions(set, true);
        while (!monitor.isCancelled() && instIter.hasNext()) {
            Instruction instr = instIter.next();

            if (!instr.getMnemonicString().equalsIgnoreCase("JMP") ||
                    instr.getNumOperands() != 1 ||
                    (instr.getOperandType(0) & OperandType.INDIRECT) != OperandType.INDIRECT) {
                continue;
            }
            
            Object[] operandObjects = instr.getOpObjects(0);
            if (operandObjects[0] instanceof Scalar) {
                Scalar scalarOperand = (Scalar) operandObjects[0];
                long indirectSource = scalarOperand.getUnsignedValue();
                if ((indirectSource & 0xFF) == 0xFF) {
                    try {
                    	Address originalIndirectSourceAddress = addressSpace.getAddress(indirectSource);
                    	long originalTarget = (long) memory.getByte(originalIndirectSourceAddress) +
                    			((long) memory.getByte(originalIndirectSourceAddress.add(1))) << 8;
                    	Address originalTargetAddress = addressSpace.getAddress(originalTarget);
                    	long effectiveTarget = (long) memory.getByte(originalIndirectSourceAddress) +
                    			((long) memory.getByte(addressSpace.getAddress(indirectSource & 0xFF00))) << 8;
                    	Address effectiveTargetAddress = addressSpace.getAddress(effectiveTarget);

                    	// Remove previous references that did not consider the bug.
                        Reference[] existingReferences = instr.getOperandReferences(0);
                        for (int referenceIndex = 0; referenceIndex < existingReferences.length; referenceIndex++) {
                        	if (existingReferences[referenceIndex].getFromAddress().compareTo(instr.getAddress()) == 0 &&
                        			existingReferences[referenceIndex].getToAddress().compareTo(originalTargetAddress) == 0) {
                        		instr.removeOperandReference(referenceIndex, originalTargetAddress);
                        	}
                        }
                        
                        Reference reference = referenceManager.addMemoryReference(instr.getAddress(),
                        		effectiveTargetAddress, RefType.JUMP_OVERRIDE_UNCONDITIONAL,
                        		SourceType.ANALYSIS, 0);
                        instr.setPrimaryMemoryReference(reference);
                    } catch (MemoryAccessException e) {
                        // Unless the computed indirect target is pointing to an unmapped memory area, this
                        // should not happen.  This should also not happen in case of rolling over the address
                        // space (say, "JMP ($FFFF)").
                        Msg.error(this, "Computed jump target is outside mapped memory.");
                    }
                }
            }
        }

        return true;
    }
}
