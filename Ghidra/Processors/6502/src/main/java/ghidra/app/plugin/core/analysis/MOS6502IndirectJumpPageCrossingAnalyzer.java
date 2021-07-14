package ghidra.app.plugin.core.analysis;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
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
        setPriority(AnalysisPriority.DISASSEMBLY.after().after().after());
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
                long indirectTarget = scalarOperand.getUnsignedValue();
                if ((indirectTarget & 0xFF) == 0xFF) {
                    try {
                        byte low = memory.getByte(addressSpace.getAddress(indirectTarget));
                        byte high = memory.getByte(addressSpace.getAddress(indirectTarget & 0xFF00));
                        long newIndirectTarget = (((long) high) << 8) + (long) low;
                        instr.setFlowOverride(FlowOverride.BRANCH);
                        instr.setFallThrough(addressSpace.getAddress(newIndirectTarget));
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
