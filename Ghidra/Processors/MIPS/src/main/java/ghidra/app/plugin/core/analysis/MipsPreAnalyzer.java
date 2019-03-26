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

import java.math.BigInteger;

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class MipsPreAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "MIPS UnAlligned Instruction Fix";
	private static final String DESCRIPTION =
		"Analyze MIPS Instructions for unaligned load pairs ldl/ldr sdl/sdr lwl/lwr swl/swr.";

	private final static int NOTIFICATION_INTERVAL = 1024;

	Register pairBitRegister;
	private Register isamode;
	private Register ismbit;
	private Register rel6bit;
	private Register micro16bit;

	public MipsPreAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		// run at a very high priority.  this needs to be done before any code fixup
		// since it changes the nature of an instruction
		setPriority(AnalysisPriority.BLOCK_ANALYSIS.after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		Processor processor = program.getLanguage().getProcessor();
		return (processor.equals(Processor.findOrPossiblyCreateProcessor("MIPS")));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		pairBitRegister = program.getProgramContext().getRegister("PAIR_INSTRUCTION_FLAG");
		isamode = program.getProgramContext().getRegister("ISA_MODE");
		ismbit = program.getProgramContext().getRegister("ISAModeSwitch");
		rel6bit = program.getProgramContext().getRegister("REL6");
		micro16bit = program.getProgramContext().getRegister("RELP");

		set = removeUninitializedBlock(program, set);

		final long locationCount = set.getNumAddresses();
		if (locationCount > NOTIFICATION_INTERVAL) {
			monitor.initialize(locationCount);
		}

		AddressIterator addresses = set.getAddresses(true);

		int count = 0;

		AddressSet pairSet = new AddressSet();
		while (addresses.hasNext()) {
			monitor.checkCanceled();

			Address addr = addresses.next();

			if (locationCount > NOTIFICATION_INTERVAL) {

				if ((count % NOTIFICATION_INTERVAL) == 0) {
					monitor.setMaximum(locationCount);
					monitor.setProgress(count);
				}
				count++;
			}

			if ((addr.getOffset() & 0x3) != 0) {
				continue;
			}

			if (pairSet.contains(addr)) {
				continue;
			}

			if (!checkPossiblePairInstruction(program, addr)) {
				continue;
			}

			Instruction instr = program.getListing().getInstructionAt(addr);
			if (instr != null) {
				if (skipif16orR6(program, instr)) {
					continue;
				}
				findPair(program, pairSet, instr, monitor);
			}
		}

		redoAllPairs(program, pairSet, monitor);

		return true;
	}

	private boolean skipif16orR6(Program program, Instruction start_inst) {
		boolean rval = false;

		BigInteger curval1 = (isamode == null ? null
				: program.getProgramContext().getValue(isamode, start_inst.getMinAddress(), false));
		BigInteger curval2 = (ismbit == null ? null
				: program.getProgramContext().getValue(ismbit, start_inst.getMinAddress(), false));
		BigInteger curval3 = (rel6bit == null ? null
				: program.getProgramContext().getValue(rel6bit, start_inst.getMinAddress(), false));
		BigInteger curval4 = (micro16bit == null ? null
				: program.getProgramContext().getValue(micro16bit, start_inst.getMinAddress(),
					false));

		if ((curval1 != null) && (curval4 != null) && (curval1.intValue() == 1) &&
			(curval4.intValue() == 1)) {
			rval = true;
		}
		if ((curval2 != null) && (curval4 != null) && (curval2.intValue() == 1) &&
			(curval4.intValue() == 1)) {
			rval = true;
		}
		if ((curval3 != null) && (curval3.intValue() == 1)) {
			rval = true;
		}

		return rval;
	}

	private boolean checkPossiblePairInstruction(Program program, Address addr) {
		int primeOpcode = 0;

		try {
			byte b = 0;
			// LE binary has primary op-code at different location
			if (!program.getLanguage().isBigEndian()) {
				// set addr to location of primary op-code for LE binary
				addr = addr.add(3);
			}
			b = program.getMemory().getByte(addr);
			primeOpcode = (b >> 2) & 0x3f;
		}
		catch (MemoryAccessException exc) {
			return false;
		}
		catch (AddressOutOfBoundsException exc) {
			// could walk of the end of memory, just ignore
			return false;
		}
		
		// Generally, the load/store left instruction comes before the right,
		// but here a pair will be found in any order.
		if (primeOpcode == 34 || primeOpcode == 38 || // lwl lwr
			primeOpcode == 42 || primeOpcode == 46 || // swl swr
			primeOpcode == 26 || primeOpcode == 27 || // ldl ldr
			primeOpcode == 44 || primeOpcode == 45) // sdl sdr
		{
			return true;
		}
		return false;
	}

	// Get rid of uninitialized, no use going through those.
	private AddressSetView removeUninitializedBlock(Program program, AddressSetView set) {
		MemoryBlock[] blocks = program.getMemory().getBlocks();
		for (MemoryBlock block : blocks) {
			if (block.isInitialized() && block.isLoaded()) {
				continue;
			}
			AddressSet blocksSet = new AddressSet();
			blocksSet.addRange(block.getStart(), block.getEnd());
			set = set.subtract(blocksSet);
		}
		return set;
	}

	Register alternateReg = null;

	/**
	 * Given one instruction, finds a corresponding paired instruction.
	 */
	private void findPair(Program program, AddressSet pairSet, Instruction start_inst,
			TaskMonitor monitor) {
		Address minPairAddr = start_inst.getMinAddress();

		BigInteger curvalue = program.getProgramContext().getValue(pairBitRegister,
			start_inst.getMinAddress(), false);
		boolean inPairBit = false;
		if (curvalue != null) {
			inPairBit = (curvalue.intValue() == 1);
		}
		if (inPairBit == true) {
			return;
		}

		// Search for a paired instruction
		Instruction curr_inst = start_inst;

		// for 5 instructions in
		//     fallthru, or jump flow
		alternateReg = null;

		int count = 0;
		while (count < 5) {
			// Follow through to get curr_inst we want to inspect
			Instruction next_instr = getNextInstruction(program, curr_inst);

			if (next_instr == null) {
				return;
			}
			curr_inst = next_instr;

			alternateReg = checkForMove(start_inst, curr_inst);

			if (checkPossiblePairInstruction(program, curr_inst.getMinAddress())) {
				Instruction pairInstr = getPairInstruction(start_inst, curr_inst);
				if (pairInstr != null) {
					// TODO: Need to adjust for delay slot for both
					//       set the bit on the whole instruction?, and back up for delay for both
					pairSet.add(getInstPairRange(start_inst));
					pairSet.add(getInstPairRange(pairInstr));
					break;
				}
			}
			count++;
		}
	}

	private Register checkForMove(Instruction start_inst, Instruction curr_inst) {
		// if this is a move, may be copying into another register.
		//  why? wasted code...
		// This is a hack and should be done with real data flow...
		if (curr_inst.getMnemonicString().equals("move")) {
			Register reg = start_inst.getRegister(0);
			Register alt = curr_inst.getRegister(1);
			if (reg != null && reg.equals(alt)) {
				return curr_inst.getRegister(0);
			}
		}
		return alternateReg;
	}

	private AddressRange getInstPairRange(Instruction inst) {
		Address start = inst.getMinAddress();
		Address end = inst.getMinAddress();
		if (inst.isInDelaySlot()) {
			start = inst.getPrevious().getMinAddress();
		}
		return new AddressRangeImpl(start, end);
	}

	private Instruction getNextInstruction(Program program, Instruction curr_inst) {
		// if instruction has a delay slot, check the delay slot instr
		if (curr_inst.getDelaySlotDepth() > 0) {
			return curr_inst.getNext();
		}

		// if instruction is in delay slot, follow delay branch
		while (curr_inst.isInDelaySlot()) {
			curr_inst = curr_inst.getPrevious();
		}

		// follow all jump flows
		FlowType flowType = curr_inst.getFlowType();
		if (flowType.isJump() && !flowType.isConditional()) {
			Address[] flows = curr_inst.getFlows();
			if (flows.length == 0) {
				return null;
			}
			curr_inst = program.getListing().getInstructionAt(flows[0]);
			return curr_inst;
		}

		// go to fall thru
		Address fallThrough = curr_inst.getFallThrough();
		if (fallThrough == null) {
			return null;
		}
		curr_inst = program.getListing().getInstructionAt(fallThrough);
		return curr_inst;
	}

	private Instruction getPairInstruction(Instruction start_inst, Instruction curr_inst) {
		// Get start_inst objects
		Object[] obj1 = getInstObjs(start_inst);
		if (obj1 == null || obj1.length != 3) {
			return null;
		}
		Register destReg1 = (Register) obj1[0];
		Register base1 = (Register) obj1[1];
		Scalar offset1 = (Scalar) obj1[2];
		if (base1 == null || offset1 == null) {
			return null;
		}

		// Get curr_inst objects
		Object[] obj2 = getInstObjs(curr_inst);
		if (obj2 == null || obj2.length != 3) {
			return null;
		}
		Register destReg2 = (Register) obj2[0];
		Register base2 = (Register) obj2[1];
		Scalar offset2 = (Scalar) obj2[2];
		if (base2 == null || offset2 == null) {
			return null;
		}

		// Check if matching pair
		Instruction pairInstr;
		pairInstr =
			checkPair(offset1, offset2, base1, base2, destReg1, destReg2, start_inst, curr_inst);

		// If no matching pair found, return
		return pairInstr;
	}

	private void redoAllPairs(Program program, AddressSet pairSet, TaskMonitor monitor)
			throws CancelledException {

		final int locationCount = pairSet.getNumAddressRanges();
		int count = 0;
		if (locationCount > NOTIFICATION_INTERVAL) {
			monitor.initialize(locationCount);
		}

		Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
		for (AddressRange addressRange : pairSet) {
			monitor.checkCanceled();
			if (locationCount > NOTIFICATION_INTERVAL) {

				if ((count % NOTIFICATION_INTERVAL) == 0) {
					//monitor.setMaximum(locationCount);
					monitor.setProgress(count);
				}
				count++;
			}

			program.getListing().clearCodeUnits(addressRange.getMinAddress(),
				addressRange.getMaxAddress(), false);

			// Set bits
			try {
				program.getProgramContext().setValue(pairBitRegister, addressRange.getMinAddress(),
					addressRange.getMaxAddress(), BigInteger.valueOf(1));

				// Disassemble all again
				AddressSet rangeSet = new AddressSet(addressRange);
				dis.disassemble(rangeSet, rangeSet, false);
				// don't notify anyone of new code, since this analyzer should run very early on all new code
			}
			catch (ContextChangeException e) {
				Msg.error(this, "Unexpected Exception", e);
			}
		}

	}

	/**
	 * @param inst		instruction to getOpObjects
	 * @return retObjs	Object array containing destReg, base, and offset
	 */
	private Object[] getInstObjs(Instruction inst) {
		Object[] retObjs = new Object[3];

		Object[] outputs = inst.getOpObjects(0);
		if (outputs.length != 1 || !(outputs[0] instanceof Register)) {
			return null;
		}
		retObjs[0] = outputs[0];

		Object[] obj = inst.getOpObjects(1);
		for (Object element : obj) {
			if (element instanceof Register) {
				retObjs[1] = element;
			}
			if (element instanceof Scalar) {
				retObjs[2] = element;
			}
		}

		return retObjs;
	}

	/**
	 * Checks if two instructions are a pair.
	 * A pair is found if
	 *  1) mnemonics are correct
	 * 	2) offset difference is correct
	 * 	3) destination and base registers match
	 *
	 * @param offset1
	 * @param offset2
	 * @param base1
	 * @param base2
	 * @param destReg1
	 * @param destReg2
	 * @param str			start inst mnemonic
	 * @param curr_inst
	 * @return Instruction that is the pair of this one
	 */
	private Instruction checkPair(Scalar offset1, Scalar offset2, Register base1, Register base2,
			Register destReg1, Register destReg2, Instruction start_inst, Instruction curr_inst) {
		int start_index1 = 0;
		int start_index2 = 0;
		String str = start_inst.getMnemonicString();
		String str2 = curr_inst.getMnemonicString();

		// Check for delay slot
		if (str.charAt(0) == '_') {
			start_index1 = 1;
		}
		if (str2.charAt(0) == '_') {
			start_index2 = 1;
		}

		// Check mnemonics are matching
		if (!str.substring(start_index1, start_index1 + 2).equals(
			str2.substring(start_index2, start_index2 + 2))) {
			return null;
		}

		// Check offset
		long diff = Math.abs(offset2.getSignedValue() - offset1.getSignedValue());
		if ((str.endsWith("wl") || str.endsWith("wr")) && diff != 3) {
			return null;
		}
		else if ((str.endsWith("dl") || str.endsWith("dr")) && diff != 7) {
			return null;
		}

		// Check base and destination registers
		if (base1.equals(base2) && (destReg1.equals(destReg2) | destReg2.equals(alternateReg))) {
			// Match found
			return curr_inst;
		}
		return null;
	}

}
