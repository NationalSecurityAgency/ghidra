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
// Figures out computed memory references at the current cursor location or at the instruction at the
// start of each range in an address set.
// Place the cursor on a register or constant operand, and run the script.  Also, if a
// register has a value set at the beginning of a function, that register value is assumed
// to be a constant.
//
// For ease of use, attach this to a key-binding to create the reference in one keystroke.
//
// This script is very useful on the ARM, PowerPC and most RISC based processors that
// use multiple instructions to build up memory references, where the reference was
// missed by auto-analysis.  It is also useful for references that weren't created
// because of complex base address + offset calculations.
//
// It is very easy to use this script in conjunction with any type of search.  For
// example on the ARM, MOVT is used to build up and address.  Search the program text
// for all mnemonics MOVT and then select the ones that are creating a reference, make
// a selection in the listing from the search, and then execute this function.  It is
// best if you have already assigned a key binding.  You can also choose single items
// from the search table and press the key bound to this script.
//
// NOTE: Any values loaded from memory are assumed to be constant.
// If a reference does not make sense on an operand, then it is added to the mnemonic.
//
//@category Analysis

import java.math.BigInteger;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.PartitionCodeSubModel;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class MultiInstructionMemReference extends GhidraScript {

	Address memReferenceLocation = null;
	private Address curInstrloc;

	@Override
	public void run() throws Exception {
		long numInstructions = currentProgram.getListing().getNumInstructions();
		monitor.initialize((int) (numInstructions));
		monitor.setMessage("Multi-Instruction Reference Markup");
		int currentOpIndex = 0;

		Address start = currentLocation.getAddress();

		if ((currentSelection == null || currentSelection.isEmpty()) &&
			currentLocation instanceof OperandFieldLocation) {
			currentOpIndex = ((OperandFieldLocation) currentLocation).getOperandIndex();
		}

		// set up the address set to restrict processing
		AddressSet refLocationsSet = new AddressSet(currentSelection);
		if (refLocationsSet.isEmpty()) {
			refLocationsSet.addRange(start, start);
		}

		findMemRefAtOperand(currentOpIndex, refLocationsSet);
	}

	@SuppressWarnings("unused")
	private boolean isSingleInstructions(AddressSet restrictedSet) {
		if (restrictedSet.isEmpty()) {
			return false;
		}
		AddressRangeIterator riter = restrictedSet.getAddressRanges();
		restrictedSet = new AddressSet(restrictedSet);

		while (riter.hasNext()) {
			AddressRange addressRange = riter.next();
			Instruction instr =
				currentProgram.getListing().getInstructionAt(addressRange.getMinAddress());
			if (instr != null) {
				addressRange = new AddressRangeImpl(instr.getMinAddress(), instr.getMaxAddress());
			}
			restrictedSet.delete(addressRange);
		}
		return restrictedSet.isEmpty();
	}

	private void findMemRefAtOperand(final int opIndex, AddressSetView set) {
		// follow all flows building up context
		// use context to fill out addresses on certain instructions 
		ContextEvaluator eval = new ContextEvaluatorAdapter() {

			@Override
			public boolean evaluateContext(VarnodeContext context, Instruction instr) {
				// TODO: could look at instructions like LEA, that are an address to create a reference to something.
				if (instr.getMinAddress().equals(curInstrloc)) {
					if (checkInstructionMatch(opIndex, context, instr)) {
						return true;
					}
					// if instruction is in delayslot, assume reference is good.
					if (instr.getDelaySlotDepth() > 0) {
						instr = instr.getNext();
						return checkInstructionMatch(opIndex, context, instr);
					}
				}
				return false;
			}

			private boolean checkInstructionMatch(final int opIdx, VarnodeContext context,
					Instruction instr) {
				int firstIndex = opIdx;
				if (instr.getRegister(firstIndex) == null) {
					firstIndex = 0;
				}
				for (int index = firstIndex; index < instr.getNumOperands(); index++) {
					Object[] opObjects = instr.getOpObjects(index);
					for (int indexOpObj = 0; indexOpObj < opObjects.length; indexOpObj++) {
						if (!(opObjects[indexOpObj] instanceof Register)) {
							continue;
						}
						Register reg = (Register) opObjects[indexOpObj];
						RegisterValue rval = context.getRegisterValue(reg);
						if (rval == null) {
							continue;
						}
						BigInteger uval = rval.getUnsignedValue();
						if (uval == null) {
							continue;
						}
						long offset = uval.longValue();
						AddressSpace space = instr.getMinAddress().getAddressSpace();
						Address addr = space.getTruncatedAddress(offset, true);

						// assume that they want the reference, don't worry it isn't in memory
						makeReference(instr, index, addr, monitor);
						return false;

					}
				}
				return false;
			}

			@Override
			public boolean allowAccess(VarnodeContext context, Address addr) {
				// allow values to be read from writable memory
				return true;
			}
		};

		try {
			AddressRangeIterator riter = set.getAddressRanges();
			while (riter.hasNext() && !monitor.isCancelled()) {
				AddressRange addressRange = riter.next();

				curInstrloc = addressRange.getMinAddress();
				AddressSet body = null;
				Address start = curInstrloc;

				Function curFunc =
					currentProgram.getFunctionManager().getFunctionContaining(curInstrloc);
				if (curFunc != null) {
					start = curFunc.getEntryPoint();
					body = new AddressSet(curFunc.getBody());
				}
				else {
					body = new AddressSet(curInstrloc);
					PartitionCodeSubModel model = new PartitionCodeSubModel(currentProgram);
					CodeBlock block = model.getFirstCodeBlockContaining(curInstrloc, monitor);
					if (block != null) {
						start = block.getFirstStartAddress();
						body.add(block);
					}
				}

				// if the instruction attempting to markup is in the delayslot, backup an instruction
				Instruction instr = currentProgram.getListing().getInstructionAt(curInstrloc);
				if (instr != null && instr.isInDelaySlot()) {
					instr = instr.getPrevious();
					if (instr != null) {
						curInstrloc = instr.getMinAddress();
					}
				}

				SymbolicPropogator symEval = new SymbolicPropogator(currentProgram);
				symEval.setParamRefCheck(false);
				symEval.setReturnRefCheck(false);
				symEval.setStoredRefCheck(false);

				symEval.flowConstants(start, body, eval, true, monitor);
			}
		}
		catch (CancelledException e) {
		}
	}

	/**
	 * @param instruction
	 * @param space
	 * @param scalar
	 * @param nextInstr
	 * @param addend
	 * @param taskMonitor
	 */
	private void makeReference(Instruction instruction, int opIndex, Address addr,
			TaskMonitor taskMonitor) {
		if (instruction.getPrototype().hasDelaySlots()) {
			instruction = instruction.getNext();
			if (instruction == null) {
				return;
			}
		}
		if (opIndex == -1) {
			for (int i = 0; i < instruction.getNumOperands(); i++) {
				int opType = instruction.getOperandType(i);
				// markup the program counter for any flow
				if ((opType & OperandType.DYNAMIC) != 0) {
					opIndex = i;
					break;
				}
			}
		}
		if (opIndex == -1) {
			opIndex = instruction.getNumOperands() - 1;
		}

		if (opIndex == -1) {
			instruction.addMnemonicReference(addr, RefType.DATA, SourceType.ANALYSIS);
		}
		else {
			instruction.addOperandReference(opIndex, addr, RefType.DATA, SourceType.ANALYSIS);
		}
	}
}
