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
import java.util.Arrays;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.PartitionCodeSubModel;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ContextEvaluator;
import ghidra.program.util.ContextEvaluatorAdapter;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;

public class MultiInstructionMemReference extends GhidraScript {

	Address memReferenceLocation = null;
	private Address curInstrloc;
	private Object[] inputObjects;
	private Object[] resultObjects;
	private Register singleRegister;
	private boolean  registerInOut;
	private boolean targetInDelaySlot = false;
	
	@Override
	public void run() throws Exception {
		long numInstructions = currentProgram.getListing().getNumInstructions();
		monitor.initialize((int) (numInstructions));
		monitor.setMessage("Multi-Instruction Reference Markup");
		int currentOpIndex = -1;

		Address start = currentLocation.getAddress();

		if ((currentSelection == null || currentSelection.isEmpty()) &&
			currentLocation instanceof OperandFieldLocation) {
			OperandFieldLocation operandLocation = (OperandFieldLocation) currentLocation;
			currentOpIndex = operandLocation.getOperandIndex();
			int subOpIndex = operandLocation.getSubOperandIndex();
			singleRegister = getRegister(start, currentOpIndex, subOpIndex);
		}

		// set up the address set to restrict processing
		AddressSet refLocationsSet = new AddressSet(currentSelection);
		if (refLocationsSet.isEmpty()) {
			refLocationsSet.addRange(start, start);
		}

		findMemRefAtOperand(currentOpIndex, refLocationsSet);
	}

	/**
	 * Get the register at the location
	 * 
	 * @param opIndex index into operands for instruction
	 * @param subOpIndex index into operands for an operand location
	 * 
	 * @return register if there is one at the location
	 */
	private Register getRegister(Address addr, int opIndex, int subOpIndex) {
		if (addr == null) {
			return null;
		}
		
		Instruction instr = currentProgram.getListing().getInstructionContaining(addr);
		if (instr == null) {
			return null;
		}
		
		List<Object> defOpRep = instr.getDefaultOperandRepresentationList(opIndex);
		if (subOpIndex >= 0 && subOpIndex < defOpRep.size()) {
			Object obj = defOpRep.get(subOpIndex);
			if (obj instanceof Register) {
			 return (Register) obj;
			}
		}
		return instr.getRegister(opIndex);
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
			public boolean evaluateContextBefore(VarnodeContext context, Instruction instr) {
				// if the requested reference was on an input op-object, get context before exec
				return checkContext(true, opIndex, context, instr);
			}

			@Override
			public boolean evaluateContext(VarnodeContext context, Instruction instr) {
				// if the requested reference was on an output op-object, get context after exec
				return checkContext(false, opIndex, context, instr);
			}


			private boolean checkContext(boolean input, final int opIndex, VarnodeContext context, Instruction instr) {
				if (instr.getMinAddress().equals(curInstrloc)) {
					if (targetInDelaySlot && instr.getDelaySlotDepth() > 0) {
						instr = instr.getNext();
					}
					if (checkInstructionMatch(opIndex, input, context, instr)) {
						return true;
					}
					// if instruction is in delayslot, assume reference is good.
					if (instr.getDelaySlotDepth() > 0) {
						instr = instr.getNext();
						return checkInstructionMatch(opIndex, input, context, instr);
					}
				}
				return false;
			}
			

			@Override
			public boolean evaluateReference(VarnodeContext context, Instruction instr, int pcodeop, Address address,
					int size, RefType refType) {
				
				return super.evaluateReference(context, instr, pcodeop, address, size, refType);
			}


			private boolean checkInstructionMatch(final int opIdx, boolean input, VarnodeContext context,
					Instruction instr) {
				List<Object> list = Arrays.asList(input ? inputObjects : resultObjects);
				
				for (int index = opIdx; index < instr.getNumOperands(); index++)
				{
					if (getRefsForOperand(context, instr, list, index)) {
						// register is both an in/out check if symbolic on out
						if (registerInOut) {
							break;
						}
						return true;
					}
				}
				if (addSymbolicRefs(input, context, instr, list)) {
					return true;
				}
				return false;
			}


			/**
			 * Check the current operand for references based on input/outputs
			 * 
			 * @param context - context holding values
			 * @param instr - instruction under consideration
			 * @param list - input/output lists
			 * @param opIndex - index of operand to check
			 * 
			 * @return true if a reference was found
			 */
			private boolean getRefsForOperand(VarnodeContext context, Instruction instr, List<Object> list, int opIndex) {
				Object[] opObjects = instr.getOpObjects(opIndex);
				for (int indexOpObj = 0; indexOpObj < opObjects.length; indexOpObj++) {
					if (!(opObjects[indexOpObj] instanceof Register)) {
						continue;
					}
					Register reg = (Register) opObjects[indexOpObj];

					// if operand has a single register and this isn't it
					if (singleRegister != null && !reg.equals(singleRegister)) {
						continue;
					}
					
					// check that the register is on the correct input/output list
					if (!list.contains(reg)) {
						continue;
					}
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
					makeReference(instr, opIndex, addr);
					return true;
				}
				return false;
			}

			private boolean addSymbolicRefs(boolean input, VarnodeContext context, Instruction instr, List<Object> list) {
				// get the value of the single register to see if this is the value desired
				if (singleRegister == null) {
					return false;
				}
				// check that the register is on the correct input/output list
				if (!list.contains(singleRegister)) {
					return false;
				}
			    Varnode registerVarnodeValue = context.getRegisterVarnodeValue(singleRegister);
			    if (!context.isSymbol(registerVarnodeValue) && !registerVarnodeValue.isRegister()) {
			    	return false;
			    }
				Address symAddr = registerVarnodeValue.getAddress();
				if (symAddr == context.BAD_ADDRESS) {
					return false;
				}
				
				String valStr = "";
				if (registerVarnodeValue.isRegister()) {
					valStr = context.getRegister(registerVarnodeValue).toString();
				} else {
					// is an offset from a space
					String name = symAddr.getAddressSpace().getName();
					BigInteger offset = symAddr.getOffsetAsBigInteger();
					valStr = name + " + 0x" + offset.toString(16);
				}
				Address lastSetLocation = context.getLastSetLocation(singleRegister, null);

				
				String comment = instr.getComment(Instruction.EOL_COMMENT);
				if (comment == null) {
					comment = "";
				}
				
				String inoutChar = (input ? " " : "\'");
				String lastStr = (lastSetLocation != null ? " @" + lastSetLocation : "");
				
				String markup = singleRegister+inoutChar+"= "+ valStr + lastStr;
				if (comment.replace('\'',' ').contains(markup.replace('\'',' '))) {
					return false;
				}
				comment = (comment.trim().length()==0 ? markup : comment + "\n" + markup);
				instr.setComment(Instruction.EOL_COMMENT, comment);
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

				Instruction instr = currentProgram.getListing().getInstructionAt(curInstrloc);
				if (instr != null) {
					inputObjects = instr.getInputObjects();
					resultObjects = instr.getResultObjects();
					registerInOut = checkRegisterInOut(singleRegister, inputObjects, resultObjects);
				}
				
				// if the instruction attempting to markup is in the delayslot, backup an instruction
				if (instr != null && instr.isInDelaySlot()) {
					instr = instr.getPrevious();
					if (instr != null) {
						curInstrloc = instr.getMinAddress();
						targetInDelaySlot  = true;
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

	private boolean checkRegisterInOut(Register reg, Object[] in, Object[] out) {
		if (reg == null || in == null || out == null) {
			return false;
		}
		
		List<Object> inList = Arrays.asList(in);
		List<Object> outList = Arrays.asList(out);
		
		return inList.contains(reg) && outList.contains(reg);
	}

	/** Make the reference on the instruction at the correct location.
	 * 
	 * @param instruction to receive reference
	 * @param space reference created in this space
	 * @param scalar used as offset into address space
	 */
	private void makeReference(Instruction instruction, int opIndex, Address addr) {
		if (targetInDelaySlot && instruction.getPrototype().hasDelaySlots()) {
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
		
		// check if it already has the reference
	    Reference[] referencesFrom = instruction.getReferencesFrom(); 
		boolean hasRef = Arrays.stream(referencesFrom).anyMatch(p -> p.getToAddress().equals(addr));
	    if (hasRef) {
	    	return;
	    }

		if (opIndex == -1) {
			instruction.addMnemonicReference(addr, RefType.DATA, SourceType.ANALYSIS);
		}
		else {
			instruction.addOperandReference(opIndex, addr, RefType.DATA, SourceType.ANALYSIS);
		}
	}
}
