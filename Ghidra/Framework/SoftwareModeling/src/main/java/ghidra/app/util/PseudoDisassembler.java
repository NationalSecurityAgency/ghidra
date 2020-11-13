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
package ghidra.app.util;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;

import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.*;

/**
 * PseudoDisassembler.java
 * 
 * Useful for disassembling and getting an Instruction or creating Data
 * at a location in memory when you don't want the program to be changed.
 * 
 * The Instructions or Data that area created are PseudoInstruction's and
 * PseudoData's.  They act like regular instructions in most respects, but
 * they don't exist in the program.  No references, symbols, are created or
 * will be saved when the program is saved.
 * 
 * You do not need to have an open transaction on the program to use the
 * PseudoDisassembler.
 * 
 * The PseudoDisassembler can also be used to check if something is a valid
 * subroutine.  The algorithm it uses could definitely use some tuning, but
 * it generally works well.
 * 
 */
public class PseudoDisassembler {
	// name of register that is used in processors that use the lower bit of addresses
	//   to transfer into an alternate code mode such as from ARM to Thumb code
	private static final String LOW_BIT_CODE_MODE_REGISTER_NAME = "LowBitCodeMode";

	private static final int DEFAULT_MAX_INSTRUCTIONS = 4000;

	Program program = null;

	private ProgramContext programContext = null;

	private Language language = null;

	private Memory memory = null;

	private int pointerSize;

	final static int MAX_REPEAT_BYTES_LIMIT = 4;  // only let 4 consecutive instructions with the same repeated bytes

	private int maxInstructions = DEFAULT_MAX_INSTRUCTIONS;

	private boolean respectExecuteFlag = false;

	/**
	 * Create a pseudo disassembler for the given program.
	 */
	public PseudoDisassembler(Program program) {
		this.program = program;

		memory = program.getMemory();

		this.language = program.getLanguage();

		pointerSize = program.getDefaultPointerSize();

		this.programContext = program.getProgramContext();
	}

	/**
	 * Set the maximum number of instructions to check
	 * 
	 * @param maxNumInstructions - maximum number of instructions to check before returning
	 */
	public void setMaxInstructions(int maxNumInstructions) {
		maxInstructions = maxNumInstructions;
	}

	/**
	 * Set flag to respect Execute bit on memory if present on any memory
	 * 
	 * @param respect - true, respect execute bit on memory blocks
	 */
	public void setRespectExecuteFlag(boolean respect) {
		respectExecuteFlag = respect;
	}

	/**
	 * Disassemble a single instruction.  The program is not affected.
	 * 
	 * @param addr location to disassemble
	 * @return a PseudoInstruction
	 * 
	 * @throws InsufficientBytesException
	 * @throws UnknownInstructionException
	 * @throws UnknownContextException
	 */
	public PseudoInstruction disassemble(Address addr) throws InsufficientBytesException,
			UnknownInstructionException, UnknownContextException {

		PseudoDisassemblerContext procContext = new PseudoDisassemblerContext(programContext);

		procContext.flowStart(addr);
		return disassemble(addr, procContext, false);
	}

	/**
	 * Disassemble a single instruction.  The program is not affected.
	 * @param addr
	 * @param disassemblerContext
	 * @param isInDelaySlot
	 * @return
	 * @throws InsufficientBytesException
	 * @throws UnknownInstructionException
	 * @throws UnknownContextException
	 */
	public PseudoInstruction disassemble(Address addr,
			PseudoDisassemblerContext disassemblerContext, boolean isInDelaySlot)
			throws InsufficientBytesException, UnknownInstructionException,
			UnknownContextException {

		MemBuffer memBuffer = new DumbMemBufferImpl(memory, addr);

		// check that address is defined in memory
		try {
			memBuffer.getByte(0);
		}
		catch (Exception e) {
			return null;
		}

		InstructionPrototype prototype = null;

		try {
			prototype = language.parse(memBuffer, disassemblerContext, isInDelaySlot);
		}
		catch (UnknownInstructionException unknownExc) {
			return null;
		}

		if (prototype == null) {
			return null;
		}

		PseudoInstruction instr;
		try {
			instr = new PseudoInstruction(program, addr, prototype, memBuffer, disassemblerContext);
		}
		catch (Exception e) {
			// this is here, if a prototype matches for some number of bytes, but
			//   the actual instruction is longer than the number of bytes needed for matching
			//   the prototype.  And all the bytes for the instruction are not available.
			return null;
		}

		return instr;
	}

	/**
	 * Disassemble a location in memory with the given set of bytes.
	 * Useful when the address has no actual bytes defined, or you want to use
	 * your own bytes instead of what is in the program at the address.
	 * 
	 * @param addr address to disassemble
	 * @param bytes bytes to use instead of those currently defined in program
	 * @return PseudoInstruction.
	 * 
	 * @throws InsufficientBytesException
	 * @throws UnknownInstructionException
	 * @throws UnknownContextException
	 */
	public PseudoInstruction disassemble(Address addr, byte bytes[])
			throws InsufficientBytesException, UnknownInstructionException,
			UnknownContextException {

		PseudoDisassemblerContext procContext = new PseudoDisassemblerContext(programContext);
		return disassemble(addr, bytes, procContext);
	}

	/**
	 * Disassemble a location in memory with the given set of bytes.
	 * Useful when the address has no actual bytes defined, or you want to use
	 * your own bytes instead of what is in the program at the address.
	 * 
	 * @param addr address to disassemble
	 * @param bytes bytes to use instead of those currently defined in program
	 * @param disassemblerContext the disassembler context to use.
	 * @return PseudoInstruction.
	 * 
	 * @throws InsufficientBytesException
	 * @throws UnknownInstructionException
	 * @throws UnknownContextException
	 */
	public PseudoInstruction disassemble(Address addr, byte bytes[],
			PseudoDisassemblerContext disassemblerContext) throws InsufficientBytesException,
			UnknownInstructionException, UnknownContextException {

		MemBuffer memBuffer = new ByteMemBufferImpl(addr, bytes, language.isBigEndian());

		// check that address is defined in memory
		try {
			memBuffer.getByte(0);
		}
		catch (Exception e) {
			return null;
		}

		InstructionPrototype prototype = null;
		disassemblerContext.flowStart(addr);
		prototype = language.parse(memBuffer, disassemblerContext, false);

		if (prototype == null) {
			return null;
		}

		PseudoInstruction instr;
		try {
			instr = new PseudoInstruction(program, addr, prototype, memBuffer, disassemblerContext);
		}
		catch (AddressOverflowException e) {
			throw new InsufficientBytesException(
				"failed to build pseudo instruction at " + addr + ": " + e.getMessage());
		}

		return instr;
	}

	/**
	 * Apply a dataType to the program at the given address.  The program is
	 * not affected.  A PseudoData item that acts like a Data item retrieved from
	 * a program is returned.  This is useful if you have a datatype and you
	 * want to use it to get values from the program at a given address.
	 * 
	 * @param addr location to get a PseudoData item for
	 * @param dt the data type to be applied
	 * @return PsuedoData that acts like Data
	 */
	public PseudoData applyDataType(Address addr, DataType dt) {

		Memory memory = program.getMemory();

		MemBuffer memBuffer = new DumbMemBufferImpl(memory, addr);

		// check that address is defined in memory
		try {
			memBuffer.getByte(0);
			return new PseudoData(program, addr, dt, memBuffer);
		}
		catch (Exception e) {
			// ignore
		}
		return null;
	}

	/**
	 * Interpret the bytes at a location in memory as an address
	 * and return the address.  This routine assumes that the bytes
	 * needed to create the address are the same size as the bytes
	 * needed to represent the toAddr.  So this is somewhat generic.
	 * 
	 * @param toAddr location of the bytes in memory
	 * 
	 * @return the address value
	 */
	public Address getIndirectAddr(Address toAddr) {
		Data data =
			applyDataType(toAddr, PointerDataType.getPointer(null, toAddr.getPointerSize()));

		if (data == null) {
			return null;
		}
		Object objVal = data.getValue();
		if (!(objVal instanceof Address)) {
			return null;
		}
		Address ptrAddr = (Address) objVal;

		return ptrAddr;
	}

	/**
	 * Check that this entry point leads to a well behaved subroutine:
	 * <ul>
	 * <li>It should return.</li>
	 * <li>Hit no bad instructions.</li>
	 * <li>Have only one entry point.</li>
	 * <li>Not overlap any existing data or instructions.</li>
	 * </ul>
	 * @param entryPoint entry point to check
	 * @return true if entry point leads to a well behaved subroutine
	 */
	public boolean isValidSubroutine(Address entryPoint) {
		return isValidSubroutine(entryPoint, false);
	}

	/**
	 * Check that this entry point leads to a well behaved subroutine, allow it
	 * to fall into existing code.
	 * <ul>
	 * <li>It should return.</li>
	 * <li>Hit no bad instructions.</li>
	 * <li>Have only one entry point.</li>
	 * <li>Not overlap any existing data or cause offcut references.</li>
	 * </ul>
	 * @param entryPoint entry point to check
	 * @param allowExistingCode true allows this subroutine to flow into existing instructions.
	 * @return true if entry point leads to a well behaved subroutine
	 */
	public boolean isValidSubroutine(Address entryPoint, boolean allowExistingCode) {
		return checkValidSubroutine(entryPoint, allowExistingCode);
	}

	/**
	 * Check that this entry point leads to a well behaved subroutine, allow it
	 * to fall into existing code.
	 * <ul>
	 * <li>Hit no bad instructions.</li>
	 * <li>Have only one entry point.</li>
	 * <li>Not overlap any existing data or cause offcut references.</li>
	 * </ul>
	 * @param entryPoint         entry point to check
	 * @param allowExistingCode  true allows this subroutine to flow into existing instructions.
	 * @param mustTerminate      true if the subroutine must terminate
	 * 
	 * @return true if entry point leads to a well behaved subroutine
	 */
	public boolean isValidSubroutine(Address entryPoint, boolean allowExistingCode,
			boolean mustTerminate) {
		return checkValidSubroutine(entryPoint, allowExistingCode, mustTerminate);
	}

	/**
	 * Check that this entry point leads to valid code:
	 * <ul>
	 * <li> May have multiple entries into the body of the code.
	 * <li>The intent is that it be valid code, not nice code.
	 * <li>Hit no bad instructions.
	 * <li>It should return.
	 * </ul>
	 * @param entryPoint
	 * @return true if the entry point leads to valid code
	 */
	public boolean isValidCode(Address entryPoint) {
		boolean valid = checkValidSubroutine(entryPoint, true, false);
		return valid;
	}

	/**
	 * Check that this entry point leads to valid code:
	 * <ul>
	 * <li> May have multiple entries into the body of the code.
	 * <li>The intent is that it be valid code, not nice code.
	 * <li>Hit no bad instructions.
	 * <li>It should return.
	 * </ul>
	 * 
	 * @param entryPoint location to test for valid code
	 * @param context disassembly context for program
	 * 
	 * @return true if the entry point leads to valid code
	 */
	public boolean isValidCode(Address entryPoint, PseudoDisassemblerContext context) {
		boolean valid = checkValidSubroutine(entryPoint, context, true, false);
		return valid;
	}

	/**
	 * Process a subroutine using the processor function.
	 * The process function can control what flows are followed and when to stop.
	 * 
	 * @param entryPoint start address
	 * @param processor processor to use
	 * @return the address set of instructions that were followed
	 */
	public AddressSet followSubFlows(Address entryPoint, int maxInstr,
			PseudoFlowProcessor processor) {
		PseudoDisassemblerContext procContext = new PseudoDisassemblerContext(programContext);

		return followSubFlows(entryPoint, procContext, maxInstr, processor);
	}

	/**
	 * Process a subroutine using the processor function.
	 * The process function can control what flows are followed and when to stop.
	 * 
	 * @param entryPoint start address
	 * @param processor processor to use
	 * @return the address set of instructions that were followed
	 */
	public AddressSet followSubFlows(Address entryPoint, PseudoDisassemblerContext procContext,
			int maxInstr, PseudoFlowProcessor processor) {
		AddressSet body = new AddressSet();
		AddressSet instrStarts = new AddressSet();

		if (hasLowBitCodeModeInAddrValues(program)) {
			entryPoint = setTargeContextForDisassembly(procContext, entryPoint);
		}
		Address target = entryPoint;

		ArrayList<Address> targetList = new ArrayList<>(); // list of valid targets
		ArrayList<Address> untriedTargetList = new ArrayList<>(); // list of valid targets

		// if entry point starts with 00 byte instruction, assume not valid
		Address tempAddr;

		try {
			tempAddr = entryPoint;

			byte[] ptrbytes = new byte[pointerSize];
			if (memory.getBytes(tempAddr, ptrbytes) == ptrbytes.length) {
				boolean allZero = true;
				for (byte ptrbyte : ptrbytes) {
					if (ptrbyte != 0) {
						allZero = false;
						break;
					}
				}
				if (allZero) {
					return body;
				}
			}
		}
		catch (MemoryAccessException e1) {
			return body;
		}
		catch (AddressOutOfBoundsException e2) {
			return body;
		}

		procContext.flowStart(entryPoint);

		try {
			// look some number of fallthroughs to see if this
			//   is a valid run of instructions.

			for (int i = 0; target != null && i < maxInstr; i++) {
				PseudoInstruction instr;
				instr = disassemble(target, procContext, false);

				boolean doContinue = processor.process(instr);
				if (!doContinue) {
					return body;
				}

				if (instr == null) {
					target = getNextTarget(body, untriedTargetList);
					continue;
				}
				Address newTarget = null;
				body.addRange(instr.getMinAddress(), instr.getMaxAddress());
				instrStarts.addRange(instr.getMinAddress(), instr.getMinAddress());

				// check whether processor wants to follow flow on this instruction
				if (!processor.followFlows(instr)) {
					target = getNextTarget(body, untriedTargetList);
					continue;
				}

				// if instruction has fall thru
				if (instr.hasFallthrough()) {
					newTarget = instr.getFallThrough();
				}
				else {
					// check if any forward jump reference is targeted right after this instruction
					Address nextAddr = instr.getMaxAddress().next();
					if (targetList.contains(nextAddr)) {
						newTarget = nextAddr;
					}
					else if (instr.getFlowType().isJump()) {
						// if this is a jump, and jumps forward only some number of bytes
						//    make that the new target.
						Address flows[] = instr.getFlows();
						if (flows != null) {
							for (Address address : flows) {
								if (!body.contains(address)) {
									newTarget = address;
									break;
								}
							}
						}
					}

					if (newTarget == null) {
						newTarget = getNextTarget(body, untriedTargetList);
					}
				}

				// if this is a jump, add it's targets to list of valid
				//   forward reference continuation points.
				if (instr.getFlowType().isJump()) {
					Address flows[] = instr.getFlows();
					if (flows != null) {
						for (Address address : flows) {
							targetList.add(address);
							untriedTargetList.add(address);
						}
					}
				}
				target = newTarget;
			}
		}
		catch (InsufficientBytesException e) {
			processor.process(null);
		}
		catch (UnknownInstructionException e) {
			processor.process(null);
		}
		catch (UnknownContextException e) {
			processor.process(null);
		}

		return body;
	}

	/**
	 * Gets a new target address from the untried target list if it can find one not already in the
	 * disassembled address set that is passed in.
	 * @param body address set of disassembled instructions
	 * @param untriedTargetList list of untried valid targets
	 * @return a new target address or null
	 */
	private Address getNextTarget(AddressSet body, ArrayList<Address> untriedTargetList) {
		Address newTarget = null;

		// no new target, try to get it from the targetList
		if (!untriedTargetList.isEmpty()) {
			Iterator<Address> iter = untriedTargetList.iterator();
			while (iter.hasNext()) {
				Address possibleTarget = iter.next();
				if (!body.contains(possibleTarget)) {
					newTarget = possibleTarget;
					iter.remove();
					break;
				}
			}
		}
		return newTarget;
	}

	/**
	 * Check if there is a valid subroutine starting at the target address.
	 * It does this by following the flow until a terminator is reached.
	 * If a bad instruction is hit or it does not flow well, then return
	 * false.
	 * 
	 * @param target - taraget address to disassemble
	 * 
	 * @return true if this is a probable subroutine.
	 */
	private boolean checkValidSubroutine(Address entryPoint, boolean allowExistingInstructions) {
		return checkValidSubroutine(entryPoint, allowExistingInstructions, true);
	}

	private boolean checkValidSubroutine(Address entryPoint, boolean allowExistingInstructions,
			boolean mustTerminate) {
		PseudoDisassemblerContext procContext = new PseudoDisassemblerContext(programContext);

		return checkValidSubroutine(entryPoint, procContext, allowExistingInstructions,
			mustTerminate);
	}

	public boolean checkValidSubroutine(Address entryPoint, PseudoDisassemblerContext procContext,
			boolean allowExistingInstructions, boolean mustTerminate) {
		AddressSet body = new AddressSet();
		AddressSet instrStarts = new AddressSet();
		AddressSetView execSet = memory.getExecuteSet();

		if (hasLowBitCodeModeInAddrValues(program)) {
			entryPoint = setTargeContextForDisassembly(procContext, entryPoint);
		}
		Address target = entryPoint;

		ArrayList<Address> targetList = new ArrayList<>(); // list of valid targets
		ArrayList<Address> untriedTargetList = new ArrayList<>(); // list of valid targets
		boolean didTerminate = false;
		boolean didCallValidSubroutine = false;

		// if entry point starts with 00 byte instruction, assume not valid
		try {
			if (memory.getLong(entryPoint) == 0) {
				return false;
			}
		}
		catch (MemoryAccessException e1) {
			return false;
		}
		catch (AddressOutOfBoundsException e2) {
			return false;
		}

		RepeatInstructionByteTracker repeatInstructionByteTracker =
			new RepeatInstructionByteTracker(MAX_REPEAT_BYTES_LIMIT, null);

		procContext.flowStart(entryPoint);
		try {
			// look some number of fallthroughs to see if this
			//   is a valid run of instructions.

			for (int i = 0; target != null && i < maxInstructions; i++) {
				if (target.compareTo(procContext.getAddress()) < 0) {
					procContext.copyToFutureFlowState(target);
					procContext.flowEnd(procContext.getAddress());
					procContext.flowStart(target);
				}
				else {
					procContext.flowToAddress(target);
				}
				PseudoInstruction instr = disassemble(target, procContext, false);
				if (instr == null) {
					// if the target is in the external section, which is uninitialized, ignore it!
					//    it is probably a JUMP to an external function.
					MemoryBlock block = memory.getBlock(target);
					if (block == null || block.isInitialized() ||
						!block.getName().equals(MemoryBlock.EXTERNAL_BLOCK_NAME)) {
						return false;
					}
					targetList.remove(target);
					target = getNextTarget(body, untriedTargetList);
					repeatInstructionByteTracker.reset();
					continue;
				}

				// check if we are getting into bad instruction runs
				if (repeatInstructionByteTracker.exceedsRepeatBytePattern(instr)) {
					return false;
				}

				Address maxAddr = instr.getMaxAddress();

				Address newTarget = null;
				body.addRange(target, maxAddr);
				instrStarts.add(target);

				// If this is a delay slot instruction - make sure delay slots disassemble OK
				int delaySlots = instr.getDelaySlotDepth();
				Address addr = maxAddr;
				for (int delaySlot = 0; delaySlot < delaySlots; delaySlot++) {
					try {
						addr = addr.addNoWrap(1);
					}
					catch (AddressOverflowException e) {
						return false;
					}
					procContext.flowToAddress(addr);
					PseudoInstruction dsInstr = disassemble(addr, procContext, true);
					if (dsInstr == null) {
						return false;
					}
					maxAddr = dsInstr.getMaxAddress();
					body.addRange(addr, maxAddr);
					instrStarts.add(addr);
					addr = maxAddr;
				}

				FlowType flowType = instr.getFlowType();
				if (flowType.isTerminal()) {
					didTerminate |= isReallyReturn(instr);
				}

				// if instruction has fall thru
				Address fallThru = null;
				if (instr.hasFallthrough()) {
					if (checkNonReturning(program, flowType, instr)) {
						target = getNextTarget(body, untriedTargetList);
						repeatInstructionByteTracker.reset();
						continue;
					}
					newTarget = instr.getFallThrough();
					fallThru = newTarget;
				}
				else {
					// check if any forward jump reference is targeted right after this instruction
					Address nextAddr = maxAddr.next();
					if (targetList.contains(nextAddr)) {
						newTarget = nextAddr;
					}
					else if (flowType.isJump()) {
						// if this is a jump, and jumps forward only some number
						// of bytes
						// make that the new target.
						Address flows[] = instr.getFlows();
						if (flows != null) {
							for (Address address : flows) {
								if (!body.contains(address)) {
									newTarget = address;
									break;
								}
							}
						}
					}

					if (newTarget == null) {
						newTarget = getNextTarget(body, untriedTargetList);
						repeatInstructionByteTracker.reset();
					}
				}

				// if this is a jump, add it's targets to list of valid
				// forward reference continuation points.
				if (flowType.isJump()) {
					Address flows[] = instr.getFlows();
					if (flows != null && flows.length > 0) {
						for (Address address : flows) {
							// if jump target is the same as the fallthru
							// Instructions with delay slots are allowed.
							if (fallThru != null &&
								address.equals(fallThru) & !instr.getPrototype().hasDelaySlots()) {
								return false;
							}
							// if this code jumps to an existing function, allow it
							Function func = null;
							if (program != null) {
								func = program.getFunctionManager().getFunctionAt(address);
							}
							if (func != null) {
								didCallValidSubroutine = true;
								newTarget = getNextTarget(body, untriedTargetList);
								repeatInstructionByteTracker.reset();
								continue;
							}
							targetList.add(address);
							untriedTargetList.add(address);
						}
					}
					else if (flowType.isComputed()) {
						didTerminate = true;
					}
				}
				if (flowType.isCall() || (flowType.isJump() && flowType.isComputed())) {
					Address flows[] = instr.getFlows();
					if (flows == null || flows.length == 0) {
						Reference[] refsFrom = instr.getReferencesFrom();
						if (refsFrom != null && refsFrom.length > 0) {
							flows = new Address[1];
							flows[0] = refsFrom[0].getToAddress();
						}
					}
					if (flows != null && flows.length > 0) {
						for (Address flow : flows) {
							// does this reference a valid function?
							if (program != null) {
								Symbol[] syms = program.getSymbolTable().getSymbols(flow);
								for (Symbol sym : syms) {
									if (sym.getSymbolType() == SymbolType.FUNCTION) {
										didCallValidSubroutine = true;
										break;
									}
								}
							}
							// if respecting execute flag on memory, test to make sure we did flow into non-execute memory
							if (respectExecuteFlag && !execSet.isEmpty() && !execSet.contains(flow)) {
								if (!flow.isExternalAddress()) {
									MemoryBlock block = memory.getBlock(flow);
									// flowing into non-executable, but readable memory is bad
									if (block != null && block.isRead() &&
										!MemoryBlock.EXTERNAL_BLOCK_NAME.equals(block.getName())) {
										return false;
									}
								}
							}
						}
					}
				}
				target = newTarget;
			}
		}
		catch (InsufficientBytesException e) {
			return false;
		}
		catch (UnknownInstructionException e) {
			return false;
		}
		catch (UnknownContextException e) {

		}

		// get rid of anything on target list that is in body of instruction
		Iterator<Address> iter = targetList.iterator();
		while (iter.hasNext()) {
			Address targetAddr = iter.next();
			if (body.contains(targetAddr)) {
				iter.remove();
			}
			// if this target does not refer to an instruction start.
			if (!instrStarts.contains(targetAddr)) {
				return false;
			}
		}

		// if target list is empty, and we are at a terminal instruction
		if (targetList.isEmpty() && (didTerminate || !mustTerminate || didCallValidSubroutine)) {
			// check that the body of the function doesn't break any rules.
			return checkPseudoBody(entryPoint, body, instrStarts, allowExistingInstructions,
				didCallValidSubroutine);
		}

		return false;
	}

	private boolean checkNonReturning(Program program, FlowType flowType, PseudoInstruction instr) {
		if (!flowType.isCall()) {
			return false;
		}

		Address[] flows = instr.getFlows();
		Function func = null;
		if (flows.length > 0) {
			if (program != null) {
				func = program.getFunctionManager().getFunctionAt(flows[0]);
			}
		}
		else {
			if (flowType.isComputed() & !flowType.isConditional()) {
				for (int opIndex = 0; opIndex < instr.getNumOperands(); opIndex++) {
					RefType operandRefType = instr.getOperandRefType(opIndex);
					if (operandRefType.isIndirect()) {
						Address addr = instr.getAddress(opIndex);
						if (addr != null) {
							func = program.getFunctionManager().getReferencedFunction(addr);
						}
					}
				}
			}
		}

		return (func != null && func.hasNoReturn());
	}

	/**
	 * Make sure the instruction really has a return in it.
	 * 
	 * @param instr instruction to check
	 */
	private boolean isReallyReturn(Instruction instr) {
		PcodeOp[] pcode = instr.getPcode();
		for (PcodeOp element : pcode) {
			if (element.getOpcode() == PcodeOp.RETURN) {
				return true;
			}
		}
		return false;
	}

	private boolean checkPseudoBody(Address entry, AddressSet body, AddressSet starts,
			boolean allowExistingInstructions, boolean didCallValidSubroutine) {

		if (program == null) {
			return true;
		}

		// check that body does not wander into non-executable memory
		AddressSetView execSet = memory.getExecuteSet();
		if (respectExecuteFlag && !execSet.isEmpty() && !execSet.contains(body)) {
			return false;
		}

		// check that the body traversed to a terminal does not
		//   have any anomolies in it.
		//   Existing Instructions/Data
		if (program.getListing().getDefinedData(body, true).hasNext()) {
			return false;
		}

		boolean canHaveOffcutEntry = hasLowBitCodeModeInAddrValues(program);
		AddressSet strictlyBody = body.subtract(starts);
		if (canHaveOffcutEntry) {
			strictlyBody.deleteRange(entry, entry.add(1));
		}
		AddressIterator addrIter =
			program.getReferenceManager().getReferenceDestinationIterator(strictlyBody, true);
		if (addrIter.hasNext()) {
			return false;  // don't allow offcut references
		}

		// if existing instructions are allowed,
		//    don't worry about multiple entry points either.
		if (allowExistingInstructions) {
			return true;
		}

		if (program.getListing().getInstructions(body, true).hasNext()) {
			return false;
		}

		// don't allow one instruction
		if (!didCallValidSubroutine && starts.getMinAddress().equals(starts.getMaxAddress())) {
			return false;
		}

		// if there are any references internally, that isn't the entry point
		//  it is a bady subroutine.
		AddressIterator iter;
		iter = program.getReferenceManager().getReferenceDestinationIterator(body, true);
		while (iter.hasNext()) {
			Address toAddr = iter.next();
			if (!toAddr.equals(entry)) {
				if (entry.add(1).equals(toAddr) && hasLowBitCodeModeInAddrValues(program)) {
					continue;
				}
				return false;
			}
		}
		return true;
	}

	/************************************************************************
	 * TODO: These routines below are gathered here so that the common concern can
	 * be found and dealt with in one place.  Eventually the DisassemblerCmd()
	 * will handle some of these concerns.  They are here until a larger refactoring
	 * 
	 */

	/**
	 * Get an address that can be used for disassembly.  Useful for some processors where
	 * pointers to code have 1 added to them for different modes such as Thumb mode for ARM.
	 * 
	 * @param program to get address from
	 * @param addr to be normallized/aligned for disassembly
	 * 
	 * @return the normalized/aligned address for disassembly
	 */
	public static Address getNormalizedDisassemblyAddress(Program program, Address addr) {
		if (!addr.isMemoryAddress()) {
			return addr;
		}
		Register lowBitCodeMode = program.getRegister(LOW_BIT_CODE_MODE_REGISTER_NAME);
		if (lowBitCodeMode == null) {
			return addr;
		}
		if ((addr.getOffset() & 1) == 0) {
			return addr;
		}
		return addr.getNewAddress(addr.getOffset() & ~0x1);
	}

	/**
	 * 
	 * @return RegisterValue setting for the context register to disassemble correctly at the given address
	 *         or null, if no setting is needed.
	 */
	public static RegisterValue getTargetContextRegisterValueForDisassembly(Program program,
			Address addr) {
		Register lowBitCodeMode = program.getRegister(LOW_BIT_CODE_MODE_REGISTER_NAME);
		if (lowBitCodeMode == null) {
			return null;
		}
		long offset = addr.getOffset();
		if ((offset & 1) == 1) {
			return new RegisterValue(lowBitCodeMode, BigInteger.ONE);
		}
		return null;
	}

	/**
	 * @return true if program has uses the low bit of an address to change Instruction Set mode
	 */
	public static boolean hasLowBitCodeModeInAddrValues(Program program) {
		Register lowBitCodeMode = program.getRegister(LOW_BIT_CODE_MODE_REGISTER_NAME);
		return (lowBitCodeMode != null);
	}

	/**
	 * If this processor uses the low bit of an address to change to a new Instruction Set mode
	 *   Check the low bit and change the instruction state at the address.
	 *   
	 * @param program
	 * @param addr the raw address
	 * @return the correct address to disassemble at if it needs to be aligned
	 */
	public static Address setTargeContextForDisassembly(Program program, Address addr) {
		Register lowBitCodeMode = program.getRegister(LOW_BIT_CODE_MODE_REGISTER_NAME);
		if (lowBitCodeMode == null) {
			return addr;
		}
		long offset = addr.getOffset();
		if ((offset & 1) == 1) {
			addr = addr.getNewAddress(addr.getOffset() & ~0x1);
			try {
				program.getProgramContext().setValue(lowBitCodeMode, addr, addr, BigInteger.ONE);
			}
			catch (ContextChangeException e) {
				// shouldn't happen
			}
		}
		return addr;
	}

	/**
	 * In order to check a location to see if it disassembles from an address reference, the
	 * address is checked for low-bit code switch behavior.  If it does switch, the context
	 * is changed.
	 * 
	 * @param procContext context to change
	 * @param addr destination address that will be disassembled (possible pseudo disassembled)
	 * @return the correct disassembly location if the address needed to be adjusted.
	 */

	public Address setTargeContextForDisassembly(PseudoDisassemblerContext procContext,
			Address addr) {
		Register lowBitCodeMode = program.getRegister(LOW_BIT_CODE_MODE_REGISTER_NAME);
		if (lowBitCodeMode == null) {
			return addr;
		}
		long offset = addr.getOffset();
		if ((offset & 1) == 1) {
			addr = addr.getNewAddress(addr.getOffset() & ~0x1);
			procContext.setValue(lowBitCodeMode, addr, BigInteger.ONE);
		}
		return addr.getNewAddress(addr.getOffset() & ~0x1);
	}

}
