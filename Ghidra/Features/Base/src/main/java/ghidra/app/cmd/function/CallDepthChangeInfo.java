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
package ghidra.app.cmd.function;

import java.util.ArrayList;
import java.util.HashMap;

import ghidra.program.model.address.*;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.lang.ProcessorContext;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.util.*;
import ghidra.program.util.*;
import ghidra.program.util.SymbolicPropogator.Value;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Given a function in a program or the start of a function, record information
 * about the change to a stack pointer from a subroutine call. The routine
 * getCallChange() can be called with the address of a call instruction. If the
 * stack could be tracked, the call instruction will return the change in the
 * stack pointer that would result from a call to the function.
 * 
 * The computation is based on a set of equations that are generated and solved.
 * Each equation represents the stack change for a given basic flow block or
 * call instruction within the function.
 */
public class CallDepthChangeInfo {

	Program program;

	ArrayList<CodeBlock> codeBlocks = new ArrayList<CodeBlock>();

	ArrayList<Address> callLocs = new ArrayList<Address>();

	IntPropertyMap changeMap;

	IntPropertyMap depthMap;

	private HashMap<Address, Integer> overrideMap = new HashMap<Address, Integer>();

	private VarnodeTranslator trans;

	private Register stackReg = null;
	private Register frameReg = null;

	SymbolicPropogator symEval = null;

	private int stackPurge = Function.UNKNOWN_STACK_DEPTH_CHANGE;

	//private static final int INVALID_DEPTH_CHANGE = 16777216; // 2^24

	private static final String STACK_DEPTH_CHANGE_NAME = "StackDepthChange";

	/**
	 * Construct a new CallDepthChangeInfo object.
	 * Using this constructor will NOT track the stack depth at the start/end of each instruction.
	 * 
	 * @param func function to examine
	 */
	public CallDepthChangeInfo(Function func) {
		this(func, false);
	}
	
	/**
	 * Construct a new CallDepthChangeInfo object.
	 * Allows calls to getRegDepth() and getRegValueRepresentation()
	 * 
	 * @param func function to examine
	 * @param storeDepthAtEachInstuction true to track stack at start/end of each instruction. allowing
	 * a call to 
	 */
	public CallDepthChangeInfo(Function func, boolean storeDepthAtEachInstuction) {
		this.program = func.getProgram();
		frameReg = program.getCompilerSpec().getStackPointer();
		try {
			initialize(func, func.getBody(), frameReg, storeDepthAtEachInstuction, TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			throw new RuntimeException("Unexpected Exception", e);
		}
	}

	/**
	 * Construct a new CallDepthChangeInfo object.
	 * @param func function to examine
	 * @param monitor used to cancel the operation
	 * 
	 * @throws CancelledException
	 *             if the operation was canceled
	 */
	public CallDepthChangeInfo(Function func, TaskMonitor monitor) throws CancelledException {
		this(func, func.getBody(), null, monitor);
	}

	/**
	 * Construct a new CallDepthChangeInfo object.
	 * Using this constructor will track the stack depth at the start/end of each instruction.
	 * 
	 * @param function function to examine
	 * @param restrictSet set of addresses to restrict flow flowing to.
	 * @param frameReg register that is to have it's depth(value) change tracked
	 * @param monitor monitor used to cancel the operation
	 * 
	 * @throws CancelledException
	 *             if the operation was canceled
	 */
	public CallDepthChangeInfo(Function function, AddressSetView restrictSet, Register frameReg,
			TaskMonitor monitor) throws CancelledException {
		this.program = function.getProgram();
		if (frameReg == null) {
			frameReg = program.getCompilerSpec().getStackPointer();
		}
		// track start/end values at each instruction
		initialize(function, restrictSet, frameReg, true, monitor);
	}


	private void initialize(Function func, AddressSetView restrictSet, Register reg,
			boolean storeDepthAtEachInstuction, TaskMonitor monitor) throws CancelledException {
		changeMap = new DefaultIntPropertyMap("change");
		depthMap = new DefaultIntPropertyMap("depth");
		trans = new VarnodeTranslator(program);

		symEval = new SymbolicPropogator(program,storeDepthAtEachInstuction);
		symEval.setParamRefCheck(false);
		symEval.setReturnRefCheck(false);
		symEval.setStoredRefCheck(false);

		// initialize stack pointer
		frameReg = reg;

		followFlows(func, restrictSet, monitor);

	}

	public int getCallChange(Address addr) {
		int i = Function.UNKNOWN_STACK_DEPTH_CHANGE;
		try {
			i = changeMap.getInt(addr);
		}
		catch (NoValueException exc) {
			// ignore
		}

		return i;
	}

	void setDepth(Instruction instr, int depth) {
		depthMap.add(instr.getMinAddress(), depth);
	}

	void setDepth(Address addr, int depth) {
		depthMap.add(addr, depth);
	}

	public int getDepth(Address addr) {
		int depth = Function.UNKNOWN_STACK_DEPTH_CHANGE;
		try {
			depth = depthMap.getInt(addr);
		}
		catch (NoValueException exc) {
			// ignore
		}
		return depth;
	}

	/**
	 * Inspect the instruction and return how it affects the stack depth. If the
	 * depth cannot be determined, then return that the stack depth change is
	 * unknown.
	 * 
	 * @param instr
	 *            instruction to analyze
	 * 
	 * @return int change to stack depth if it can be determined,
	 *         Function.UNKNOWN_STACK_DEPTH_CHANGE otherwise.
	 */
	public int getInstructionStackDepthChange(Instruction instr) {
		return getInstructionStackDepthChange(instr, null, 0);
	}

	/**
	 * Inspect the instruction and return how it affects the stack depth. If the
	 * depth cannot be determined, then return that the stack depth change is
	 * unknown.
	 * 
	 * @param instr instruction to analyze
	 * @param procContext 
	 * @param currentStackDepth 
	 * 
	 * @return int change to stack depth if it can be determined,
	 *         Function.UNKNOWN_STACK_DEPTH_CHANGE otherwise.
	 */
	int getInstructionStackDepthChange(Instruction instr, ProcessorContext procContext,
			int currentStackDepth) {
		// see if there is an override at this address
		Integer override = overrideMap.get(instr.getMinAddress());
		if (override != null) {
			return override.intValue();
		}

		int depthChange = 0;

		if (!trans.supportsPcode()) {
			return Function.UNKNOWN_STACK_DEPTH_CHANGE;
		}

		int possibleDepthChange = 0;

		// TODO: This is hack, a call instruction can modify the stack while
		//       in progress, it matters what happens upon return...
		//       what we care about here is what is the result after execution on the
		// stack pointer
		FlowType flowType = instr.getFlowType();
		if (flowType.isCall()) {
			//			depthChange = getCallPurge(instr);
			//			if (depthChange == Function.UNKNOWN_STACK_DEPTH_CHANGE)
			//				return 0;
			//			return depthChange;
			return 0;
		}

		PcodeOp[] pcode = instr.getPcode();
		Varnode outVarNode = null;
		for (PcodeOp op : pcode) {
			Varnode input0 = op.getInput(0);
			Varnode input1 = op.getInput(1);
			Varnode output = op.getOutput();
			switch (op.getOpcode()) {
				case PcodeOp.INT_ADD:
					if (isStackPointer(input0)) {
						possibleDepthChange = (int) input1.getOffset();
						outVarNode = output;
					}
					else if (input0.equals(outVarNode)) {
						possibleDepthChange += (int) input1.getOffset();
						outVarNode = output;
					}
					else if (isStackPointer(input1)) {
						possibleDepthChange = (int) input0.getOffset();
						outVarNode = output;
					}
					else if (input1.equals(outVarNode)) {
						possibleDepthChange += (int) input0.getOffset();
						outVarNode = output;
					}
					break;
				case PcodeOp.INT_SUB:
					if (isStackPointer(input0)) {
						possibleDepthChange = (int) -input1.getOffset();
						outVarNode = output;
					}
					else if (input0.equals(outVarNode)) {
						possibleDepthChange += (int) -input1.getOffset();
						outVarNode = output;
					}
					else if (isStackPointer(input1)) {
						possibleDepthChange = (int) -input0.getOffset();
						outVarNode = output;
					}
					else if (input1.equals(outVarNode)) {
						possibleDepthChange += (int) -input0.getOffset();
						outVarNode = output;
					}
					break;
				case PcodeOp.INT_AND: // Assume this is a stack alignment and do the and
					if (isStackPointer(input0)) {
						if (currentStackDepth != Function.UNKNOWN_STACK_DEPTH_CHANGE) {
							possibleDepthChange =
								(int) (currentStackDepth & input1.getOffset()) - currentStackDepth;
						}
						outVarNode = output;
					}
					else if (input0.equals(outVarNode)) {
						possibleDepthChange = 0;
						outVarNode = output;
					}
					else if (isStackPointer(input1)) {
						if (currentStackDepth != Function.UNKNOWN_STACK_DEPTH_CHANGE) {
							possibleDepthChange =
								(int) (currentStackDepth & input0.getOffset()) - currentStackDepth;
						}
						outVarNode = output;
					}
					else if (input1.equals(outVarNode)) {
						possibleDepthChange = 0;
						outVarNode = output;
					}
					break;
			}

			if (!isStackPointer(output)) {
				//				possibleDepthChange = 0;
				continue;
			}

			switch (op.getOpcode()) {
				case PcodeOp.INT_ADD:
				case PcodeOp.INT_SUB:
				case PcodeOp.INT_AND:
					depthChange += possibleDepthChange;
					break;
				case PcodeOp.STORE:
					break;
				case PcodeOp.INT_OR:
					// if the op is an OR, then this could be a copy
					Varnode orInput1 = op.getInput(0);
					Varnode orInput2 = op.getInput(1);
					if (!orInput1.equals(orInput2)) {
						break;
					}
					Msg.debug(this, "INT_OR" + instr.getMinAddress());
				case PcodeOp.COPY:
					Varnode input = op.getInput(0);
					// if we know the processor context, find the value
					if (procContext != null && input.isRegister()) {
						Register reg = null;
						reg = trans.getRegister(input);
						if (procContext.hasValue(reg)) {
							long value = procContext.getValue(reg, true).longValue();
							depthChange = (int) (value - currentStackDepth);
							currentStackDepth += depthChange;
							continue;
						}
					}
					if (!input.equals(outVarNode)) {
						return Function.UNKNOWN_STACK_DEPTH_CHANGE;
					}
					depthChange = possibleDepthChange;
					break;
				default:
					return Function.UNKNOWN_STACK_DEPTH_CHANGE;
			}
		}

		// TODO: Modify return by normal stack shift....
		if (flowType.isTerminal()) {
			depthChange -= program.getCompilerSpec().getDefaultCallingConvention().getStackshift();
		}

		// if the current stack depth is still bad, don't return a depth change.
		if (currentStackDepth == Function.UNKNOWN_STACK_DEPTH_CHANGE ||
			currentStackDepth == Function.INVALID_STACK_DEPTH_CHANGE) {
			return Function.UNKNOWN_STACK_DEPTH_CHANGE;
		}
		return depthChange;
	}

	boolean isStackPointer(Varnode output) {
		if (output == null) {
			return false;
		}

		Register reg = null;
		reg = trans.getRegister(output);

		// is this register the stack pointer
		if (reg == stackReg) {
			return true;
		}

		return false;
	}

	/**
	 * Gets the stack depth change value that has been set at the indicated address.
	 * 
	 * @param program the program to be checked
	 * @param address the program address
	 * @return the stack depth change value or null if value has not been set
	 */
	public static Integer getStackDepthChange(Program program, Address address) {
		PropertyMapManager pmm = program.getUsrPropertyManager();
		IntPropertyMap ipm = pmm.getIntPropertyMap(STACK_DEPTH_CHANGE_NAME);
		if (ipm == null || !ipm.hasProperty(address)) {
			return null;
		}

		try {
			return ipm.getInt(address);
		}
		catch (NoValueException e) {
			throw new AssertException("Already checked that it has a property");
		}
	}

	/**
	 * Sets a new value for the stack depth change at the indicated address. 
	 * 
	 * @param program the program where the value will be set
	 * @param address the program address
	 * @param stackDepthChange the new stack depth change value
	 * 
	 * @throws DuplicateNameException if the property name for stack depth changes conflicted 
	 * with another property tha has the same name.
	 */
	public static void setStackDepthChange(Program program, Address address, int stackDepthChange)
			throws DuplicateNameException {

		PropertyMapManager pmm = program.getUsrPropertyManager();
		IntPropertyMap ipm = pmm.getIntPropertyMap(STACK_DEPTH_CHANGE_NAME);
		if (ipm == null) {
			ipm = pmm.createIntPropertyMap(STACK_DEPTH_CHANGE_NAME);
		}
		ipm.add(address, stackDepthChange);
	}

	/**
	 * Removes the value for the stack depth change at the indicated address. 
	 * 
	 * @param program the program where the value will be removed
	 * @param address the program address
	 * 
	 * @return true if a stack depth change existed at the indicated at the address and it was removed.
	 */
	public static boolean removeStackDepthChange(Program program, Address address) {

		PropertyMapManager pmm = program.getUsrPropertyManager();
		IntPropertyMap ipm = pmm.getIntPropertyMap(STACK_DEPTH_CHANGE_NAME);
		if (ipm != null) {
			return ipm.remove(address);
		}
		return false;
	}

	/**
	 * Gets an iterator indicating all the addresses that have a stack depth change value specified
	 * within a program's indicated address set.
	 * 
	 * @param program the program to be checked
	 * @param addressSet the set of addresses to check for a stack depth change value
	 * @return the address iterator indicating where stack depth change values have been set
	 */
	public static AddressIterator getStackDepthChanges(Program program, AddressSetView addressSet) {
		PropertyMapManager pmm = program.getUsrPropertyManager();
		IntPropertyMap ipm = pmm.getIntPropertyMap(STACK_DEPTH_CHANGE_NAME);
		if (ipm == null) {
			return new EmptyAddressIterator();
		}
		return ipm.getPropertyIterator(addressSet);
	}

	/**
	 * Follow the flows of the subroutine, accumulating information about the
	 * stack pointer and any other register the stack pointer is assigned to.
	 * 
	 * @param func
	 *            function to analyze
	 * @param monitor
	 *            monitor to provide feedback and cancel
	 * @throws CancelledException if monitor canceled
	 */
	private void followFlows(Function func, AddressSetView restrictSet, TaskMonitor monitor)
			throws CancelledException {
		if (frameReg == null) {
			return;
		}

		// check if this is thunk function
		if (func.isThunk()) {
			return;
		}

		// if extrapop is has an unknown purge, check for a purge on return instructions
		int purge = (short) program.getCompilerSpec().getDefaultCallingConvention().getExtrapop();
		final boolean possiblePurge = purge == -1 || purge > 3200 || purge < -3200;

		// follow all flows building up context
		// use context to fill out addresses on certain instructions 
		final ContextEvaluator eval = new ContextEvaluatorAdapter() {

			@Override
			public boolean evaluateContextBefore(VarnodeContext context, Instruction instr) {
				Varnode stackRegVarnode = context.getRegisterVarnode(frameReg);
				Varnode stackValue = context.getValue(stackRegVarnode, true, this);

				if (stackValue != null && context.isSymbol(stackValue) &&
					context.isStackSymbolicSpace(stackValue)) {
					long stackPointerDepth = stackValue.getOffset();
					int size = stackValue.getSize();
					stackPointerDepth = (stackPointerDepth << 8 * (8 - size)) >> 8 * (8 - size);
					setDepth(instr, (int) stackPointerDepth);
				}

				return false;
			}

			@Override
			public boolean evaluateContext(VarnodeContext context, Instruction instr) {
				FlowType ftype = instr.getFlowType();
				if (possiblePurge && ftype.isTerminal()) {
					String mnemonicStr = instr.getMnemonicString().toLowerCase();
					if ("ret".equals(mnemonicStr) || "retf".equals(mnemonicStr)) {
						// x86 has a scalar operand to purge value from the stack
						int tempPurge = 0;
						Scalar scalar = instr.getScalar(0);
						if (scalar != null) {
							tempPurge = (int) scalar.getSignedValue();
							stackPurge = tempPurge;
						}
						else {
							stackPurge = 0;
						}
					}
				}

				return false;
			}

			@Override
			public boolean evaluateSymbolicReference(VarnodeContext context, Instruction instr,
					Address address) {
				if (instr.getFlowType().isTerminal()) {
					return false;
				}
				checkForStackOffset(context, instr, address, -1);
				return false;
			}

			private void checkForStackOffset(VarnodeContext context, Instruction instr,
					Address address, int opIndex) {
				String spaceName = address.getAddressSpace().getName();
				if (spaceName.startsWith("track_") || context.isStackSpaceName(spaceName)) {
					// TODO: what to do on a Symbolic reference
				}
			}
		};

		// set the stack pointer to be tracked
		stackReg = program.getLanguage().getDefaultCompilerSpec().getStackPointer();
		if (stackReg == null) {
			return;
		}

		symEval.setRegister(func.getEntryPoint(), stackReg);

		setDepth(func.getEntryPoint(), 0);

		symEval.flowConstants(func.getEntryPoint(), restrictSet, eval, true, monitor);

		return;
	}

	public int getStackPurge() {
		return stackPurge;
	}

	public int getStackOffset(Instruction cu, int opIndex) {
		int offset = 0;
		int offsetReg = 0;
		Register offReg = null;
		Scalar s = null;
		Object obj[] = cu.getOpObjects(opIndex);
		for (int i = 0; obj != null && i < obj.length; i++) {
			if (obj[i] instanceof Scalar) {
				Scalar newsc = (Scalar) obj[i];
				if (s != null) {
					return Function.INVALID_STACK_DEPTH_CHANGE;
				}
				// choose the biggest value....
				if (Math.abs(offset) < newsc.getUnsignedValue()) {
					offset = (int) newsc.getSignedValue();
					s = newsc;
				}
			}

			// check if any register is the stack pointer
			// if it is, need to compute stack depth offset for function
			//
			if (obj[i] instanceof Register) {
				Register reg = (Register) obj[i];
				int depth = getRegDepth(cu.getMinAddress(), reg);
				if (depth != Function.INVALID_STACK_DEPTH_CHANGE &&
					depth != Function.UNKNOWN_STACK_DEPTH_CHANGE) {
					offReg = reg;
					offsetReg = depth;
				}
			}
		}

		// must have a register that has the stack depth in it and a scalar
		if (offReg == null || s == null) {
			return Function.INVALID_STACK_DEPTH_CHANGE;
		}
		offset += offsetReg;

		return offset;
	}

	/**
	 * @param addr the address to get the stack pointer depth at.
	 * @return the stack pointer depth at the address.
	 */
	public int getSPDepth(Address addr) {
		return getRegDepth(addr, stackReg);
	}

	/** Get the stack register depth at address.
	 *  To have a valid value, the class must be constructed to storeDepthAtEachInstuction
	 *  
	 * @param addr the address to get the register depth at.
	 * @param reg the register to get the depth of.
	 * @return the depth of the register at the address.
	 */
	public int getRegDepth(Address addr, Register reg) {
		Value rValue = symEval.getRegisterValue(addr, reg);
		if (rValue == null) {
			return Function.INVALID_STACK_DEPTH_CHANGE;
		}
		Register relativeReg = rValue.getRelativeRegister();
		if (!reg.equals(stackReg)) {
			if (relativeReg == null || !relativeReg.equals(stackReg)) {
				return Function.INVALID_STACK_DEPTH_CHANGE;
			}
		}
		else if (relativeReg != null && !relativeReg.equals(stackReg)) {
			return Function.INVALID_STACK_DEPTH_CHANGE;
		}
		return (int) rValue.getValue();
	}

	/**
	 * Get the stack register value as a printable string.  This can be an equation
	 * of register+value.
	 * 
	 *  To have a valid value, the class must be constructed to storeDepthAtEachInstuction
	 *  
	 * @param addr the address of the register value to get the representation of.
	 * @param reg the register to get the representation of.
	 * @return the string representation of the register value.
	 */
	public String getRegValueRepresentation(Address addr, Register reg) {
		return symEval.getRegisterValueRepresentation(addr, reg);
	}
}
