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

import java.util.*;

import ghidra.program.model.address.*;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.util.*;
import ghidra.program.util.*;
import ghidra.program.util.SymbolicPropogator.Value;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * CallDepthChangeInfo.java
 * 
 * Date: Feb 6, 2003
 * 
 */
/**
 * 
 * Given a function in a program or the start of a function, record information
 * about the change to a stack pointer from a subroutine call. The routine
 * getCallChange() can be called with the address of a call instruction. If the
 * stack could be tracked, the call instruction will return the change in the
 * stack pointer that would result from a call to the function.
 * 
 * The computation is based on a set of equations that are generated and solved.
 * Each equation represents the stack change for a given basic flow block or
 * call instruction within the function.
 * 
 * 
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
	 * @param func function to examine
	 */
	public CallDepthChangeInfo(Function func) {
		this.program = func.getProgram();
		frameReg = program.getCompilerSpec().getStackPointer();
		try {
			initialize(func, func.getBody(), frameReg, TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			throw new RuntimeException("Unexpected Exception", e);
		}
	}

	/**
	 * Construct a new CallDepthChangeInfo object.
	 * @param func
	 *            function to examine
	 * @param monitor
	 *            monitor used to cancel the operation
	 * 
	 * @throws CancelledException
	 *             if the operation was canceled
	 */
	public CallDepthChangeInfo(Function func, TaskMonitor monitor) throws CancelledException {
		this(func, func.getBody(), null, monitor);
	}

	/**
	 * Construct a new CallDepthChangeInfo object.
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
		initialize(function, restrictSet, frameReg, monitor);
	}

	/**
	 * Construct a new CallDepthChangeInfo object.
	 * 
	 * @param program  program containing the function to examime
	 * @param addr     address within the function to examine
	 * @param restrictSet set of addresses to restrict flow flowing to.
	 * @param frameReg register that is to have it's depth(value) change tracked
	 * @param monitor  monitor used to cancel the operation
	 * @throws CancelledException
	 *             if the operation was canceled
	 */
	public CallDepthChangeInfo(Program program, Address addr, AddressSetView restrictSet,
			Register frameReg, TaskMonitor monitor) throws CancelledException {
		Function func = program.getFunctionManager().getFunctionContaining(addr);
		Register stackReg = program.getCompilerSpec().getStackPointer();
		initialize(func, restrictSet, stackReg, monitor);
	}

	/**
	 * initialize codeblocks and call locations.
	 * 
	 * @param addressSetView
	 * @param monitor
	 * @throws CancelledException
	 */
	private void initialize(Function func, AddressSetView restrictSet, Register reg,
			TaskMonitor monitor) throws CancelledException {
		changeMap = new DefaultIntPropertyMap("change");
		depthMap = new DefaultIntPropertyMap("depth");
		trans = new VarnodeTranslator(program);

		symEval = new SymbolicPropogator(program);
		symEval.setParamRefCheck(false);
		symEval.setReturnRefCheck(false);
		symEval.setStoredRefCheck(false);

		// initialize stack pointer
		frameReg = reg;

		followFlows(func, restrictSet, monitor);

//		try {
//			CodeBlockIterator cbIter = new SimpleBlockModel(program).getCodeBlocksContaining(body, monitor);
//			while (cbIter.hasNext()) {
//				CodeBlock block = cbIter.next();
//				codeBlocks.add(block);
//				if (block.getFlowType().isCall()) {
//					Instruction instr = program.getListing()
//							.getInstructionContaining(block.getMaxAddress());
//					if (instr != null) {
//						callLocs.add(instr.getMinAddress());
//					}
//				}
//			}
//			computeDepthChange(monitor);
//		} catch (UncomputableStackDepthException e) {
//		}
	}

	public int getCallChange(Address addr) {
		int i = Function.UNKNOWN_STACK_DEPTH_CHANGE;
		try {
			i = changeMap.getInt(addr);
		}
		catch (NoValueException exc) {
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
	 * @param instr
	 *            instruction to analyze
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
	 * Get the default/assumed stack depth change for this language
	 * 
	 * @param depth stack depth to return if the default is unknown for the language
	 * @return
	 */
	private int getDefaultStackDepthChange(int depth) {
		PrototypeModel defaultModel = program.getCompilerSpec().getDefaultCallingConvention();
		int callStackMod = defaultModel.getExtrapop();
		int callStackShift = defaultModel.getStackshift();
		if (callStackMod != PrototypeModel.UNKNOWN_EXTRAPOP && callStackShift >= 0) {
			return callStackShift - callStackMod;
		}
		return depth;
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
	 * Do a better job of tracking the stack by attempting to follow the data
	 * flow of the stack pointer as it moves in and out of other variables.
	 * 
	 * @param program1 -
	 *            program containing the function to analyze
	 * @param func -
	 *            function to analyze stack pointer references
	 */
	public int smoothDepth(Program program1, Function func, TaskMonitor monitor) {
		if (trans.supportsPcode()) {
			return smoothPcodeDepth(program1, func, monitor);
		}

		int returnStackDepth = Function.INVALID_STACK_DEPTH_CHANGE;

		// terminal points
		ArrayList<Address> terminalPoints = new ArrayList<Address>(); // list of points that are
		// terminal to this function

		Stack<Object> st = new Stack<Object>();
		st.push(func.getEntryPoint());
		st.push(new Integer(0));
		st.push(Boolean.TRUE);
		ProcessorContextImpl procContext = new ProcessorContextImpl(program.getLanguage());

		AddressSet undone = new AddressSet(func.getBody());
		AddressSet badStackSet = new AddressSet(undone);
		while (!st.empty()) {
			Boolean stackOK = (Boolean) st.pop();
			int stackPointerDepth = ((Integer) st.pop()).intValue();
			Address loc = (Address) st.pop();

			if (!undone.contains(loc)) {
				continue;
			}
			// remove instruction from address set
			undone.deleteRange(loc, loc);

			Instruction instr = program1.getListing().getInstructionAt(loc);
			if (instr == null) {
				continue;
			}

			if (stackOK == Boolean.TRUE) {
				this.setDepth(instr, stackPointerDepth);
			}

			// check for a frame setup
//			if (checkFrameSetup(instr, stackPointerDepth, procContext)) {
//				isFrameBased = true;
//			}

			// process any stack pointer manipulations
			int instrChangeDepth =
				this.getInstructionStackDepthChange(instr, procContext, stackPointerDepth);
			if (instrChangeDepth != Function.UNKNOWN_STACK_DEPTH_CHANGE &&
				instrChangeDepth != Function.INVALID_STACK_DEPTH_CHANGE) {
				stackPointerDepth += instrChangeDepth;
			}
			else {
				stackOK = Boolean.FALSE;
			}

			// if stack is OK at this instruction, remove from the bad stack set
			if (stackOK == Boolean.TRUE) {
				badStackSet.deleteRange(instr.getMinAddress(), instr.getMaxAddress());
			}

			// push any control flows that are still in address set
			FlowType flow = instr.getFlowType();
			if (!flow.isCall()) {
				Address[] flows = instr.getFlows();
				for (Address flow2 : flows) {
					st.push(flow2);
					st.push(new Integer(stackPointerDepth));
					st.push(stackOK);
				}
			}
			else {
				// see if the info structure has the call depth
				int callStackChange = getCallChange(instr.getMinAddress());
				if (callStackChange == Function.UNKNOWN_STACK_DEPTH_CHANGE ||
					callStackChange == Function.INVALID_STACK_DEPTH_CHANGE) {
					stackOK = Boolean.FALSE;
				}
				else if (stackOK == Boolean.TRUE) {
					stackPointerDepth += callStackChange;
				}
			}
			Address fallThru = instr.getFallThrough();
			if (fallThru != null) {
				st.push(fallThru);
				st.push(new Integer(stackPointerDepth));
				st.push(stackOK);
			}
			if (flow.isTerminal()) {
				int instrPurge =
					getInstructionStackDepthChange(instr, procContext, returnStackDepth);
				if (stackOK.booleanValue()) {
					returnStackDepth = stackPointerDepth - instrPurge;
				}
				else {
					returnStackDepth = -instrPurge;
					terminalPoints.add(instr.getMinAddress());
				}
//				if (instr.getScalar(0) != null) {
//					returnStackDepth = (int) -instr.getScalar(0)
//							.getSignedValue();
//				} else {
//					if (stackOK == Boolean.TRUE) {
//						returnStackDepth = stackPointerDepth;
//					} else {
//						terminalPoints.add(instr.getMinAddress());
//					}
//				}
			}
		}

		//		if (processTerminal) {
		//			backPropogateStackDepth(program, func, badStackSet, this,
		// procContext, terminalPoints, monitor);
		//		}

		return returnStackDepth;
	}

	/**
	 * Follow the flows of the subroutine, accumulating information about the
	 * stack pointer and any other register the stack pointer is assigned to.
	 * 
	 * @param func
	 *            function to analyze
	 * @param monitor
	 *            monitor to provide feedback and cancel
	 * @throws CancelledException 
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

		int purge = (short) program.getCompilerSpec().getDefaultCallingConvention().getExtrapop();
		final boolean possiblePurge = purge == -1 || purge > 3200 || purge < -3200;

		// follow all flows building up context
		// use context to fill out addresses on certain instructions 
		final ContextEvaluator eval = new ContextEvaluatorAdapter() {

			@Override
			public boolean evaluateContextBefore(VarnodeContext context, Instruction instr) {
				Varnode stackRegVarnode = context.getRegisterVarnode(frameReg);
				Varnode stackValue = null;
				try {
					stackValue = context.getValue(stackRegVarnode, true, this);
				}
				catch (NotFoundException e) {
				}
				//Varnode stackValue = context.getRegisterVarnodeValue(stackReg, instr.getMinAddress(), true);
				if (stackValue != null && context.isSymbol(stackValue) &&
					stackValue.getAddress().getAddressSpace().getName().equals(
						stackReg.getName())) {
					int stackPointerDepth = (int) stackValue.getOffset();
					setDepth(instr, stackPointerDepth);
				}
				return false;
			}

			@Override
			public boolean evaluateContext(VarnodeContext context, Instruction instr) {
				FlowType ftype = instr.getFlowType();
				if (possiblePurge && ftype.isTerminal()) {
					if (instr.getMnemonicString().compareToIgnoreCase("ret") == 0) {
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
				AddressSpace space = address.getAddressSpace();
				if (space.getName().startsWith("track_") ||
					space.getName().equals(stackReg.getName())) {
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

//	/**
//	 * Checks the indicated function in the program to determine if it is a jump thunk
//	 * through a function pointer.
//	 * @param func the function to check
//	 * @param monitor status monitor for indicating progress and allowing cancel.
//	 * @return true if check if this is a jump thunk through a function pointer
//	 */
//	private boolean checkThunk(Function func, TaskMonitor monitor) {
//		Instruction instr = program.getListing().getInstructionAt(func.getEntryPoint());
//		if (instr == null) {
//			return false;
//		}
//
//		FlowType type = instr.getFlowType();
//		if (!type.isJump() || !type.isComputed()) {
//			return false;
//		}
//
//		Address flows[] = instr.getFlows();
//		if (flows != null && flows.length > 0) {
//			return false;
//		}
//
//		Reference refs[] = instr.getReferencesFrom();
//		if (refs == null || refs.length == 0) {
//			return false;
//		}
//
//		Function indirFunc = program.getFunctionManager().getFunctionAt(refs[0].getToAddress());
//		FunctionSignature fsig = null;
//		int purge = Function.UNKNOWN_STACK_DEPTH_CHANGE;
//		if (indirFunc != null) {
//			fsig = indirFunc.getSignature();
//			purge = indirFunc.getStackPurgeSize();
//		}
//		else {
//			Data data = program.getListing().getDataAt(refs[0].getToAddress());
//			if (data != null && data.isPointer() &&
//				data.getDataType() instanceof FunctionDefinition) {
//				FunctionDefinition fdef = (FunctionDefinition) data.getDataType();
//				fsig = fdef;
//			}
//		}
//		if (fsig == null) {
//			return false;
//		}
//		func.setStackPurgeSize(purge);
//		return true;
//	}

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

	/**
	 * @param addr the address to get the register depth at.
	 * @param reg the register to get the depth of.
	 * @return the depth of the register at the address.
	 */
	public int getRegDepth(Address addr, Register reg) {
		// OK lets CHEAT...
		// Since single instructions will give the wrong value,
		// get the value as of the end of the last instruction that fell into this one!
		Instruction instr = this.program.getListing().getInstructionAt(addr);
		if (instr != null && instr.getLength() < 2) {
			Address fallAddr = instr.getFallFrom();
			if (fallAddr != null) {
				addr = fallAddr;
			}
			// just in case this instruction falling from is bigger than 1 byte
			instr = program.getListing().getInstructionAt(addr);
			addr = instr.getMaxAddress();
		}
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
	 * @param addr the address of the register value to get the representation of.
	 * @param reg the register to get the representation of.
	 * @return the string representation of the register value.
	 */
	public String getRegValueRepresentation(Address addr, Register reg) {
		return symEval.getRegisterValueRepresentation(addr, reg);
	}

	/**
	 * Create locals and parameters based on references involving purely the
	 * stack pointer. Pushes, Pops, and arithmetic manipulation of the stack
	 * pointer must be tracked.
	 * 
	 * @param program1 -
	 *            program containing the function to analyze
	 * @param func -
	 *            function to analyze stack pointer references
	 */
	private int smoothPcodeDepth(Program program1, Function func, TaskMonitor monitor) {

		int returnStackDepth = Function.INVALID_STACK_DEPTH_CHANGE;

		ArrayList<Address> terminalPoints = new ArrayList<Address>(); // list of points that are
		// terminal to this function

		Stack<Object> st = new Stack<Object>();
		st.push(func.getEntryPoint());
		st.push(Integer.valueOf(0));
		st.push(Boolean.TRUE);
		ProcessorContextImpl procContext = new ProcessorContextImpl(program.getLanguage());

		AddressSet undone = new AddressSet(func.getBody());
		AddressSet badStackSet = new AddressSet(undone);
		while (!st.empty()) {
			Boolean stackOK = (Boolean) st.pop();
			int stackPointerDepth = ((Integer) st.pop()).intValue();
			Address loc = (Address) st.pop();

			if (!undone.contains(loc)) {
				continue;
			}
			// remove instruction from address set
			undone.deleteRange(loc, loc);

			Instruction instr = program1.getListing().getInstructionAt(loc);
			if (instr == null) {
				continue;
			}

			if (stackOK == Boolean.TRUE) {
				this.setDepth(instr, stackPointerDepth);
			}

			// check for a frame setup
//			if (checkFrameSetup(instr, stackPointerDepth, procContext)) {
//				isFrameBased = true;
//			}

			// process any stack pointer manipulations
			int instrChangeDepth =
				this.getInstructionStackDepthChange(instr, procContext, stackPointerDepth);
			if (instrChangeDepth != Function.UNKNOWN_STACK_DEPTH_CHANGE) {
				stackPointerDepth += instrChangeDepth;
			}
			else {
				stackOK = Boolean.FALSE;
			}

			// if stack is OK at this instruction, remove from the bad stack set
			if (stackOK == Boolean.TRUE) {
				badStackSet.deleteRange(instr.getMinAddress(), instr.getMaxAddress());
			}

			// push any control flows that are still in address set
			FlowType flow = instr.getFlowType();
			if (!flow.isCall()) {
				Address[] flows = instr.getFlows();
				for (Address flow2 : flows) {
					st.push(flow2);
					st.push(Integer.valueOf(stackPointerDepth));
					st.push(stackOK);
				}
			}
			else {
				// see if the info structure has the call depth
				int callStackChange = getCallPurge(instr);
				if (callStackChange == Function.UNKNOWN_STACK_DEPTH_CHANGE) {
					callStackChange = this.getCallChange(instr.getMinAddress());
				}
				if (callStackChange == Function.UNKNOWN_STACK_DEPTH_CHANGE) {
					stackOK = Boolean.FALSE;
				}
				else if (stackOK == Boolean.TRUE) {
					stackPointerDepth += callStackChange;
				}
			}
			Address fallThru = instr.getFallThrough();
			if (fallThru != null) {
				st.push(fallThru);
				st.push(new Integer(stackPointerDepth));
				st.push(stackOK);
			}
			if (flow.isTerminal()) {
				if (stackOK == Boolean.TRUE) {
					returnStackDepth = stackPointerDepth;
				}
				else {
					if (instr.getScalar(0) != null) {
						returnStackDepth = (int) instr.getScalar(0).getSignedValue();
					}
					else {
						terminalPoints.add(instr.getMinAddress());
					}
				}
			}
		}

		//		if (processTerminal) {
		//			backPropogateStackDepth(program, func, badStackSet, this,
		// procContext, terminalPoints, monitor);
		//		}

		return returnStackDepth;
	}

	/**
	 * @param instr
	 */
	private int getCallPurge(Instruction instr) {

		// see if there is an override at this address
		Integer override = overrideMap.get(instr.getMinAddress());
		if (override != null) {
			return override.intValue();
		}

		FlowType fType = instr.getFlowType();
		Address[] flows;
		if (fType.isComputed()) {
			Reference refs[] = instr.getReferencesFrom();
			flows = new Address[refs.length];
			for (int ri = 0; ri < refs.length; ri++) {
				Data data = program.getListing().getDataAt(refs[ri].getToAddress());
				if (data != null && data.isPointer()) {
					Reference pointerRef = data.getPrimaryReference(0);
					if (pointerRef != null) {
						flows[ri] = pointerRef.getToAddress();
					}
				}
			}
		}
		else {
			flows = instr.getFlows();
		}

		// try to find a call destination that the stack frame is known
		for (Address flow : flows) {
			if (flow == null) {
				continue;
			}
			Function func = program.getListing().getFunctionAt(flow);
			if (func != null) {
				int purge = func.getStackPurgeSize();
				if (func.isStackPurgeSizeValid() && purge != Function.UNKNOWN_STACK_DEPTH_CHANGE &&
					purge != Function.INVALID_STACK_DEPTH_CHANGE) {
					return purge;
				}
			}
		}

		return getDefaultStackDepthChange(Function.UNKNOWN_STACK_DEPTH_CHANGE);
	}

}
