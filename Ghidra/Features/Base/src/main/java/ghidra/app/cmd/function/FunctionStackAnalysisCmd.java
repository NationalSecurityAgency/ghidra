/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.Stack;

/**
 * Command for analyzing the Stack; the command is run in the background.
 * NOTE: referenced thunk-functions should be created prior to this command
 */
public class FunctionStackAnalysisCmd extends BackgroundCommand {
	private AddressSet entryPoints = new AddressSet();
	private Program program;
	private boolean forceProcessing = false;
	private boolean dontCreateNewVariables = false;
	private boolean doParams = false;
	private boolean doLocals = false;

	static String DEFAULT_FUNCTION_COMMENT = " FUNCTION";

	/**
	 * Constructs a new command for analyzing the Stack.
	 * @param entries and address set indicating the entry points of functions that have 
	 * stacks to be analyzed.
	 * @param forceProcessing flag to force processing of stack references even if the stack
	 *           has already been defined.
	 */
	public FunctionStackAnalysisCmd(AddressSetView entries, boolean forceProcessing) {
		this(entries, true, true, forceProcessing);
	}

	/**
	 * Constructs a new command for analyzing the Stack.
	 * @param entry the entry point of the function that contains the stack to
	 *           be analyzed.
	 * @param forceProcessing flag to force processing of stack references even if the stack
	 *           has already been defined.
	 */
	public FunctionStackAnalysisCmd(Address entry, boolean forceProcessing) {
		this(new AddressSet(entry, entry), true, true, forceProcessing);
	}

	public FunctionStackAnalysisCmd(AddressSetView entries, boolean doParameterAnalysis,
			boolean doLocalAnalysis, boolean forceProcessing) {
		super("Create Function Stack Variables", true, true, false);
		entryPoints.add(entries);
		this.forceProcessing = forceProcessing;
		doParams = doParameterAnalysis;
		doLocals = doLocalAnalysis;
	}

	/**
	 * 
	 * @see ghidra.framework.cmd.BackgroundCommand#applyTo(ghidra.framework.model.DomainObject, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		program = (Program) obj;

		int count = 0;
		monitor.initialize(entryPoints.getNumAddresses());
		AddressIterator iter = entryPoints.getAddresses(true);
		while (iter.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}

			Address origEntry = iter.next();
			monitor.setProgress(++count);

			Symbol funName = program.getSymbolTable().getPrimarySymbol(origEntry);
			String msg = (funName == null ? "" + origEntry : funName.getName());
			monitor.setMessage("Stack " + msg);

			try {
				if (!analyzeFunction(origEntry, monitor)) {
					setStatusMsg("Function overlaps an existing function body");
				}
			}
			catch (CancelledException e) {
				//
			}
		}
		if (monitor.isCancelled()) {
			setStatusMsg("Function Stack analysis cancelled");
			return false;
		}
		return true;
	}

	/**
	 * Analyze a function to build a stack frame based on stack references.
	 * 
	 * @param entry   The address of the entry point for the new function
	 * @param monitor the task monitor that is checked to see if the command has
	 * been cancelled.
	 * @throws CancelledException if the user canceled this command
	 */
	private boolean analyzeFunction(Address entry, TaskMonitor monitor) throws CancelledException {
		Listing listing = program.getListing();
		Function f = listing.getFunctionAt(entry);
		if (f == null || f.isThunk()) {
			return false;
		}
//		int depthChange = 0;

		// Perform depth search of all functions reached by this function.
		// Any function that has not had its stack analyzed is added to a list.
		// This way, the lowest level functions frames are looked at to try and determine their
		//  stack purge, before this functions stack is analyzed.
		Stack<Function> stack = new Stack<Function>(); // functions needing to be looked at for valid frames
		ArrayList<Function> funcList = new ArrayList<Function>(); // list of functions needing stack frames created
		stack.push(f);
		while (!stack.isEmpty()) {
			monitor.checkCanceled();
			Function func = stack.pop();
			if (func.isThunk()) {
				continue;
			}
			// if the purge for the function is unknown, it has not been looked at yet.
			//  we need to add it to the list to analyze its stack frame.
			int numVars = func.getVariables(VariableFilter.STACK_VARIABLE_FILTER).length;
			if (numVars == 0) {
				// This function needs its stack looked at.
				funcList.add(0, func);
			}
			else if (forceProcessing && func.getEntryPoint().equals(entry)) {
				// This function needs its stack looked at.
				funcList.add(0, func);
			}
		}

		// Process all the functions identified as needing stack analysis.
		// The list will have the lowest level functions analyzed first.
//		int default_purge = program.getCompilerSpec().getCallStackMod();
//		int default_stackshift = program.getCompilerSpec().getCallStackShift();
		while (!funcList.isEmpty()) {
			monitor.checkCanceled();
			Function func = funcList.remove(0);
			SourceType oldSignatureSource = func.getSignatureSource();

			monitor.setMessage("Stack " + func.getName());
			createStackPointerVariables(func, monitor);

			if (oldSignatureSource != func.getSignatureSource()) {
				// preserve signature source 
				func.setSignatureSource(oldSignatureSource);
			}

//			if (depthChange > 0xfffff || depthChange < -0xfffff) {
//				depthChange = Function.INVALID_STACK_DEPTH_CHANGE;
//			}
//
//			// Stack purge is defined as the number of extra bytes that are popped
//			//   off of the stack beyond the normal calling conventions.
//			//   the default_callstackmod includes the normal call stack shift,
//			//   so subtract it out.
//			if (default_purge != PrototypeModel.UNKNOWN_EXTRAPOP) {
//				depthChange = default_purge - default_stackshift;
//			}
			// func.setStackPurgeSize(depthChange);
		}
		return true;
	}

	/**
	 * Create locals and parameters based on references involving purely the stack pointer.
	 * Pushes, Pops, and arithmetic manipulation of the stack pointer must be tracked.
	 * 
	 * @param func - function to analyze stack pointer references
	 */
	private int createStackPointerVariables(Function func, TaskMonitor monitor)
			throws CancelledException {
		// check if this is a jump thunk through a function pointer
		if (func.isThunk()) {
			return func.getStackPurgeSize();
		}

		// if it already has stack variables
//		if (func.getStackFrame().getStackVariables().length > 0 && !forceProcessing) {
//			return func.getStackPurgeSize();
//		}

		// TODO: Taking this out  could cause problems with importing from XML.
		//    The XML would have the stack defined, and all references.
		//    If we go and re-analyze, it could overwrite or change the references.
//		dontCreateNewVariables = (func.getStackFrame().getStackVariables().length > 0 && !forceProcessing);

		CallDepthChangeInfo info = new CallDepthChangeInfo(func, monitor);

		InstructionIterator iter = program.getListing().getInstructions(func.getBody(), true);
		while (iter.hasNext()) {
			monitor.checkCanceled();
			Instruction instr = iter.next();

			// process any stack pointer references
			int numOps = instr.getNumOperands();
			for (int opIndex = 0; opIndex < numOps; opIndex++) {
				int offset = info.getStackOffset(instr, opIndex);
				if (offset == Function.INVALID_STACK_DEPTH_CHANGE) {
					continue;
				}

				defineFuncVariable(func, instr, opIndex, offset);
			}
		}

		return info.getStackPurge();
	}

//	/**
//	 * Checks the indicated function in the program to determine if it is a jump thunk
//	 * through a function pointer.
//	 * @param func the function to check
//	 * @param monitor status monitor for indicating progress and allowing cancel.
//	 * @returntrue if check if this is a jump thunk through a function pointer
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

	private void defineFuncVariable(Function func, Instruction instr, int opIndex, int stackOffset) {

		ReferenceManager refMgr = program.getReferenceManager();

		int refSize = getRefSize(instr, opIndex);

		try {
			// check if operand already has a stack reference created
			Reference ref = instr.getPrimaryReference(opIndex);
			if (ref instanceof StackReference) {
				Variable var = refMgr.getReferencedVariable(ref);
				if (var == null) {
					stackOffset = ((StackReference) ref).getStackOffset(); // TODO: is this necessary?
					createVar(func, 0, stackOffset, refSize);
				}
				return;
			}

			RefType refType = RefTypeFactory.getDefaultStackRefType(instr, opIndex);

			int unitSize = program.getAddressFactory().getStackSpace().getAddressableUnitSize();
			stackOffset *= unitSize; // factor in stack unit size
			refMgr.addStackReference(instr.getMinAddress(), opIndex, stackOffset, refType,
				SourceType.ANALYSIS);
			createVar(func, 0, stackOffset, refSize);
		}
		catch (InvalidInputException e) {
			Msg.debug(this, "Failed to create variable (instruction at " + instr.getMinAddress() +
				", stack-offset=" + stackOffset + ", size=" + refSize + "): " + e.getMessage());
		}
	}

	/**
	 * Look at the result register to try and figure out stack access size.
	 * 
	 * @param instr instruction being analyzed
	 * @param opIndex operand that has a stack reference.
	 * 
	 * @return size of value referenced on the stack
	 */
	private int getRefSize(Instruction instr, int opIndex) {
		if (instr.getProgram().getLanguage().supportsPcode()) {
			PcodeOp[] pcode = instr.getPcode();
			for (int i = pcode.length - 1; i >= 0; i--) {
				if (pcode[i].getOpcode() == PcodeOp.LOAD) {
					Varnode out = pcode[i].getOutput();
					return out.getSize();
				}
				if (pcode[i].getOpcode() == PcodeOp.STORE) {
					Varnode src = pcode[i].getInput(2);
					return src.getSize();
				}
			}
		}
		else {
			Object results[] = instr.getResultObjects();
			if (results.length == 1 && results[0] instanceof Register) {
				return ((Register) results[0]).getMinimumByteSize();
			}
		}
		return 0;
	}

	private Variable createVar(Function func, int frameOffset, int offset, int refSize)
			throws InvalidInputException {
		if (dontCreateNewVariables) {
			return null;
		}
		StackFrame frame = func.getStackFrame();
		int frameLoc = offset + frameOffset;
		Variable var = frame.getVariableContaining(frameLoc);
		if (var == null) {
			try {
				if (!doLocals && frameLoc <= 0) {
					return null;
				}
				if (!doParams && frameLoc > 0) {
					return null;
				}
				// only create variables at locations where a variable doesn't exist
				var =
					frame.createVariable(null, frameLoc, Undefined.getUndefinedDataType(refSize),
						SourceType.ANALYSIS);
			}
			catch (DuplicateNameException e) {
				throw new AssertException(e);
			}
		}
		else if (var.getStackOffset() == frameLoc && var.getDataType().getLength() < refSize) {
			// don't get rid of existing variables, just change their size bigger
			DataType dt = var.getDataType();
			if (dt instanceof Undefined || dt == DefaultDataType.dataType) {
				var.setDataType(Undefined.getUndefinedDataType(refSize), SourceType.ANALYSIS);
			}
		}
		return var;
	}

}
