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

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.state.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Command for analyzing the Stack; the command is run in the background.
 */
public class FunctionResultStateStackAnalysisCmd extends BackgroundCommand {
	private AddressSet entryPoints = new AddressSet();
	private boolean forceProcessing = false;
	private boolean dontCreateNewVariables = false;

	/**
	 * Constructs a new command for analyzing the Stack.
	 * @param entries and address set indicating the entry points of functions that have 
	 * stacks to be analyzed.
	 * @param forceProcessing flag to force processing of stack references even if the stack
	 *           has already been defined.
	 */
	public FunctionResultStateStackAnalysisCmd(AddressSetView entries, boolean forceProcessing) {
		super("Create Function Stack Variables", true, true, false);
		entryPoints.add(entries);
		this.forceProcessing = forceProcessing;
	}

	/**
	 * Constructs a new command for analyzing the Stack.
	 * @param entry the entry point of the function that contains the stack to
	 *           be analyzed.
	 * @param forceProcessing flag to force processing of stack references even if the stack
	 *           has already been defined.
	 */
	public FunctionResultStateStackAnalysisCmd(Address entry, boolean forceProcessing) {
		this(new AddressSet(entry, entry), forceProcessing);
	}

	/**
	 * 
	 * @see ghidra.framework.cmd.BackgroundCommand#applyTo(ghidra.framework.model.DomainObject, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		Program program = (Program) obj;

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
				if (!analyzeFunction(program, origEntry, monitor)) {
					setStatusMsg("Function overlaps an existing function body");
				}
			}
			catch (CancelledException e) {
				// don't care
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
	private boolean analyzeFunction(Program program, Address entry, TaskMonitor monitor)
			throws CancelledException {
		Listing listing = program.getListing();
		Function f = listing.getFunctionAt(entry);
		if (f == null) {
			return false;
		}
		int depthChange = 0;

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
			// if the purge for the function is unknown, it has not been looked at yet.
			//  we need to add it to the list to analyze its stack frame.
			if (func.getStackPurgeSize() == Function.UNKNOWN_STACK_DEPTH_CHANGE) {
				// look at any call references out of this function and put them on
				//   the stack to be looked at
				AddressIterator iter =
					program.getReferenceManager().getReferenceSourceIterator(func.getBody(), true);
				while (iter.hasNext()) {
					monitor.checkCanceled();
					Address fromAddr = iter.next();
					Reference refs[] =
						program.getReferenceManager().getFlowReferencesFrom(fromAddr);
					for (Reference ref : refs) {
						if (ref.getReferenceType().isCall()) {
							Address calledAddr = ref.getToAddress();
							Function destFunc = program.getListing().getFunctionAt(calledAddr);
							if (destFunc != null && !destFunc.isInline()) {
								stack.push(destFunc);
							}
						}
					}
				}

				// This function needs its stack looked at.
				//   Set its stack purge to invalid, so won't be added to list again if called recursively.
				func.setStackPurgeSize(Function.INVALID_STACK_DEPTH_CHANGE);
				funcList.add(0, func);
			}
			else if (forceProcessing && func.getEntryPoint().equals(entry)) {
				// This function needs its stack looked at.
				//   Set its stack purge to invalid, so won't be added to list again if called recursively.
				func.setStackPurgeSize(Function.INVALID_STACK_DEPTH_CHANGE);
				funcList.add(0, func);
			}
		}

		// Process all the functions identified as needing stack analysis.
		// The list will have the lowest level functions analyzed first.
		PrototypeModel defaultModel = program.getCompilerSpec().getDefaultCallingConvention();
		int default_extraPop = defaultModel.getExtrapop();
		int default_stackshift = defaultModel.getStackshift();

		while (!funcList.isEmpty()) {
			monitor.checkCanceled();
			Function func = funcList.remove(0);
			monitor.setMessage("Stack " + func.getName());

			depthChange = createStackPointerVariables(func, monitor);

			PrototypeModel callingConvention = func.getCallingConvention();

			int stackShift = default_stackshift;
			int extraPop = default_extraPop;
			if (callingConvention != null) {
				stackShift = callingConvention.getStackshift();
				extraPop = callingConvention.getExtrapop();
			}

			if (depthChange > 0xfffff || depthChange < -0xfffff) {
				depthChange = Function.INVALID_STACK_DEPTH_CHANGE;
			}

			// Stack purge is defined as the number of extra bytes that are popped
			//   off of the stack beyond the normal calling conventions.
			//   the default_callstackmod includes the normal call stack shift,
			//   so subtract it out.
			if (extraPop != PrototypeModel.UNKNOWN_EXTRAPOP) {
				depthChange = extraPop - stackShift;
			}
			else if (depthChange != Function.INVALID_STACK_DEPTH_CHANGE) {
				depthChange -= stackShift;
			}
			func.setStackPurgeSize(depthChange);
		}
		return true;
	}

	/**
	 * Create locals and parameters based on references involving purely the stack pointer.
	 * Pushes, Pops, and arithmetic manipulation of the stack pointer must be tracked.
	 * 
	 * @param func - function to analyze stack pointer references
	 */
	private int createStackPointerVariables(final Function func, TaskMonitor monitor)
			throws CancelledException {

		final Program program = func.getProgram();
		final Listing listing = program.getListing();
		final AddressFactory addrFactory = program.getAddressFactory();
		final ReferenceManager refMgr = program.getReferenceManager();

		// set the stack pointer to be tracked
		Register stackReg = program.getCompilerSpec().getStackPointer();
		if (stackReg == null) {
			return Function.UNKNOWN_STACK_DEPTH_CHANGE;
		}

		ResultsState results = new ResultsState(func.getEntryPoint(), new FunctionAnalyzer() {

			@Override
			public void dataReference(PcodeOp op, int instrOpIndex, Varnode storageVarnode,
					RefType refType, TaskMonitor monitor1) throws CancelledException {
				// TODO Auto-generated method stub
			}

			@Override
			public void indirectDataReference(PcodeOp op, int instrOpIndex, Varnode offsetVarnode,
					int size, int storageSpaceID, RefType refType, TaskMonitor monitor1)
					throws CancelledException {
				// TODO Auto-generated method stub

			}

			@Override
			public boolean resolvedFlow(PcodeOp op, int instrOpIndex, Address destAddr,
					ContextState currentState, ResultsState results1, TaskMonitor monitor1)
					throws CancelledException {
				// TODO Auto-generated method stub
				return false;
			}

			@Override
			public void stackReference(PcodeOp op, int instrOpIndex, int stackOffset, int size,
					int storageSpaceID, RefType refType, TaskMonitor monitor1)
					throws CancelledException {

				if (instrOpIndex < 0) {
					return;
				}
				Address fromAddr = op.getSeqnum().getTarget();
				Instruction instr = listing.getInstructionAt(fromAddr);
				if (instr == null) {
					return;
				}
				Address stackAddr = addrFactory.getStackSpace().getAddress(stackOffset);
				RefType rt = refType;
				Reference ref = refMgr.getReference(fromAddr, stackAddr, instrOpIndex);
				if (ref != null) {
					RefType existingRefType = ref.getReferenceType();
					if (existingRefType == rt) {
						return;
					}
					if (existingRefType == RefType.READ || existingRefType == RefType.WRITE) {
						rt = RefType.READ_WRITE;
					}
				}
				else if (refMgr.getReferencesFrom(fromAddr, instrOpIndex).length != 0) {
					// don't overwrite existing reference
					return;
				}
				if (!dontCreateNewVariables) {
					StackFrame stackFrame = func.getStackFrame();
					Variable existingVar = stackFrame.getVariableContaining(stackOffset);
					DataType type =
						size > 0 ? Undefined.getUndefinedDataType(size) : DataType.DEFAULT;
					if (existingVar != null && existingVar.getDataType() == DataType.DEFAULT) {
						func.removeVariable(existingVar);
						existingVar = null;
					}
					if (existingVar == null) {
						try {
							stackFrame.createVariable(null, stackOffset, type, SourceType.ANALYSIS);
// TODO: How can I tell when these stack variables are used as a pointer ?
						}
						catch (DuplicateNameException e) {
							throw new AssertException(); // unexpected
						}
						catch (InvalidInputException e) {
							Msg.error(this,
								"Failed to create stack variable at " + func.getEntryPoint() +
									", ref-from=" + fromAddr + ", stack-offset=" + stackOffset +
									", size=" + size + ": " + e.getMessage());
						}
					}
				}
				refMgr.addStackReference(fromAddr, instrOpIndex, stackOffset, rt,
					SourceType.ANALYSIS);
			}

			@Override
			public void stackReference(PcodeOp op, int instrOpIndex,
					VarnodeOperation computedStackOffset, int size, int storageSpaceID,
					RefType refType, TaskMonitor monitor1) throws CancelledException {
				//
			}

			@Override
			public List<Address> unresolvedIndirectFlow(PcodeOp op, int instrOpIndex,
					Varnode destination, ContextState currentState, ResultsState results1,
					TaskMonitor monitor1) throws CancelledException {
				return null;
			}

		}, program, true, monitor);

		if (results.getPreservedRegisters().contains(stackReg)) {
			return 0;
		}

		Set<Varnode> spReturnValues = results.getReturnValues(results.getStackPointerVarnode());
		if (!spReturnValues.isEmpty()) {
			for (SequenceNumber seq : results.getReturnAddresses()) {
				ContextState returnState = results.getContextStates(seq).next();
				Varnode varnode =
					returnState.get(results.getStackPointerVarnode(),
						TaskMonitorAdapter.DUMMY_MONITOR);
				Varnode zero =
					new Varnode(addrFactory.getConstantSpace().getAddress(0),
						stackReg.getMinimumByteSize());
				varnode =
					replaceInputVarnodes(varnode, results.getStackPointerVarnode(), zero, 4,
						monitor);
				if (varnode == null) {
					continue;
				}
				varnode = simplifyVarnode(varnode, addrFactory);
				if (varnode.isConstant()) {
					long offset = ResultsState.getSignedOffset(varnode);
					return (int) offset;
				}
			}
		}

		return Function.UNKNOWN_STACK_DEPTH_CHANGE;
	}

	private Varnode simplifyVarnode(Varnode vn, AddressFactory addrFactory)
			throws CancelledException {
		if (!(vn instanceof VarnodeOperation)) {
			return vn;
		}
		VarnodeOperation vop = (VarnodeOperation) vn;
		return ResultsState.simplify(vop.getPCodeOp(), vop.getInputValues(), addrFactory,
			TaskMonitorAdapter.DUMMY_MONITOR);
	}

	/**
	 * Replace all occurrences of vn within exp with value
	 * @param exp expression within which vn should be replaced with value
	 * @param vn a simple varnode to be replaced (e.g., register), must not be a VarnodeOperation
	 * @param value replacement value (e.g., constant varnode), must not be a VarnodeOperation
	 * @param maxComplexity maximum expression complexity (i.e., depth) allowed for exp
	 * @param monitor
	 * @return updated expression or null if maxComplexity exceeded
	 * @throws CancelledException
	 */
	private Varnode replaceInputVarnodes(Varnode exp, Varnode vn, Varnode value, int maxComplexity,
			TaskMonitor monitor) throws CancelledException {
		if (!(exp instanceof VarnodeOperation)) {
			return exp.equals(vn) ? value : exp;
		}
		VarnodeOperation vop = (VarnodeOperation) exp;
		Varnode[] inputValues = vop.getInputValues();
		for (int i = 0; i < inputValues.length; i++) {
			monitor.checkCanceled();
			if (vn.equals(inputValues[i])) {
				inputValues[i] = value;
			}
			else if (maxComplexity == 0) {
				return null; // maxComplexity exceeded
			}
			else {
				inputValues[i] =
					replaceInputVarnodes(inputValues[i], vn, value, maxComplexity - 1, monitor);
				if (inputValues[i] == null) {
					return null; // maxComplexity exceeded
				}
			}
		}
		return new VarnodeOperation(vop.getPCodeOp(), inputValues);
	}

}
