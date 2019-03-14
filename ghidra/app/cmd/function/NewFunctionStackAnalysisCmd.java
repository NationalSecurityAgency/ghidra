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

import java.math.BigInteger;
import java.util.*;

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Command for analyzing the Stack; the command is run in the background.
 * NOTE: referenced thunk-functions should be created prior to this command
 */
public class NewFunctionStackAnalysisCmd extends BackgroundCommand {

	private static final int MAX_PARAM_OFFSET = 2048;        // max size of param reference space
	private static final int MAX_LOCAL_OFFSET = -(64 * 1024);  // max size of local reference space

	private AddressSet entryPoints = new AddressSet();
	private Program program;
	private boolean forceProcessing = false;
	private boolean dontCreateNewVariables = false;
	private boolean doParams = false;
	private boolean doLocals = false;
	private Register stackReg;
	private int purge = 0;

	static String DEFAULT_FUNCTION_COMMENT = " FUNCTION";

	/**
	 * Constructs a new command for analyzing the Stack.
	 * @param entries and address set indicating the entry points of functions that have 
	 * stacks to be analyzed.
	 * @param forceProcessing flag to force processing of stack references even if the stack
	 *           has already been defined.
	 */
	public NewFunctionStackAnalysisCmd(AddressSetView entries, boolean forceProcessing) {
		this(entries, true, true, forceProcessing);
	}

	/**
	 * Constructs a new command for analyzing the Stack.
	 * @param entry the entry point of the function that contains the stack to
	 *           be analyzed.
	 * @param forceProcessing flag to force processing of stack references even if the stack
	 *           has already been defined.
	 */
	public NewFunctionStackAnalysisCmd(Address entry, boolean forceProcessing) {
		this(new AddressSet(entry, entry), true, true, forceProcessing);
	}

	public NewFunctionStackAnalysisCmd(AddressSetView entries, boolean doParameterAnalysis,
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
		long numAddresses = entryPoints.getNumAddresses();
		int numRanges = entryPoints.getNumAddressRanges();
		// is this a bigger set, or individual function locations
		if (numRanges != numAddresses) {
			numAddresses = program.getFunctionManager().getFunctionCount();
		}

		monitor.initialize(numAddresses);
		FunctionIterator functions = program.getFunctionManager().getFunctions(entryPoints, true);
		while (functions.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}

			Function func = functions.next();
			monitor.setProgress(++count);

			monitor.setMessage("Stack " + func.getName());

			try {
				if (!analyzeFunction(func, monitor)) {
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
	private boolean analyzeFunction(Function f, TaskMonitor monitor) throws CancelledException {
		Address entry = f.getEntryPoint();

		// Perform depth search of all functions reached by this function.
		// Any function that has not had its stack analyzed is added to a list.
		// This way, the lowest level functions frames are looked at to try and determine their
		//  stack purge, before this functions stack is analyzed.
		Stack<Function> stack = new Stack<>(); // functions needing to be looked at for valid frames
		ArrayList<Function> funcList = new ArrayList<>(); // list of functions needing stack frames created
		stack.push(f);
		while (!stack.isEmpty()) {
			monitor.checkCanceled();
			Function func = stack.pop();
			if (func.isThunk()) {
				continue;
			}

			if (forceProcessing && func.getEntryPoint().equals(entry)) {
				// This function needs its stack looked at.
				funcList.add(0, func);
			}

			// If the function has no references to stack or local variables, compute them
			// Later this should change to stack locked.
			Variable[] variables = func.getVariables(VariableFilter.STACK_VARIABLE_FILTER);
			boolean hasReferences = false;
			for (int i = 0; i < variables.length; i++) {
				Reference[] referencesTo =
					program.getReferenceManager().getReferencesTo(variables[i]);
				if (referencesTo.length != 0) {
					hasReferences = true;
					break;
				}
			}
			if (variables.length == 0 || !hasReferences) {
				// TODO: SHOULD HAVE OPTION JUST TO CREATE REFERENCES
				// TODO: SHOULD HAVE OPTION JUST TO CREATE PARAMETERS
				// TODO: SHOULD HAVE OPTION JUST TO CREATE LOCALS
				funcList.add(0, func);
			}
		}

		// Process all the functions identified as needing stack analysis.
		// The list will have the lowest level functions analyzed first.
		while (!funcList.isEmpty()) {
			monitor.checkCanceled();
			Function func = funcList.remove(0);
			SourceType oldSignatureSource = func.getSignatureSource();

			monitor.setMessage("Stack " + func.getName());
			createStackPointerVariables(func, monitor);

			// Now check that there are not missing stack variables
			//addMissingStackVariables(func);

			if (oldSignatureSource != func.getSignatureSource()) {
				// preserve signature source 
				func.setSignatureSource(oldSignatureSource);
			}
		}
		return true;
	}

	private boolean isProtectedVariable(Variable var) {
		return !var.isStackVariable() || !Undefined.isUndefined(var.getDataType()) ||
			var.getSource() == SourceType.IMPORTED || var.getSource() == SourceType.USER_DEFINED ||
			var.isCompoundVariable();
	}

	private void addFunctionStackVariablesToSortedList(Function func,
			List<Variable> sortedVariables) {

		for (Variable stackVar : func.getVariables(VariableFilter.STACK_VARIABLE_FILTER)) {
			Variable varImpl;
			if (isProtectedVariable(stackVar)) {
				continue;
			}
			try {
				if (stackVar instanceof Parameter) {
					varImpl = new ParameterImpl(null, stackVar.getDataType(),
						stackVar.getStackOffset(), program);
				}
				else {
					varImpl = new LocalVariableImpl(null, stackVar.getDataType(),
						stackVar.getStackOffset(), program);
				}
			}
			catch (InvalidInputException e) {
				continue; // skip variable
			}
			addVariableToSortedList(varImpl, sortedVariables);
		}
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
//		if (checkThunk(func, monitor)) {
//			return func.getStackPurgeSize();
//		}

		stackReg = program.getCompilerSpec().getStackPointer();

		final List<Variable> sortedVariables = new ArrayList<>();

		// Add stack variables with undefined types to map to simplify merging
		addFunctionStackVariablesToSortedList(func, sortedVariables);

		SymbolicPropogator symEval = new SymbolicPropogator(program);
		symEval.setParamRefCheck(false);
		symEval.setReturnRefCheck(false);
		symEval.setStoredRefCheck(false);

		// follow all flows building up context
		// use context to fill out addresses on certain instructions 
		ContextEvaluator eval = new ContextEvaluatorAdapter() {

			@Override
			public boolean evaluateContext(VarnodeContext context, Instruction instr) {
				if (instr.getFlowType().isTerminal()) {
					RegisterValue value = context.getRegisterValue(stackReg, instr.getMaxAddress());
					if (value != null) {
						BigInteger signedValue = value.getSignedValue();
						if (signedValue != null) {
							purge = signedValue.intValue();
						}
					}
				}
				if (instr.getMnemonicString().equals("LEA")) {
					Register destReg = instr.getRegister(0);
					if (destReg != null) {
						Varnode value = context.getRegisterVarnodeValue(destReg);
						if (value != null) {
							checkForStackOffset(context, instr, value.getAddress(), 0);
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
				String spaceName = space.getName();
				if (spaceName.startsWith("track_") || spaceName.equals(stackReg.getName())) {
					if (opIndex == -1) {
						opIndex = getStackOpIndex(context, instr, (int) address.getOffset());
						// if didn't get the right opIndex, and has a delayslot, check for good stack ref
						if (opIndex == -1 && instr.getPrototype().hasDelaySlots()) {
							instr = instr.getNext();
							if (instr == null) {
								return;
							}
							opIndex = getStackOpIndex(context, instr, (int) address.getOffset());
						}
					}
					if (opIndex == -1) {
						return;
					}
					// TODO: Dirty Dirty nasty Hack for POP EBP problem, only very few cases of this!
					if (instr.getMnemonicString().equals("POP")) {
						Register reg = instr.getRegister(opIndex);
						if (reg != null && reg.getName().contains("BP")) {
							return;
						}
					}
					long extendedOffset =
						extendOffset(address.getOffset(), stackReg.getBitLength());
					Function func =
						program.getFunctionManager().getFunctionContaining(instr.getMinAddress());
					defineFuncVariable(func, instr, opIndex, (int) extendedOffset, sortedVariables);
				}
			}

			private long extendOffset(long offset, int bitLength) {
				// Properly extend the stack offset for -/+
				return (offset << (64 - bitLength)) >> (64 - bitLength);
			}
		};

		// set the stack pointer to be tracked
		symEval.setRegister(func.getEntryPoint(), stackReg);

		symEval.flowConstants(func.getEntryPoint(), func.getBody(), eval, true, monitor);

		if (sortedVariables.size() != 0) {

			List<Variable> protectedFuncVars = new ArrayList<>();
			for (Variable v : func.getAllVariables()) {
				if (isProtectedVariable(v)) {
					protectedFuncVars.add(v);
				}
			}
			VariableStorageConflicts conflicts =
				new VariableStorageConflicts(sortedVariables, protectedFuncVars, false, monitor);

			SourceType signatureSource = func.getSignatureSource();
			if (signatureSource != SourceType.IMPORTED &&
				signatureSource != SourceType.USER_DEFINED) {
				addStackParameters(func, sortedVariables, conflicts, monitor);
			}

			addStackLocalVariables(func, sortedVariables, conflicts, monitor);

		}
		return purge;
	}

	private void addStackLocalVariables(Function func, List<Variable> sortedVariables,
			VariableStorageConflicts conflicts, TaskMonitor monitor) {

		if (func.isThunk()) {
			return;
		}

		Variable[] unprotectedLocals =
			func.getVariables(variable -> (variable instanceof LocalVariable) &&
				variable.isStackVariable() && !isProtectedVariable(variable));

		for (Variable var : sortedVariables) {
			if ((var instanceof Parameter) || conflicts.isConflicted(var, null)) {
				continue;
			}
			for (Variable old : unprotectedLocals) {
				if (old.getVariableStorage().intersects(var.getVariableStorage())) {
					func.removeVariable(old);
				}
			}
			try {
				// skip variable if conflict with non-default variable occurs
				VariableUtilities.checkVariableConflict(func, null, var.getVariableStorage(),
					false);
				func.addLocalVariable(var, SourceType.DEFAULT);
			}
			catch (DuplicateNameException | InvalidInputException e) {
				// ignore - unexpected
			}
		}
	}

	private void addStackParameters(Function func, List<Variable> sortedVariables,
			VariableStorageConflicts conflicts, TaskMonitor monitor) {

		Parameter[] oldParamList = func.getParameters();
		List<Variable> newParamList = new ArrayList<>();

		boolean growsNegative = func.getStackFrame().growsNegative();

		int sortedVarCnt = sortedVariables.size();

		int index = 0;
		for (index = 0; index < sortedVarCnt; ++index) {
			Variable var = sortedVariables.get(index);
			if (growsNegative && (var instanceof Parameter)) {
				break;
			}
			else if (!growsNegative && !(var instanceof Parameter)) {
				--index;
				break;
			}
		}

		if (index < 0 || index == sortedVarCnt) {
			// no parameters found
			return;
		}

		PrototypeModel callingConvention = func.getCallingConvention();
		if (callingConvention == null) {
			callingConvention = program.getCompilerSpec().getDefaultCallingConvention();
		}

		if (callingConvention == null) {
			return;
		}

		boolean hasStackParams = (callingConvention.getStackParameterAlignment() >= 0);

		int nextCopyParamIndex = 0;
		if (growsNegative) {
			for (int i = index; i < sortedVarCnt; ++i) {
				Variable v = sortedVariables.get(i);
				if (conflicts.isConflicted(v, null)) {
					continue;
				}
				nextCopyParamIndex = addMissingParameters(v, nextCopyParamIndex, oldParamList,
					newParamList, callingConvention, hasStackParams);
				if (nextCopyParamIndex < 0) {
					return;
				}
				newParamList.add(v);
			}
		}
		else {
			for (int i = index; i >= 0; --i) {
				Variable v = sortedVariables.get(i);
				if (conflicts.isConflicted(v, null)) {
					continue;
				}
				nextCopyParamIndex = addMissingParameters(v, nextCopyParamIndex, oldParamList,
					newParamList, callingConvention, hasStackParams);
				if (nextCopyParamIndex < 0) {
					return;
				}
				newParamList.add(v);
			}
		}

		while (nextCopyParamIndex < oldParamList.length) {
			newParamList.add(oldParamList[nextCopyParamIndex++]);
		}

		try {
			func.replaceParameters(newParamList,
				func.hasCustomVariableStorage() ? FunctionUpdateType.CUSTOM_STORAGE
						: FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
				true, func.getSignatureSource());
			if (!VariableUtilities.storageMatches(newParamList, func.getParameters())) {
				func.replaceParameters(newParamList, FunctionUpdateType.CUSTOM_STORAGE, true,
					func.getSignatureSource());
			}
		}
		catch (DuplicateNameException e) {
			// ignore - unexpected
		}
		catch (InvalidInputException e) {
			// ignore - unexpected
		}

	}

	private static final int MAX_PARAM_FILLIN_COUNT = 10;

	private int addMissingParameters(Variable stackVar, int nextCopyParamIndex,
			Parameter[] oldParamList, List<Variable> newParamList, PrototypeModel callingConvention,
			boolean hasStackParams) {
		if (!(stackVar instanceof Parameter)) {
			throw new IllegalArgumentException();
		}

		if (callingConvention.getStackParameterOffset() == null) {
			return -1; // don't add parameters
		}

		int offset = stackVar.getStackOffset();

		// copy old params which come before stackVar offset
		while (nextCopyParamIndex < oldParamList.length) {
			Parameter p = oldParamList[nextCopyParamIndex];
			if (!p.isStackVariable()) {
				newParamList.add(p);
			}
			else {
				int stackOffset = p.getStackOffset();
				if ((offset > 0 && offset > stackOffset) || (offset < 0 && offset < stackOffset)) {
					newParamList.add(p);
				}
				else {
					if (offset == stackOffset) {
						// assume replacement
						++nextCopyParamIndex;
					}
					break;
				}
			}
			++nextCopyParamIndex;
		}

		// fill-in missing params - don't bother if we already have 
		// too many or no stack param block defined
		int nextOrdinal = newParamList.size();
		if ((!hasStackParams) || nextOrdinal >= MAX_PARAM_FILLIN_COUNT) {
			return nextCopyParamIndex;
		}

		VariableStorage argLocation;
		try {
			Parameter[] params = new Parameter[nextOrdinal];
			argLocation = callingConvention.getArgLocation(nextOrdinal,
				newParamList.toArray(params), DataType.DEFAULT, program);
			while (!argLocation.intersects(stackVar.getVariableStorage()) &&
				nextOrdinal < MAX_PARAM_FILLIN_COUNT) {
				// TODO: it feels bad to add a bunch of register variables
				Parameter p = new ParameterImpl(null, DataType.DEFAULT, argLocation, program);
				newParamList.add(p);
				++nextOrdinal;
				params = new Parameter[nextOrdinal];
				argLocation = callingConvention.getArgLocation(nextOrdinal,
					newParamList.toArray(params), DataType.DEFAULT, program);
			}
		}
		catch (InvalidInputException e) {
			throw new RuntimeException(e); // unexpected
		}

		if (!argLocation.isStackStorage()) {
			return nextCopyParamIndex;
		}

		return nextCopyParamIndex;
	}

	private int getStackOpIndex(VarnodeContext context, Instruction cu, int offset) {
		int opIndex = 0;
//		int opLocation = -1;
		for (; opIndex < cu.getNumOperands(); opIndex++) {
			Object obj[] = cu.getOpObjects(opIndex);
//	        if (obj.length <= 1) {
//	        	continue;
//	        }
			int local_offset = 0;
			for (int i = 0; obj != null && i < obj.length; i++) {
				// check if any register is the stack pointer
				// if it is, need to compute stack depth offset for function
				//
				if (obj[i] instanceof Register) {
					Register reg = (Register) obj[i];
					Varnode vnode = context.getRegisterVarnodeValue(reg);
					if (vnode == null) {
						continue;
					}
					String spaceName = vnode.getAddress().getAddressSpace().getName();
					if (spaceName.startsWith("track_") || spaceName.equals(stackReg.getName())) {
//						opLocation = opIndex;
						local_offset += (int) vnode.getOffset();
					}
					else {
						continue;
					}
				}
				else if (obj[i] instanceof Scalar) {
					Scalar sc = (Scalar) obj[i];
					local_offset += sc.getSignedValue();
				}
				else {
					continue;
				}
				if (local_offset == offset) {
					return opIndex;
				}
			}
		}
		return -1;
	}

	/**
	 * Checks the indicated function in the program to determine if it is a jump thunk
	 * through a function pointer.
	 * @param func the function to check
	 * @param monitor status monitor for indicating progress and allowing cancel.
	 * @returntrue if check if this is a jump thunk through a function pointer
	 */
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

	private void defineFuncVariable(Function func, Instruction instr, int opIndex, int stackOffset,
			List<Variable> sortedVariables) {

		ReferenceManager refMgr = program.getReferenceManager();
		int refSize = getRefSize(instr, opIndex);
		try {
			// don't create crazy offsets
			if (stackOffset > MAX_PARAM_OFFSET || stackOffset < MAX_LOCAL_OFFSET) {
				return;
			}

			// check if operand already has a stack reference created
			Reference ref = instr.getPrimaryReference(opIndex);
			if (ref instanceof StackReference) {
				Variable var = refMgr.getReferencedVariable(ref);
				if (var == null) {
					accumulateVariable(func, ((StackReference) ref).getStackOffset(), refSize,
						sortedVariables);
				}
				return;
			}
			else if (ref == null) {
				RefType refType = RefTypeFactory.getDefaultStackRefType(instr, opIndex);
				refMgr.addStackReference(instr.getMinAddress(), opIndex, stackOffset, refType,
					SourceType.ANALYSIS);
				accumulateVariable(func, stackOffset, refSize, sortedVariables);
			}
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

	//private List<Variable> sortedVariables;

	private List<Variable> getVariablesIntersecting(int offset, int size,
			List<Variable> sortedVariables) {

		List<Variable> list = null;

		int maxOffset = offset + size - 1;

		while (offset <= maxOffset) {
			Variable var = getVariableContaining(offset, sortedVariables);
			if (var != null) {
				if (list == null) {
					list = new ArrayList<>();
				}
				list.add(var);
				offset += var.getLength();
			}
			else {
				++offset;
			}
		}

		return list;
	}

	private Variable getVariableContaining(int offset, List<Variable> sortedVariables) {
		Object key = new Integer(offset);
		int index = Collections.binarySearch(sortedVariables, key, StackVariableComparator.get());
		if (index >= 0) {
			return sortedVariables.get(index);
		}
		index = -index - 1;
		index = index - 1;
		if (index < 0) {
			return null;
		}
		Variable var = sortedVariables.get(index);
		int stackOffset = var.getStackOffset();
		if ((stackOffset + var.getLength()) > offset) {
			if (var.getDataType().isDeleted()) {
				sortedVariables.remove(index);
			}
			else {
				return var;
			}
		}
		return null;
	}

	/**
	 * Add non-overlapping stack variable to sorted variable list.  
	 * The caller is responsible for ensuring that no overlap/conflict
	 * with other variables in the list exist.
	 * @param var
	 * @param sortedVariables
	 */
	private void addVariableToSortedList(Variable var, List<Variable> sortedVariables) {
		int index = Collections.binarySearch(sortedVariables, new Integer(var.getStackOffset()),
			StackVariableComparator.get());
		if (index >= 0) {
			throw new AssertException("Unexpected variable conflict");
		}
		index = -index - 1;
		sortedVariables.add(index, var);
	}

	private void accumulateVariable(Function func, int offset, int refSize,
			List<Variable> sortedVariables) throws InvalidInputException {
		if (dontCreateNewVariables) {
			return;
		}

		int size = refSize > 0 ? refSize : 1;

		StackFrame frame = func.getStackFrame();
		int paramOffset = frame.getParameterOffset();
		boolean growsNegative = frame.growsNegative();

		boolean isParam =
			(growsNegative && offset >= paramOffset) || (!growsNegative && offset <= paramOffset);

		// Check exclusion options
		if (!doLocals && !isParam) {
			return;
		}
		if (!doParams && isParam) {
			return;
		}

		DataType dt;

		List<Variable> variablesIntersecting =
			getVariablesIntersecting(offset, size, sortedVariables);
		if (variablesIntersecting != null) {
			Variable firstVar = variablesIntersecting.get(0);
			if (firstVar.getLength() == size) {
				return; // exact match
			}

			int endOffset = (offset + size - 1);

			Variable lastVar = variablesIntersecting.get(variablesIntersecting.size() - 1);
			int minOffset = firstVar.getStackOffset();
			int maxOffset = lastVar.getStackOffset() + lastVar.getLength() - 1;
			for (int i = 0; i < variablesIntersecting.size(); i++) {
				sortedVariables.remove(variablesIntersecting.get(i));
			}

			// combine all intersecting variables into one
			if (minOffset > offset) {
				minOffset = offset;
			}
			if (maxOffset < endOffset) {
				maxOffset = endOffset;
			}

			dt = Undefined.getUndefinedDataType(Math.abs(maxOffset - minOffset) + 1);
			offset = minOffset;
		}
		else {
			dt = Undefined.getUndefinedDataType(size);
		}

		Variable var;
		if (isParam) {
			var = new ParameterImpl(null, dt, offset, program);
		}
		else {
			var = new LocalVariableImpl(null, dt, offset, program);
		}

		addVariableToSortedList(var, sortedVariables);
	}

}
