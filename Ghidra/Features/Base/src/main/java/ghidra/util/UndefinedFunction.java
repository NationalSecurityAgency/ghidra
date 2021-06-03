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
package ghidra.util;

import java.util.*;

import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class UndefinedFunction implements Function {

	private Program p;
	private AddressSetView body;
	private Address entry;
	private FunctionSignature signature;
	private StackFrame frame;

	/**
	 * Undefined Function constructor.
	 * Function will adopt the default calling convention prototype
	 * defined by the program's compiler specification.  The
	 * associated stack frame will also follow this default
	 * convention.
	 * @param p program containing the function
	 * @param entry function entry point
	 */
	public UndefinedFunction(Program p, Address entry) {
		if (entry != null && !entry.isMemoryAddress()) {
			throw new IllegalArgumentException("Entry point must be memory address");
		}
		this.p = p;
		this.body = new AddressSet(entry);
		this.entry = entry;
		signature = new FunctionDefinitionDataType(this, true);
		frame = new StackFrameImpl(this);
	}

	@Override
	public boolean isDeleted() {
		return false;
	}

	/**
	 * Identifies a <code>UndefinedFunction</code> based on the location given based upon the current
	 * listing disassembly at time of construction using a block model.
	 * @param program program to be searched
	 * @param address address within body of function
	 * @param monitor task monitor
	 * @return function or null if invalid parameters, not found, or cancelled
	 */
	public static UndefinedFunction findFunction(Program program, Address address,
			TaskMonitor monitor) {
		if (program == null || address == null || monitor.isCancelled()) {
			return null;
		}

		// first try to walk back up to the top of the function
		UndefinedFunction function = findFunctionUsingSimpleBlockModel(program, address, monitor);
		if (function != null || monitor.isCancelled()) {
			return function;
		}

		return findFunctionUsingIsolatedBlockModel(program, address, monitor);
	}

	@Override
	public int hashCode() {
		return entry.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof UndefinedFunction)) {
			return false;
		}
		UndefinedFunction otherFunc = (UndefinedFunction) obj;

		if (!entry.equals(otherFunc.entry)) {
			return false;
		}

		if (!SystemUtilities.isEqual(getBody(), otherFunc.getBody())) {
			return false;
		}
		return true;
	}

	@Override
	public boolean isExternal() {
		return false;
	}

	@Override
	public ExternalLocation getExternalLocation() {
		return null;
	}

	public static UndefinedFunction findFunctionUsingIsolatedBlockModel(Program program,
			Address address, TaskMonitor monitor) {

		monitor.setMessage(
			"Find undefined entry for " + address.toString() + " (isolated entry model)");
		try {
			IsolatedEntrySubModel model = new IsolatedEntrySubModel(program);
			CodeBlock codeBlock = model.getFirstCodeBlockContaining(address, monitor);
			if (codeBlock == null) {
				return null;
			}

			Address entry = codeBlock.getFirstStartAddress();
			return new UndefinedFunction(program, entry);
		}
		catch (CancelledException e) {
			return null;
		}
	}

	public static UndefinedFunction findFunctionUsingSimpleBlockModel(Program program,
			Address address, TaskMonitor monitor) {

		monitor.setMessage("Find undefined entry for " + address.toString() + " (simple model)");

		// if no instruction, don't try getting the function body
		if (program.getListing().getInstructionContaining(address) == null) {
			return null;
		}

		try {
			CodeBlock block = getEntryBlock(program, address, monitor);
			if (block == null) {
				return null;
			}
			return new UndefinedFunction(program, block.getFirstStartAddress());
		}
		catch (CancelledException e) {
			return null;
		}
	}

	private static CodeBlock getEntryBlock(Program program, Address address, TaskMonitor monitor)
			throws CancelledException {
		SimpleBlockModel simpleModel = new SimpleBlockModel(program);
		CodeBlock block = simpleModel.getFirstCodeBlockContaining(address, monitor);
		if (block == null || block.isEmpty()) {
			return null;
		}

		AddressSet visitedAddresses = new AddressSet();
		Deque<CodeBlock> worklist = new LinkedList<CodeBlock>();
		Address blockStart = block.getFirstStartAddress();
		visitedAddresses.addRange(blockStart, blockStart);
		worklist.add(block);
		while (!worklist.isEmpty()) {		// While there are blocks that haven't been examined yet
			CodeBlock curblock = worklist.poll();
			int count = 0;
			CodeBlockReferenceIterator iterator = curblock.getSources(monitor);
			while (iterator.hasNext() && !monitor.isCancelled()) {
				CodeBlockReference blockReference = iterator.next();
				FlowType flowType = blockReference.getFlowType();
				if (flowType.isCall()) {
					continue; // Don't follow call edges for within-function analysis
				}
				if (flowType.isIndirect()) {
					continue; // Don't follow improper use of Indirect reference
				}
				count += 1;	  // Count the existence of source that is NOT a call
				Address sourceAddr = blockReference.getSourceAddress();
				if (visitedAddresses.contains(sourceAddr)) {
					continue; // Already visited this block
				}
				visitedAddresses.addRange(sourceAddr, sourceAddr);
				worklist.add(blockReference.getSourceBlock());
			}
			if (count == 0) {
				return curblock;
			}
		}
		return null;
	}

	@Override
	public Variable addLocalVariable(Variable var, SourceType source)
			throws DuplicateNameException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Parameter addParameter(Variable var, SourceType source) throws DuplicateNameException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Parameter moveParameter(int fromOrdinal, int toOrdinal) {
		throw new UnsupportedOperationException();
	}

	@Override
	public PrototypeModel getCallingConvention() {
		return p.getCompilerSpec().getDefaultCallingConvention();
	}

	@Override
	public String getCallingConventionName() {
		return Function.UNKNOWN_CALLING_CONVENTION_STRING;
	}

	@Override
	public String getComment() {
		return null;
	}

	@Override
	public String[] getCommentAsArray() {
		return new String[0];
	}

	@Override
	public String getDefaultCallingConventionName() {
		return p.getCompilerSpec().getDefaultCallingConvention().getName();
	}

	@Override
	public Address getEntryPoint() {
		return entry;
	}

	@Override
	public Variable[] getLocalVariables() {
		return new Variable[0];
	}

	@Override
	public String getName() {
		return "UndefinedFunction_" + entry.toString(false);
	}

	@Override
	public Parameter getParameter(int ordinal) {
		return null;
	}

	@Override
	public int getParameterCount() {
		return 0;
	}

	@Override
	public int getAutoParameterCount() {
		return 0;
	}

	@Override
	public Parameter[] getParameters() {
		return new Parameter[0];
	}

	@Override
	public Program getProgram() {
		return p;
	}

	@Override
	public Parameter[] getParameters(VariableFilter filter) {
		return new Parameter[0];
	}

	@Override
	public Variable[] getLocalVariables(VariableFilter filter) {
		return new Variable[0];
	}

	@Override
	public Variable[] getVariables(VariableFilter filter) {
		return new Variable[0];
	}

	@Override
	public boolean hasCustomVariableStorage() {
		return false;
	}

	@Override
	public void setCustomVariableStorage(boolean hasCustomVariableStorage) {
		// don't support
	}

	@Override
	public Variable[] getAllVariables() {
		return new Variable[0];
	}

	@Override
	public String getRepeatableComment() {
		return null;
	}

	@Override
	public String[] getRepeatableCommentAsArray() {
		return new String[0];
	}

	@Override
	public DataType getReturnType() {
		return DataType.DEFAULT;
	}

	@Override
	public Parameter getReturn() {
		try {
			DataType dt = getReturnType();
			if (dt instanceof TypeDef) {
				dt = ((TypeDef) dt).getBaseDataType();
			}
			return new ReturnParameterImpl(dt,
				(dt instanceof VoidDataType) ? VariableStorage.VOID_STORAGE
						: VariableStorage.UNASSIGNED_STORAGE,
				getProgram());
		}
		catch (InvalidInputException e) {
			throw new AssertException(e);
		}
	}

	@Override
	public void setReturn(DataType type, VariableStorage storage, SourceType source)
			throws InvalidInputException {
		throw new UnsupportedOperationException();
	}

	@Override
	public FunctionSignature getSignature() {
		return signature;
	}

	@Override
	public FunctionSignature getSignature(boolean formalSignature) {
		return signature;
	}

	@Override
	public String getPrototypeString(boolean formalSignature, boolean includeCallingConvention) {
		return signature.getPrototypeString(includeCallingConvention);
	}

	@Override
	public SourceType getSignatureSource() {
		return SourceType.DEFAULT;
	}

	@Override
	public void setSignatureSource(SourceType signatureSource) {
		throw new UnsupportedOperationException();
	}

	@Override
	public StackFrame getStackFrame() {
		return frame;
	}

	@Override
	public int getStackPurgeSize() {
		return 0; // should not be used by analyzer
	}

	@Override
	public boolean hasNoReturn() {
		return false;
	}

	@Override
	public boolean hasVarArgs() {
		return false;
	}

	@Override
	public Parameter insertParameter(int ordinal, Variable var, SourceType source)
			throws DuplicateNameException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void replaceParameters(List<? extends Variable> params, FunctionUpdateType updateType,
			boolean force, SourceType source) throws DuplicateNameException, InvalidInputException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void replaceParameters(FunctionUpdateType updateType, boolean force, SourceType source,
			Variable... params) throws DuplicateNameException, InvalidInputException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void updateFunction(String callingConvention, Variable returnValue,
			FunctionUpdateType updateType, boolean force, SourceType source, Variable... newParams)
			throws DuplicateNameException, InvalidInputException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void updateFunction(String callingConvention, Variable returnVar,
			List<? extends Variable> newParams, FunctionUpdateType updateType, boolean force,
			SourceType source) throws DuplicateNameException, InvalidInputException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isInline() {
		return false;
	}

	@Override
	public boolean isStackPurgeSizeValid() {
		return false;
	}

	@Override
	public void removeParameter(int ordinal) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeVariable(Variable var) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setBody(AddressSetView newBody) {
		body = newBody;
	}

	@Override
	public void setCallingConvention(String name) throws InvalidInputException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setComment(String comment) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setInline(boolean isInline) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setName(String name, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setNoReturn(boolean hasNoReturn) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setRepeatableComment(String comment) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setReturnType(DataType type, SourceType source) {
		if (type == DataType.DEFAULT) {
			return;
		}
		throw new UnsupportedOperationException();
	}

	@Override
	public void setStackPurgeSize(int purgeSize) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setVarArgs(boolean hasVarArgs) {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressSetView getBody() {
		return body;
	}

	@Override
	public long getID() {
		// should not be used
		return -1;
	}

	@Override
	public String getName(boolean includeNamespacePath) {
		return getName();
	}

	@Override
	public Namespace getParentNamespace() {
		return p.getGlobalNamespace();
	}

	@Override
	public Symbol getSymbol() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setParentNamespace(Namespace parentNamespace)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getCallFixup() {
		return null;
	}

	@Override
	public void setCallFixup(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isThunk() {
		return false;
	}

	@Override
	public Function getThunkedFunction(boolean recursive) {
		return null;
	}

	@Override
	public void setThunkedFunction(Function thunkedFunction) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Address[] getFunctionThunkAddresses() {
		return null;
	}

	@Override
	public Set<Function> getCallingFunctions(TaskMonitor monitor) {
		return Collections.emptySet();
	}

	@Override
	public Set<Function> getCalledFunctions(TaskMonitor monitor) {
		return Collections.emptySet();
	}

	@Override
	public void removeTag(String tagName) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Set<FunctionTag> getTags() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean addTag(String tagName) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void promoteLocalUserLabelsToGlobal() {
		throw new UnsupportedOperationException();
	}

}
