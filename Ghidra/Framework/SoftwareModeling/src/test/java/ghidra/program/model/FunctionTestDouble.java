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
package ghidra.program.model;

import java.util.List;
import java.util.Set;

import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class FunctionTestDouble implements Function {
	private String name;
	private FunctionSignature functionSignature;

	public FunctionTestDouble(String name) {
		this.name = name;
	}

	public FunctionTestDouble(String name, String signature) {
		this(name);
		functionSignature = new TestDoubleFunctionSignature(signature);
	}

	public FunctionTestDouble(String name, FunctionSignature signature) {
		this(name);
		functionSignature = signature;
	}

	@Override
	public boolean isDeleted() {
		return false;
	}

	@Override
	public String toString() {
		return name;
	}

	@Override
	public Symbol getSymbol() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getName(boolean includeNamespacePath) {
		return name;
	}

	@Override
	public long getID() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Namespace getParentNamespace() {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressSetView getBody() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setParentNamespace(Namespace parentNamespace)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public void setName(String name, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setCallFixup(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getCallFixup() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Program getProgram() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getComment() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String[] getCommentAsArray() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setComment(String comment) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getRepeatableComment() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String[] getRepeatableCommentAsArray() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setRepeatableComment(String comment) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Address getEntryPoint() {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType getReturnType() {
		if (functionSignature == null) {
			throw new UnsupportedOperationException();
		}
		return functionSignature.getReturnType();
	}

	@Override
	public void setReturnType(DataType type, SourceType source) throws InvalidInputException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Parameter getReturn() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setReturn(DataType type, VariableStorage storage, SourceType source)
			throws InvalidInputException {
		throw new UnsupportedOperationException();
	}

	@Override
	public FunctionSignature getSignature() {
		if (functionSignature == null) {
			throw new UnsupportedOperationException();
		}
		return functionSignature;
	}

	@Override
	public FunctionSignature getSignature(boolean formalSignature) {
		return getSignature();
	}

	@Override
	public String getPrototypeString(boolean formalSignature, boolean includeCallingConvention) {
		if (functionSignature == null) {
			throw new UnsupportedOperationException();
		}
		return functionSignature.getPrototypeString();
	}

	@Override
	public SourceType getSignatureSource() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setSignatureSource(SourceType signatureSource) {
		throw new UnsupportedOperationException();
	}

	@Override
	public StackFrame getStackFrame() {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getStackPurgeSize() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setStackPurgeSize(int purgeSize) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isStackPurgeSizeValid() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Parameter addParameter(Variable var, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Parameter insertParameter(int ordinal, Variable var, SourceType source)
			throws DuplicateNameException, InvalidInputException {
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
	public Parameter getParameter(int ordinal) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeParameter(int ordinal) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Parameter moveParameter(int fromOrdinal, int toOrdinal) throws InvalidInputException {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getParameterCount() {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getAutoParameterCount() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Parameter[] getParameters() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Parameter[] getParameters(VariableFilter filter) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Variable[] getLocalVariables() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Variable[] getLocalVariables(VariableFilter filter) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Variable[] getVariables(VariableFilter filter) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Variable[] getAllVariables() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Variable addLocalVariable(Variable var, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeVariable(Variable var) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setBody(AddressSetView newBody) throws OverlappingFunctionException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasVarArgs() {
		if (functionSignature == null) {
			throw new UnsupportedOperationException();
		}
		return functionSignature.hasVarArgs();
	}

	@Override
	public void setVarArgs(boolean hasVarArgs) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isInline() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setInline(boolean isInline) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasNoReturn() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setNoReturn(boolean hasNoReturn) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasCustomVariableStorage() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setCustomVariableStorage(boolean hasCustomVariableStorage) {
		throw new UnsupportedOperationException();
	}

	@Override
	public PrototypeModel getCallingConvention() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getCallingConventionName() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getDefaultCallingConventionName() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setCallingConvention(String name) throws InvalidInputException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isThunk() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Function getThunkedFunction(boolean recursive) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Address[] getFunctionThunkAddresses() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setThunkedFunction(Function thunkedFunction) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isExternal() {
		throw new UnsupportedOperationException();
	}

	@Override
	public ExternalLocation getExternalLocation() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Set<Function> getCallingFunctions(TaskMonitor monitor) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Set<Function> getCalledFunctions(TaskMonitor monitor) {
		throw new UnsupportedOperationException();
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
