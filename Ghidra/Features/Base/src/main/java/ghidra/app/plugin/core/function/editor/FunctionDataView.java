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
package ghidra.app.plugin.core.function.editor;

import java.util.*;

import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SymbolUtilities;

/**
 * {@link FunctionDataView} provides an immutable view of function data used by the 
 * Function Editor model. 
 */
class FunctionDataView {

	Function function;

	String name;
	boolean hasVarArgs;
	ParamInfo returnInfo;
	List<ParamInfo> parameters = new ArrayList<>();
	int autoParamCount = 0;
	boolean isInLine;
	boolean hasNoReturn;
	String callingConventionName;
	boolean allowCustomStorage;
	String callFixupName;

	/**
	 * Construct instance from {@link Function} details.
	 * @param function program function
	 */
	FunctionDataView(Function function) {
		this.function = function;
		this.name = function.getName();
		allowCustomStorage = function.hasCustomVariableStorage();
		hasVarArgs = function.hasVarArgs();
		isInLine = function.isInline();
		hasNoReturn = function.hasNoReturn();
		callingConventionName = function.getCallingConventionName();
		callFixupName = function.getCallFixup();
		initializeParametersAndReturn();
	}

	/**
	 * Construct a duplicate instance from another {@link FunctionDataView} instance.
	 * @param otherFunctionData function data
	 */
	FunctionDataView(FunctionDataView otherFunctionData) {
		name = otherFunctionData.name;
		hasVarArgs = otherFunctionData.hasVarArgs;
		returnInfo = otherFunctionData.returnInfo.copy();
		for (ParamInfo p : otherFunctionData.parameters) {
			parameters.add(p.copy());
		}
		autoParamCount = otherFunctionData.autoParamCount;
		isInLine = otherFunctionData.isInLine;
		hasNoReturn = otherFunctionData.hasNoReturn;
		callingConventionName = otherFunctionData.callingConventionName;
		allowCustomStorage = otherFunctionData.allowCustomStorage;
		callFixupName = otherFunctionData.callFixupName;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof FunctionDataView otherFunctionData)) {
			return false;
		}
		if (!Objects.equals(name, otherFunctionData.name) ||
			!Objects.equals(callingConventionName, otherFunctionData.callingConventionName) ||
			hasVarArgs != otherFunctionData.hasVarArgs ||
			parameters.size() != otherFunctionData.parameters.size() ||
			autoParamCount != otherFunctionData.autoParamCount ||
			isInLine != otherFunctionData.isInLine ||
			hasNoReturn != otherFunctionData.hasNoReturn ||
			allowCustomStorage != otherFunctionData.allowCustomStorage ||
			!Objects.equals(callFixupName, otherFunctionData.callFixupName) ||
			!returnInfo.isSame(otherFunctionData.returnInfo)) {
			return false;
		}

		int paramCount = parameters.size();
		for (int i = 0; i < paramCount; i++) {
			ParamInfo param = parameters.get(i);
			ParamInfo otherParam = otherFunctionData.parameters.get(i);
			if (!param.isSame(otherParam)) {
				return false;
			}
		}

		return true;
	}

	@Override
	public int hashCode() {
		return getNameString().hashCode();
	}

	private void initializeParametersAndReturn() {

		returnInfo = new ParamInfo(this, function.getReturn());

		// check for void storage correction
		if (VoidDataType.isVoidDataType(returnInfo.getDataType()) &&
			returnInfo.getStorage() != VariableStorage.VOID_STORAGE) {
			returnInfo.setStorage(VariableStorage.VOID_STORAGE);
		}

		autoParamCount = 0;
		Parameter[] params = function.getParameters();
		for (Parameter parameter : params) {
			if (parameter.isAutoParameter()) {
				++autoParamCount;
			}
			parameters.add(new ParamInfo(this, parameter));
		}

		fixupOrdinals();
	}

	void fixupOrdinals() {
		for (int i = 0; i < parameters.size(); i++) {
			parameters.get(i).setOrdinal(i);
		}
	}

	String getFunctionSignatureText() {
		StringBuilder buf = new StringBuilder();
		buf.append(returnInfo.getFormalDataType().getName()).append(" ");
		buf.append(getNameString());
		buf.append(" (");
		int skipCount = autoParamCount;
		int ordinal = 0;
		for (ParamInfo param : parameters) {
			if (skipCount > 0) {
				--skipCount;
				continue;
			}
			if (ordinal++ != 0) {
				buf.append(", ");
			}
			buf.append(param.getFormalDataType().getName());

			buf.append(" ");

			buf.append(param.getName());

		}
		if (hasVarArgs()) {
			if (!parameters.isEmpty()) {
				buf.append(", ");
			}
			buf.append(FunctionSignature.VAR_ARGS_DISPLAY_STRING);
		}
		else if (parameters.size() == 0) {
			buf.append(FunctionSignature.VOID_PARAM_DISPLAY_STRING);
		}
		buf.append(')');
		return buf.toString();
	}

	public Program getProgram() {
		return function.getProgram();
	}

	boolean canCustomizeStorage() {
		return allowCustomStorage;
	}

	int getAutoParamCount() {
		return autoParamCount;
	}

	int getParamCount() {
		return parameters.size();
	}

	public String getName() {
		return name;
	}

	String getNameString() {
		return name.length() == 0 ? SymbolUtilities.getDefaultFunctionName(function.getEntryPoint())
				: name;
	}

	boolean isInline() {
		return isInLine;
	}

	boolean hasNoReturn() {
		return hasNoReturn;
	}

	String getCallFixupName() {
		return callFixupName;
	}

	boolean hasCallFixup() {
		return callFixupName != null;
	}

	List<ParamInfo> getParameters() {
		return parameters;
	}

	ParamInfo getReturnInfo() {
		return returnInfo;
	}

	PrototypeModel getEffectiveCallingConvention() {
		FunctionManager functionManager = getProgram().getFunctionManager();
		PrototypeModel effectiveCallingConvention =
			functionManager.getCallingConvention(getCallingConventionName());
		if (effectiveCallingConvention == null) {
			effectiveCallingConvention = functionManager.getDefaultCallingConvention();
		}
		return effectiveCallingConvention;
	}

	String getCallingConventionName() {
		return callingConventionName;
	}

	boolean hasVarArgs() {
		return hasVarArgs;
	}

	boolean hasParameters() {
		return !parameters.isEmpty();
	}

}
