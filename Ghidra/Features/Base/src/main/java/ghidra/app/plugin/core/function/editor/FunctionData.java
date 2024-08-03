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

import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.InvalidInputException;

class FunctionData extends FunctionDataView {

	public FunctionData(Function function) {
		super(function);
	}

	/**
	 * Determine if return/parameter datatype and/or storage has changed and should be comitted.
	 * Auto params and calling-convention imposed changes are not considered.
	 * @param originalFunctionData original function data prior to edits
	 * @return true if non-auto parameters have been modified, else false
	 */
	boolean hasParameterChanges(FunctionDataView originalFunctionData) {

		boolean checkStorage = false;
		if (canCustomizeStorage()) {
//			if (!originalFunctionData.canCustomizeStorage()) {
//				// switched to using custom storage
//				return true;
//			}
			checkStorage = true;
		}

		if (!returnInfo.getFormalDataType()
				.equals(originalFunctionData.returnInfo.getFormalDataType())) {
			return true;
		}
		if (checkStorage &&
			!returnInfo.getStorage().equals(originalFunctionData.returnInfo.getStorage())) {
			return true;
		}

		int paramStartIndex = autoParamCount;
		int nonAutoParamCount = parameters.size() - paramStartIndex;
		int originalParamStartIndex = originalFunctionData.autoParamCount;
		int originalNonAutoParamCount =
			originalFunctionData.parameters.size() - originalParamStartIndex;

		if (nonAutoParamCount != originalNonAutoParamCount) {
			return true;
		}

		for (int i = 0; i < nonAutoParamCount; i++) {
			ParamInfo param = parameters.get(paramStartIndex + i);
			ParamInfo originalParam =
				originalFunctionData.parameters.get(originalParamStartIndex + i);
			if (!param.getFormalDataType().equals(originalParam.getFormalDataType())) {
				return true;
			}
			if (checkStorage && !param.getStorage().equals(originalParam.getStorage())) {
				return true;
			}

			// Check for name change without stored param
			if (!Objects.equals(param.getName(true), originalParam.getName(true))) {
				if (function.getParameter(param.getOrdinal()) == null) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Determine if parameter name(s) have been modified.  Note that this method will return false
	 * if the number of non-auto parameters has changed.
	 * @param originalFunctionData original function data prior to edits
	 * @return true if one or more parameter names has changed, else false
	 */
	boolean hasParameterNamesChanged(FunctionDataView originalFunctionData) {

		int paramStartIndex = autoParamCount;
		int nonAutoParamCount = parameters.size() - paramStartIndex;
		int originalParamStartIndex = originalFunctionData.autoParamCount;
		int originalNonAutoParamCount =
			originalFunctionData.parameters.size() - originalParamStartIndex;

		if (nonAutoParamCount != originalNonAutoParamCount) {
			return false;
		}

		for (int i = 0; i < nonAutoParamCount; i++) {
			ParamInfo param = parameters.get(paramStartIndex + i);
			ParamInfo originalParam =
				originalFunctionData.parameters.get(originalParamStartIndex + i);
			if (!Objects.equals(param.getName(true), originalParam.getName(true))) {
				return true;
			}
		}

		return false;
	}

	ParamInfo addNewParameter() {
		ParamInfo param = new ParamInfo(this, null, DataType.DEFAULT,
			VariableStorage.UNASSIGNED_STORAGE, canCustomizeStorage(), parameters.size());
		parameters.add(param);
		fixupOrdinals();
		updateParameterAndReturnStorage();
		return param;
	}

	void removeAllParameters() {
		parameters.clear();
		autoParamCount = 0;
	}

	void removeParameters(List<ParamInfo> paramsToRemove) {
		Iterator<ParamInfo> it = parameters.iterator();
		while (it.hasNext()) {
			ParamInfo p = it.next();
			if (paramsToRemove.contains(p)) {
				it.remove();
			}
		}
		fixupOrdinals();
		updateParameterAndReturnStorage();
	}

	void moveParameterUp(int paramIndex) {
		ParamInfo param = parameters.remove(paramIndex);
		parameters.add(paramIndex - 1, param);
		fixupOrdinals();
		updateParameterAndReturnStorage();
	}

	void moveParameterDown(int paramIndex) {
		ParamInfo param = parameters.remove(paramIndex);
		parameters.add(paramIndex + 1, param);
		fixupOrdinals();
		updateParameterAndReturnStorage();
	}

	void setName(String n) {
		this.name = n;
	}

	void setInline(boolean enable) {
		this.isInLine = enable;
	}

	void setHasNoReturn(boolean enable) {
		this.hasNoReturn = enable;
	}

	void clearCallFixup() {
		callFixupName = null;
	}

	void setCallFixupName(String cfuName) {
		this.callFixupName = cfuName;
	}

	void setCallingConventionName(String ccName) {
		if (Objects.equals(ccName, callingConventionName)) {
			return;
		}
		this.callingConventionName = ccName;
		removeExplicitThisParameter();
		updateParameterAndReturnStorage();
	}

	void setVarArgs(boolean enable) {
		this.hasVarArgs = enable;
	}

	/**
	 * Update dynamic storage and auto-params when custom storage is disasbled.
	 * Returns immediately if custom storage is enabled.
	 */
	void updateParameterAndReturnStorage() {
		if (allowCustomStorage) {
			autoParamCount = 0;
			return;
		}
		PrototypeModel effectiveCallingConvention = getEffectiveCallingConvention();

		if (effectiveCallingConvention == null) {
			for (ParamInfo info : parameters) {
				info.setStorage(VariableStorage.UNASSIGNED_STORAGE);
			}
			return;
		}

		DataType[] dataTypes = new DataType[parameters.size() - autoParamCount + 1];
		dataTypes[0] = returnInfo.getFormalDataType();

		int index = 1;
		for (int i = autoParamCount; i < parameters.size(); i++) {
			dataTypes[index++] = parameters.get(i).getFormalDataType();
		}

		VariableStorage[] paramStorage =
			effectiveCallingConvention.getStorageLocations(getProgram(), dataTypes, true);

		returnInfo.setStorage(paramStorage[0]);

		List<ParamInfo> oldParams = parameters;
		int oldAutoCount = autoParamCount;

		parameters = new ArrayList<>();
		autoParamCount = 0;

		int ordinal = 0;
		for (int i = 1; i < paramStorage.length; i++) {
			VariableStorage storage = paramStorage[i];
			ParamInfo info;
			if (storage.isAutoStorage()) {
				DataType dt = VariableUtilities.getAutoDataType(function,
					returnInfo.getFormalDataType(), storage);
				try {
					info = new ParamInfo(this,
						new AutoParameterImpl(dt, ++autoParamCount, storage, function));
				}
				catch (InvalidInputException e) {
					throw new AssertException(e); // unexpected
				}
			}
			else {
				info = oldParams.get(oldAutoCount + ordinal);
				info.setStorage(storage);
				++ordinal;
			}
			parameters.add(info);
		}
		fixupOrdinals();
	}

	void clearAutoParams() {
		autoParamCount = 0;
	}

	/**
	 * Change the enablement of custom storage
	 * @param enable true if custom storage should be enable, else false to 
	 */
	void setUseCustomStorage(boolean enable) {
		if (enable == allowCustomStorage) {
			return;
		}
		allowCustomStorage = enable;
		if (!enable) {
			removeExplicitThisParameter();
			DataType returnDt = removeExplicitReturnStoragePtrParameter();
			if (returnDt != null) {
				returnInfo.setFormalDataType(returnDt);
				returnInfo.setStorage(VariableStorage.UNASSIGNED_STORAGE);
			}
			updateParameterAndReturnStorage();
		}
		else {
			switchToCustomStorage();
		}
	}

	/**
	 * Switch to custom storage and perform required transformations
	 */
	private void switchToCustomStorage() {
		try {
			VariableStorage returnStorage = returnInfo.getStorage();
			DataType returnType = returnInfo.getDataType();
			if (returnStorage.isForcedIndirect() && returnStorage.isVoidStorage()) {
				returnType = VoidDataType.dataType;
			}
			returnInfo.setFormalDataType(returnType);
			returnInfo.setStorage(returnStorage.clone(getProgram()));

			autoParamCount = 0;
			for (ParamInfo paramInfo : parameters) {
				DataType dt = paramInfo.getDataType();
				VariableStorage storage = paramInfo.getStorage();
				paramInfo.setFormalDataType(dt);
				paramInfo.setStorage(storage.clone(getProgram()));
			}
		}
		catch (InvalidInputException e) {
			throw new AssertException(e); // unexpected
		}
	}

	void removeExplicitThisParameter() {
		if (!allowCustomStorage &&
			CompilerSpec.CALLING_CONVENTION_thiscall.equals(callingConventionName)) {
			int thisIndex = findExplicitThisParameter();
			if (thisIndex >= 0) {
				parameters.remove(thisIndex); // remove explicit 'this' parameter
			}
		}
	}

	private DataType removeExplicitReturnStoragePtrParameter() {
		int index = findExplicitReturnStoragePtrParameter();
		if (index >= 0) {
			// remove explicit '__return_storage_ptr__' parameter - should always be a pointer
			ParamInfo returnStoragePtrParameter = parameters.remove(index);
			DataType dt = returnStoragePtrParameter.getDataType();
			if (dt instanceof Pointer ptr) {
				return ptr.getDataType();
			}
		}
		return null;
	}

	private int findExplicitThisParameter() {
		for (int i = 0; i < parameters.size(); i++) {
			ParamInfo p = parameters.get(i);
			if (!p.isAutoParameter() && Function.THIS_PARAM_NAME.equals(p.getName()) &&
				(p.getDataType() instanceof Pointer)) {
				return i;
			}
		}
		return -1;
	}

	private int findExplicitReturnStoragePtrParameter() {
		for (int i = 0; i < parameters.size(); i++) {
			ParamInfo p = parameters.get(i);
			if (!p.isAutoParameter() && Function.RETURN_PTR_PARAM_NAME.equals(p.getName()) &&
				(p.getDataType() instanceof Pointer)) {
				return i;
			}
		}
		return -1;
	}

}
