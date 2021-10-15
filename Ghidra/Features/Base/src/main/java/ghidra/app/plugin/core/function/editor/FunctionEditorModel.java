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

import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.*;
import ghidra.util.exception.*;

public class FunctionEditorModel {
	public static final String PARSING_MODE_STATUS_TEXT =
		"<TAB> or <RETURN> to commit edits, <ESC> to abort";
	static final String NONE_CHOICE = "-NONE-";

	private String name;
	private ModelChangeListener listener;
	private boolean hasVarArgs;
	private ParamInfo returnInfo;
	private List<ParamInfo> parameters = new ArrayList<>();
	private int autoParamCount = 0;
	private String statusText = "";
	private boolean isValid = true;
	private boolean signatureTransformed = false;
	private boolean isInLine;
	private boolean isNoReturn;
	private String callingConventionName;
	private Function function;
	private FunctionManager functionManager;
	private String callFixupName;
	private int[] selectedFunctionRows = new int[0];
	private Program program;
	private boolean allowCustomStorage;
	private boolean isInParsingMode;
	private String signatureFieldText;
	private DataTypeManagerService dataTypeManagerService;
	private boolean modelChanged = false;

	public FunctionEditorModel(DataTypeManagerService service, Function function) {
		this.dataTypeManagerService = service;
		this.function = function;
		this.program = function.getProgram();
		this.name = function.getName();
		this.functionManager = program.getFunctionManager();
		allowCustomStorage = function.hasCustomVariableStorage();
		hasVarArgs = function.hasVarArgs();
		isInLine = function.isInline();
		isNoReturn = function.hasNoReturn();
		callingConventionName = function.getCallingConventionName();
		callFixupName = function.getCallFixup();
		if (callFixupName == null) {
			callFixupName = NONE_CHOICE;
		}
		initializeParametersAndReturn();
		validate();
	}

	void setModelChangeListener(ModelChangeListener listener) {
		this.listener = listener;
	}

	// Returns the current calling convention or the default calling convention if current unknown
	private PrototypeModel getEffectiveCallingConvention() {
		PrototypeModel effectiveCallingConvention =
			functionManager.getCallingConvention(callingConventionName);
		if (effectiveCallingConvention == null) {
			effectiveCallingConvention = functionManager.getDefaultCallingConvention();
		}
		return effectiveCallingConvention;
	}

	private void initializeParametersAndReturn() {

		returnInfo = new ParamInfo(this, function.getReturn());

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

	private boolean hasModifiedParametersOrReturn() {
		if (returnInfo.isModified()) {
			return true;
		}
		if ((function.getParameterCount() -
			function.getAutoParameterCount()) != (parameters.size() - autoParamCount)) {
			return true;
		}
		for (ParamInfo info : parameters) {
			if (!info.isAutoParameter() && info.isModified()) {
				return true;
			}
		}
		return false;
	}

	public List<String> getCallingConventionNames() {
		return functionManager.getCallingConventionNames();
	}

	public String[] getCallFixupNames() {
		return program.getCompilerSpec().getPcodeInjectLibrary().getCallFixupNames();
	}

	public void setName(String name) {
		if (this.name.equals(name)) {
			return;
		}
		this.name = name.trim();
		notifyDataChanged();
	}

	public void setCallingConventionName(String callingConventionName) {
		this.callingConventionName = callingConventionName;
		removeExplicitThisParameter();
		updateParameterAndReturnStorage();
		notifyDataChanged();
	}

	public String getCallingConventionName() {
		return callingConventionName;
	}

	public void setHasVarArgs(boolean b) {
		hasVarArgs = b;
		notifyDataChanged();
	}

	public String getName() {
		return name;
	}

	public void dispose() {
		listener = new ModelChangeListener() {
			@Override
			public void tableRowsChanged() {
				// do nothing
			}

			@Override
			public void dataChanged() {
				// do nothing
			}
		};
	}

	private void notifyDataChanged() {
		notifyDataChanged(true);
	}

	private void notifyDataChanged(boolean functionDataChanged) {
		this.modelChanged |= functionDataChanged;
		validate();
		if (listener != null) {
			Swing.runLater(() -> listener.dataChanged());
		}
	}

	private void validate() {
		statusText = "";
		if (signatureTransformed) {
			statusText = "Signature transformed due to auto-params and/or forced-indirect storage";
			signatureTransformed = false; // one-shot message
		}
		isValid =
			hasValidName() && hasValidReturnType() && hasValidReturnStorage() && hasValidParams();
		if (isValid) {
			checkUnassignedStorage();
		}
	}

	private boolean hasValidReturnStorage() {

		if (!allowCustomStorage) {
			return true;
		}

		VariableStorage returnStorage = returnInfo.getStorage();
		DataType returnType = returnInfo.getDataType();

		if (returnStorage.isUnassignedStorage()) {
			return true; // allow dynamic unassigned storage
		}

		int storageSize = returnStorage.size();
		if (returnType instanceof TypeDef) {
			returnType = ((TypeDef) returnType).getBaseDataType();
		}
		if (storageSize > 0 && (returnType instanceof AbstractFloatDataType)) {
			return true; // don't constrain float storage size
		}

		int returnDataTypeSize = returnType.getLength();

		if (storageSize < returnDataTypeSize) {
			statusText = "Insufficient Return Storage (" + storageSize + "-bytes) for datatype (" +
				returnDataTypeSize + "-bytes)";
			return false;
		}
		else if (storageSize > returnDataTypeSize) {
			statusText = "Too much Return Storage (" + storageSize + "-bytes) for datatype (" +
				returnDataTypeSize + "-bytes)";
			return false;
		}
		return true;
	}

	private void checkUnassignedStorage() {

		VariableStorage returnStorage = returnInfo.getStorage();
		DataType returnType = returnInfo.getFormalDataType();

		boolean hasUnassignedStorage = returnStorage != null && returnStorage.isUnassignedStorage();

		if (!hasUnassignedStorage) {
			for (ParamInfo param : parameters) {
				if (param.getStorage().isUnassignedStorage()) {
					hasUnassignedStorage = true;
					break;
				}
			}
		}

		if (hasUnassignedStorage) {
			statusText = "Warning: Return Storage and/or Parameter Storage is Unassigned";
		}
		else if (!allowCustomStorage &&
			Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(callingConventionName)) {
			if (!(returnType instanceof VoidDataType && parameters.isEmpty())) {
				statusText =
					"Warning: No calling convention specified. Ghidra may automatically assign one later.";
			}
		}

	}

	private boolean hasValidParams() {
		for (ParamInfo param : parameters) {
			if (!(isValidParamType(param) && isValidParamName(param) && isValidStorage(param))) {
				return false;
			}
		}
		return checkForConflictingParameters();
	}

	private boolean checkForConflictingParameters() {
		// VARDO conflicting parameters
		return true;
	}

	private boolean isValidStorage(ParamInfo param) {
		if (!allowCustomStorage) {
			return true;
		}

		VariableStorage storage = param.getStorage();
		if (storage.isUnassignedStorage()) {
			return true; // allow dynamic unassigned storage
		}

		int storageSize = storage.size();

		DataType datatype = param.getDataType();
		if (datatype instanceof TypeDef) {
			datatype = ((TypeDef) datatype).getBaseDataType();
		}
		if (storageSize > 0 && (datatype instanceof AbstractFloatDataType)) {
			return true; // don't constrain float storage size
		}

		int requiredSize = datatype.getLength();

		if (storageSize < requiredSize) {
			statusText = "Insufficient storage (" + storageSize + "-bytes) for datatype (" +
				requiredSize + "-bytes) assigned to parameter " + (param.getOrdinal() + 1);
			return false;
		}
		else if (requiredSize == 0) {
			// assume 0-sized structure which we need to allow
		}
		else if (storageSize > requiredSize) {
			statusText = "Too much storage (" + storageSize + "-bytes) for datatype (" +
				requiredSize + "-bytes) assigned to parameter " + (param.getOrdinal() + 1);
			return false;
		}
		return true;
	}

	public boolean hasValidName() {
		if (name.length() == 0) {
			statusText = "Missing function name";
			return false;
		}
		if (SymbolUtilities.containsInvalidChars(name)) {
			statusText = "Invalid function name: \"" + name + "\"";
			return false;
		}

		return true;
	}

	private DataType getBaseDataType(DataType dataType) {
		if (dataType instanceof TypeDef) {
			return ((TypeDef) dataType).getBaseDataType();
		}
		return dataType;
	}

	private boolean hasValidReturnType() {
		DataType returnType = returnInfo.getDataType();
		DataType baseType = getBaseDataType(returnType);
		if (baseType instanceof VoidDataType) {
			return true;
		}
		if (returnType.getLength() <= 0) {
			statusText = "\"" + returnType.getName() +
				"\" is not allowed as a return type: Must be fixed size.";
			return false;
		}
		return true;
	}

	private boolean isValidParamName(ParamInfo param) {
		String paramName = param.getName();
		if (SymbolUtilities.containsInvalidChars(paramName)) {
			statusText =
				"Invalid name for parameter " + (param.getOrdinal() + 1) + ": " + paramName;
			return false;
		}
		for (ParamInfo info : parameters) {
			if (info != param && info.getName().equals(paramName)) {
				statusText = "Duplicate parameter name: " + paramName;
				return false;
			}
		}
		return true;
	}

	private boolean isValidParamType(ParamInfo param) {
		DataType dataType = param.getDataType();
		if (dataType.isEquivalent(VoidDataType.dataType)) {
			statusText = "\"void\" is not allowed as a parameter datatype.";
			return false;
		}

		if (dataType.getLength() < 0) {
			statusText = "\"" + dataType.getName() +
				"\" is not allowed as a parameter datatype. Must be fixed size.";
			return false;
		}
		return true;
	}

	public boolean isValid() {
		return isValid;
	}

	public String getFunctionSignatureTextFromModel() {
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

			buf.append(getParamNameString(param));

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

	public String getNameString() {
		return name.length() == 0 ? "?" : name;
	}

	private String getParamNameString(ParamInfo param) {
		return param.getName();
	}

	public boolean hasVarArgs() {
		return hasVarArgs;
	}

	public DataType getReturnType() {
		return returnInfo.getDataType();
	}

	public DataType getFormalReturnType() {
		return returnInfo.getFormalDataType();
	}

	public boolean setFormalReturnType(DataType formalReturnType) {
		return setParameterFormalDataType(returnInfo, formalReturnType);
	}

	public String getStatusText() {
		if (isInParsingMode) {
			return PARSING_MODE_STATUS_TEXT;
		}
		return statusText;
	}

	public void setIsInLine(boolean isInLine) {
		if (isInLine == this.isInLine) {
			return;
		}
		this.isInLine = isInLine;
		if (isInLine) {
			callFixupName = NONE_CHOICE;
		}
		notifyDataChanged();
	}

	public void setNoReturn(boolean isNoReturn) {
		this.isNoReturn = isNoReturn;
		notifyDataChanged();
	}

	public boolean isInlineAllowed() {
		return !getAffectiveFunction().isExternal();
	}

	/**
	 * Get the effective function to which changes will be made.  This
	 * will be the same as function unless it is a thunk in which case
	 * the returned function will be the ultimate non-thunk function.
	 * @return non-thunk function
	 */
	private Function getAffectiveFunction() {
		return function.isThunk() ? function.getThunkedFunction(true) : function;
	}

	public boolean isInLine() {
		return isInLine;
	}

	public boolean isNoReturn() {
		return isNoReturn;
	}

	public String getCallFixupName() {
		return callFixupName;
	}

	public void setCallFixupName(String callFixupName) {
		if (callFixupName.equals(this.callFixupName)) {
			return;
		}
		this.callFixupName = callFixupName;
		if (!callFixupName.equals(NONE_CHOICE)) {
			isInLine = false;
		}
		notifyDataChanged();
	}

	public void setSelectedParameterRow(int[] selectedRows) {
		selectedFunctionRows = selectedRows;
		notifyDataChanged();
	}

	private void setSelectedRow(int row) {
		selectedFunctionRows = new int[] { row };
	}

	private void adjustSelectionForRowRemoved(int row) {
		// adjust selectedParamRows
		if (selectedFunctionRows.length == 0) {
			return;
		}
		List<Integer> rows = new ArrayList<>();
		for (int i : selectedFunctionRows) {
			if (i < row) {
				rows.add(i);
			}
			if (i > row) {
				rows.add(i - 1);
			}
		}
		selectedFunctionRows = new int[rows.size()];
		int index = 0;
		for (int i : rows) {
			selectedFunctionRows[index++] = i;
		}
	}

	private void adjustSelectionForRowAdded(int row) {
		// adjust selectedParamRows
		if (selectedFunctionRows.length == 0) {
			return;
		}
		List<Integer> rows = new ArrayList<>();
		for (int i : selectedFunctionRows) {
			if (i < row) {
				rows.add(i);
			}
			if (i >= row) {
				rows.add(i + 1);
			}
		}
		selectedFunctionRows = new int[rows.size()];
		int index = 0;
		for (int i : rows) {
			selectedFunctionRows[index++] = i;
		}
	}

	public int[] getSelectedParameterRows() {
		return selectedFunctionRows;
	}

	public void addParameter() {
		if (listener != null) {
			listener.tableRowsChanged();
		}
		ParamInfo param = new ParamInfo(this, null, DataType.DEFAULT,
			VariableStorage.UNASSIGNED_STORAGE, parameters.size());
		parameters.add(param);
		fixupOrdinals();
		updateParameterAndReturnStorage();
		setSelectedRow(parameters.size());
		notifyDataChanged();
	}

	/**
	 * Switch to custom storage and perform required transformations
	 */
	private void switchToCustomStorage() {
		try {
			VariableStorage returnStorage = returnInfo.getStorage();
			if (returnStorage.isForcedIndirect()) {
				DataType returnType = returnInfo.getDataType();
				returnInfo.setFormalDataType(returnType);
				returnInfo.setStorage(returnStorage.clone(program));
				signatureTransformed = true;
			}
			autoParamCount = 0;
			int paramCnt = parameters.size();
			for (int i = 0; i < paramCnt; i++) {
				ParamInfo paramInfo = parameters.get(i);
				DataType dt = paramInfo.getDataType();
				VariableStorage storage = paramInfo.getStorage();
				signatureTransformed |= storage.isAutoStorage();
				paramInfo.setFormalDataType(dt);
				paramInfo.setStorage(storage.clone(program));
			}
		}
		catch (InvalidInputException e) {
			throw new AssertException(e); // unexpected
		}
	}

	private void updateParameterAndReturnStorage() {
		if (allowCustomStorage) {
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
			effectiveCallingConvention.getStorageLocations(program, dataTypes, true);

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
					if (autoParamCount < oldAutoCount) {
						if (oldParams.get(
							autoParamCount).getStorage().getAutoParameterType() != storage
									.getAutoParameterType()) {
							adjustSelectionForRowRemoved(i);
						}
					}
					else {
						adjustSelectionForRowAdded(i);
					}
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
		for (int i = oldAutoCount; i > autoParamCount; i--) {
			adjustSelectionForRowRemoved(i);
		}
		fixupOrdinals();
	}

	private void fixupOrdinals() {
		for (int i = 0; i < parameters.size(); i++) {
			parameters.get(i).setOrdinal(i);
		}
	}

	public void removeParameters() {
		if (!canRemoveParameters()) {
			throw new AssertException("Attempted to remove parameters when not allowed.");
		}
		if (listener != null) {
			listener.tableRowsChanged();
		}
		Arrays.sort(selectedFunctionRows);
		for (int i = selectedFunctionRows.length - 1; i >= 0; i--) {
			int index = selectedFunctionRows[i];
			parameters.remove(index - 1);
		}
		if (parameters.isEmpty()) {
			selectedFunctionRows = new int[0];
		}
		else {
			int selectRow = Math.min(selectedFunctionRows[0], parameters.size());
			selectedFunctionRows = new int[] { selectRow };
		}
		fixupOrdinals();
		updateParameterAndReturnStorage();
		notifyDataChanged();
	}

	public void moveSelectedParameterUp() {
		if (!canMoveParameterUp()) {
			throw new AssertException("Attempted to move parameters up when not allowed.");
		}
		if (listener != null) {
			listener.tableRowsChanged();
		}
		int paramIndex = selectedFunctionRows[0] - 1;  // first row is return value 
		ParamInfo param = parameters.remove(paramIndex);
		parameters.add(paramIndex - 1, param);
		fixupOrdinals();
		setSelectedRow(selectedFunctionRows[0] - 1);	// move selection up one row
		updateParameterAndReturnStorage();
		notifyDataChanged();
	}

	public void moveSelectedParameterDown() {
		if (!canMoveParameterDown()) {
			throw new AssertException("Attempted to move parameters down when not allowed.");
		}
		if (listener != null) {
			listener.tableRowsChanged();
		}
		int paramIndex = selectedFunctionRows[0] - 1;
		ParamInfo param = parameters.remove(paramIndex);
		parameters.add(paramIndex + 1, param);
		fixupOrdinals();
		setSelectedRow(selectedFunctionRows[0] + 1);
		updateParameterAndReturnStorage();
		notifyDataChanged();
	}

	public List<ParamInfo> getParameters() {
		return parameters;
	}

	public boolean canRemoveParameters() {
		if (selectedFunctionRows.length == 0) {
			return false;
		}
		for (int row : selectedFunctionRows) {
			if (row <= autoParamCount) {
				return false;
			}
		}
		return true;
	}

	public boolean canMoveParameterUp() {
		// remember first row (return type) and auto-params cannot be moved.
		int minRowToMoveUp = 2 + autoParamCount;
		if (parameters.size() > 0 && parameters.get(0).getName().equals("this")) {
			minRowToMoveUp++;
		}
		return selectedFunctionRows.length == 1 && selectedFunctionRows[0] >= minRowToMoveUp;
	}

	public boolean canMoveParameterDown() {
		if (selectedFunctionRows.length != 1) {
			return false;
		}
		// remember first row (return type) and auto-params cannot be moved.
		int minRowToMoveDown = 1 + autoParamCount;
		if (parameters.size() > 0 && parameters.get(0).getName().equals("this")) {
			minRowToMoveDown++;
		}
		int selectedRow = selectedFunctionRows[0];
		return selectedRow >= minRowToMoveDown && selectedRow < parameters.size();
	}

	public void setParameterName(ParamInfo param, String newName) {
		param.setName(newName);
		notifyDataChanged();
	}

	public boolean setParameterFormalDataType(ParamInfo param, DataType formalDataType) {
		boolean isReturn = (param.getOrdinal() == Parameter.RETURN_ORIDINAL);
		try {
			formalDataType = VariableUtilities.checkDataType(formalDataType, isReturn, 0, program);
		}
		catch (InvalidInputException e) {
			Msg.showError(this, null, "Invalid Data Type", e.getMessage());
			return false;
		}

		if (formalDataType.equals(param.getFormalDataType())) {
			return true;
		}

		param.setFormalDataType(formalDataType.clone(program.getDataTypeManager()));
		if (allowCustomStorage) {
			if (isReturn && (formalDataType instanceof VoidDataType)) {
				param.setStorage(VariableStorage.VOID_STORAGE);
			}
			else {
				VariableStorage curStorage = param.getStorage();
				int size = formalDataType.getLength();
				if (curStorage == VariableStorage.VOID_STORAGE) {
					param.setStorage(VariableStorage.UNASSIGNED_STORAGE);
				}
				else if (size > 0 && size != curStorage.size() &&
					curStorage.getVarnodeCount() == 1) {
					adjustStorageSize(param, curStorage, size);
				}
			}
		}
		else {
			updateParameterAndReturnStorage();
		}
		notifyDataChanged();
		return true;
	}

	private void adjustStorageSize(ParamInfo param, VariableStorage curStorage, int newSize) {
		Varnode varnode = curStorage.getVarnodes()[0];
		Address address = varnode.getAddress();
		if (address != null) {
			Register reg =
				VarnodeInfo.getRegister(program, varnode.getAddress(), varnode.getSize());
			if (reg != null) {
				Register baseReg = reg.getBaseRegister();
				if (newSize > baseReg.getMinimumByteSize()) {
					address = baseReg.getAddress();
					newSize = baseReg.getMinimumByteSize();
				}
				else if (baseReg.isBigEndian()) {
					// adjust big endian register address
					address = baseReg.getAddress().add(baseReg.getMinimumByteSize() - newSize);
				}
			}
			try {
				param.setStorage(new VariableStorage(program, address, newSize));
			}
			catch (InvalidInputException e) {
				// ignore
			}
		}
	}

	public VariableStorage getReturnStorage() {
		return returnInfo.getStorage();
	}

	public Function getFunction() {
		return function;
	}

	public void setReturnStorage(VariableStorage storage) {
		if (storage == null) {
			storage = VariableStorage.UNASSIGNED_STORAGE;
		}
		returnInfo.setStorage(storage);
		notifyDataChanged();
	}

	public void setParameterStorage(ParamInfo param, VariableStorage storage) {
		param.setStorage(storage);
		notifyDataChanged();
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

	private void removeExplicitThisParameter() {
		if (!allowCustomStorage &&
			CompilerSpec.CALLING_CONVENTION_thiscall.equals(callingConventionName)) {
			int thisIndex = findExplicitThisParameter();
			if (thisIndex >= 0) {
				parameters.remove(thisIndex); // remove explicit 'this' parameter
				adjustSelectionForRowRemoved(thisIndex);
			}
		}
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

	private boolean removeExplicitReturnStoragePtrParameter() {
		int index = findExplicitReturnStoragePtrParameter();
		if (index >= 0) {
			parameters.remove(index); // remove explicit '__return_storage_ptr__' parameter
			adjustSelectionForRowRemoved(index);
			return true;
		}
		return false;
	}

	private void revertIndirectParameter(ParamInfo param) {
		if (allowCustomStorage) {
			throw new AssertException(); // auto-storage mode only
		}
		DataType dt = param.getDataType();
		if (dt instanceof Pointer) {
			param.setFormalDataType(((Pointer) dt).getDataType());
			param.setStorage(VariableStorage.UNASSIGNED_STORAGE);
		}
	}

	/**
	 * Change custom storage enablement
	 * @param b enablement state
	 */
	public void setUseCustomizeStorage(boolean b) {
		if (b == allowCustomStorage) {
			return;
		}
		allowCustomStorage = b;
		if (!allowCustomStorage) {
			removeExplicitThisParameter();
			if (removeExplicitReturnStoragePtrParameter()) {
				revertIndirectParameter(returnInfo);
			}
			updateParameterAndReturnStorage();
		}
		else {
			switchToCustomStorage();
		}
		notifyDataChanged();
	}

	public boolean canCustomizeStorage() {
		return allowCustomStorage;
	}

	public boolean apply() {
		if (!modelChanged) {
			return true;
		}
		int id = program.startTransaction("Edit Function");
		try {
			return applyFunctionData();
		}
		finally {
			program.endTransaction(id, true);
		}
	}

	private boolean applyFunctionData() {

		try {

			if (!name.equals(function.getName())) {
				function.setName(name, SourceType.USER_DEFINED);
			}

			boolean paramsOrReturnModified = hasModifiedParametersOrReturn();
			if (!paramsOrReturnModified) {

				// change param names without impacting signature source
				for (ParamInfo paramInfo : parameters) {
					if (!paramInfo.isAutoParameter() && paramInfo.isNameModified()) {
						Parameter param = paramInfo.getOriginalParameter();
						if (param != null) {
							if (param.getSymbol().isDeleted()) {
								// concurrent removal of param - must do full update
								paramsOrReturnModified = true;
								break;
							}
							param.setName(paramInfo.getName(), SourceType.USER_DEFINED);
						}
					}
				}
			}

			if (paramsOrReturnModified) {
				List<Parameter> params = new ArrayList<>();
				for (ParamInfo paramInfo : parameters) {
					if (paramInfo.isAutoParameter()) {
						continue;
					}
					params.add(paramInfo.getParameter(allowCustomStorage));
				}

				// TODO: How should we handle conflicts with locals?
				function.updateFunction(callingConventionName,
					returnInfo.getParameter(allowCustomStorage), params,
					allowCustomStorage ? FunctionUpdateType.CUSTOM_STORAGE
							: FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
					true, SourceType.USER_DEFINED);
			}
			else {
				boolean changed = false;
				if (allowCustomStorage != function.hasCustomVariableStorage()) {
					function.setCustomVariableStorage(allowCustomStorage);
					changed = true;
				}
				if (!function.getCallingConventionName().equals(callingConventionName)) {
					try {
						function.setCallingConvention(callingConventionName);
					}
					catch (InvalidInputException e) {
						// user had to choose from list, so can't happen
						throw new AssertException("Unexpected exception", e);
					}
				}
				if (changed && function.getSignatureSource() == SourceType.DEFAULT &&
					parameters.size() == 0 &&
					!Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(callingConventionName)) {
					function.setSignatureSource(SourceType.USER_DEFINED);
				}
			}
		}
		catch (DuplicateNameException e) {
			Msg.showError(this, null, "Function Edit Error", e.getMessage());
			return false;
		}
		catch (InvalidInputException e) {
			Msg.showError(this, null, "Function Edit Error", e.getMessage());
			return false;
		}

		if (function.isInline() != isInLine) {
			function.setInline(isInLine);
		}

		if (function.hasVarArgs() != hasVarArgs) {
			function.setVarArgs(hasVarArgs);
		}

		if (function.hasNoReturn() != isNoReturn) {
			function.setNoReturn(isNoReturn);
		}

		String fixupName = callFixupName.equals(NONE_CHOICE) ? null : callFixupName;
		if (!SystemUtilities.isEqual(fixupName, function.getCallFixup())) {
			function.setCallFixup(fixupName);
		}

		return true;
	}

	Program getProgram() {
		return program;
	}

	DataTypeManagerService getDataTypeManagerService() {
		return dataTypeManagerService;
	}

	int getAutoParamCount() {
		return autoParamCount;
	}

	private boolean isSameSize(DataType dt1, DataType dt2) {
		if (dt1 == null || dt2 == null) {
			return false;
		}
		return dt1.getLength() == dt2.getLength();
	}

	public void setFunctionData(FunctionDefinitionDataType functionDefinition) {
		name = functionDefinition.getName();

		GenericCallingConvention genericCallingConvention =
			functionDefinition.getGenericCallingConvention();
		if (genericCallingConvention != null &&
			genericCallingConvention != GenericCallingConvention.unknown) {
			PrototypeModel matchConvention =
				function.getProgram().getCompilerSpec().matchConvention(genericCallingConvention);
			setCallingConventionName(matchConvention.getName());
		}

		if (!isSameSize(returnInfo.getFormalDataType(), functionDefinition.getReturnType())) {
			returnInfo.setStorage(VariableStorage.UNASSIGNED_STORAGE);
		}
		returnInfo.setFormalDataType(functionDefinition.getReturnType());

		List<ParamInfo> oldParams = parameters;
		parameters = new ArrayList<>();
		autoParamCount = 0;
		selectedFunctionRows = new int[0];

		for (ParameterDefinition paramDefinition : functionDefinition.getArguments()) {
			parameters.add(new ParamInfo(this, paramDefinition));
		}
		hasVarArgs = functionDefinition.hasVarArgs();
		fixupOrdinals();

		if (allowCustomStorage) {
			reconcileCustomStorage(oldParams, parameters);
		}
		else {
			updateParameterAndReturnStorage();
		}
		notifyDataChanged();
	}

	private void reconcileCustomStorage(List<ParamInfo> oldParams, List<ParamInfo> newParams) {
		Set<ParamInfo> oldMatches = new HashSet<>();
		Set<ParamInfo> newMatches = new HashSet<>();

		// first try to match names
		for (ParamInfo paramInfo : newParams) {
			ParamInfo oldInfo = findOldCustomInfoByNameAndDataTypeSize(oldParams,
				paramInfo.getName(), paramInfo.getDataType().getLength());
			if (oldInfo != null) {
				oldMatches.add(oldInfo);
				newMatches.add(paramInfo);
				paramInfo.setStorage(oldInfo.getStorage());
			}
		}
		// now match in order as long as datatype lengths are the same and we don't hit one that was already matched
		for (int i = 0; i < newParams.size() && i < oldParams.size(); i++) {
			ParamInfo oldInfo = oldParams.get(i);
			ParamInfo newInfo = newParams.get(i);
			if (oldMatches.contains(oldInfo) || newMatches.contains(newInfo)) {
				break;
			}
			if (!isSameSize(oldInfo.getDataType(), newInfo.getDataType())) {
				break;
			}
			newInfo.setStorage(oldInfo.getStorage());
		}

	}

	private ParamInfo findOldCustomInfoByNameAndDataTypeSize(List<ParamInfo> oldParams,
			String newParamName, int size) {
		for (ParamInfo paramInfo : oldParams) {
			if (paramInfo.getName().equals(newParamName)) {
				if (paramInfo.getDataType().getLength() == size) {
					return paramInfo;
				}
			}
		}
		return null;
	}

	public boolean isInParsingMode() {
		return isInParsingMode;
	}

	public void setSignatureFieldText(String text) {
		signatureFieldText = text;
		boolean signatureTextFieldInSync =
			signatureFieldText.equals(getFunctionSignatureTextFromModel());
		if (isInParsingMode == signatureTextFieldInSync) {
			isInParsingMode = !isInParsingMode;
			notifyDataChanged(false);
//			notifyParsingModeChanged();
		}
	}

	public void resetSignatureTextField() {
		setSignatureFieldText(getFunctionSignatureTextFromModel());
	}

	public boolean hasChanges() {
		return !Objects.equals(getFunctionSignatureTextFromModel(), signatureFieldText);
	}

	public void parseSignatureFieldText() throws ParseException, CancelledException {
		FunctionSignatureParser parser =
			new FunctionSignatureParser(program.getDataTypeManager(), dataTypeManagerService);
		FunctionDefinitionDataType f = parser.parse(function.getSignature(), signatureFieldText);

		setFunctionData(f);
		isInParsingMode = false;
	}

	public int getFunctionNameStartPosition() {
		return returnInfo.getFormalDataType().getName().length() + 1;
	}

	/**
	 * Sets the change state of the model. Normally, the model sets the modelChanged variable to true
	 * every time something is changed. This provides a way to for applications to make some initial changes
	 * but make the dialog think that nothing has changed.
	 * @param b the  new changeState for this model
	 */
	public void setModelChanged(boolean b) {
		modelChanged = b;
	}

}
