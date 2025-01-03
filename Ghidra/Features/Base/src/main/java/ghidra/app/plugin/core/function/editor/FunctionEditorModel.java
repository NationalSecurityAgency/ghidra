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
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.VariableUtilities.VariableConflictHandler;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.util.*;
import ghidra.util.exception.*;

public class FunctionEditorModel {
	public static final String PARSING_MODE_STATUS_TEXT = HTMLUtilities.HTML +
		HTMLUtilities.escapeHTML("<TAB> or <RETURN> to commit edits, <ESC> to abort");
	static final String NONE_CHOICE = "-NONE-";

	private FunctionData functionData;
	private FunctionDataView originalFunctionData;

	private String signatureFieldText;

	private ModelChangeListener listener;

	private Function function;
	private Program program;

	private List<ParamInfo> selectedParams = new ArrayList<>();

	private boolean isInParsingMode;

	private DataTypeManagerService dataTypeManagerService;

	private String statusText = "";
	private boolean isValid = true;
	private boolean isSignatureTransformed = false;
	private boolean hasSignificantParameterChanges = false;

	public FunctionEditorModel(DataTypeManagerService service, Function function) {
		this.dataTypeManagerService = service;
		this.function = function;
		this.program = function.getProgram();
		functionData = new FunctionData(function);
		this.originalFunctionData = new FunctionDataView(functionData);
		validate();
	}

	void setModelChangeListener(ModelChangeListener listener) {
		this.listener = listener;
	}

	boolean hasChanges() {
		return !functionData.equals(originalFunctionData);
	}

	boolean hasSignificantParameterChanges() {
		return hasSignificantParameterChanges;
	}

	// Returns the current calling convention or the default calling convention if current unknown

	List<String> getCallingConventionNames() {
		Collection<String> names =
			function.getProgram().getFunctionManager().getCallingConventionNames();
		List<String> list = new ArrayList<>(names);
		String callingConventionName = getCallingConventionName();
		if (callingConventionName != null && !names.contains(callingConventionName)) {
			list.add(callingConventionName);
			Collections.sort(list);
		}
		list.add(0, Function.DEFAULT_CALLING_CONVENTION_STRING);
		list.add(0, Function.UNKNOWN_CALLING_CONVENTION_STRING);
		return list;
	}

	String[] getCallFixupNames() {
		return program.getCompilerSpec().getPcodeInjectLibrary().getCallFixupNames();
	}

	void dispose() {
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
		validate();
		if (listener != null) {
			Swing.runLater(() -> listener.dataChanged());
		}
	}

	private void validate() {
		statusText = "";
		if (isSignatureTransformed) {
			statusText =
				"Signature transformed due to auto-params and/or forced-indirect storage change";
			isSignatureTransformed = false; // one-shot message
		}
		isValid =
			hasValidName() && hasValidReturnType() && hasValidReturnStorage() && hasValidParams();
		hasSignificantParameterChanges = false;
		if (isValid) {
			hasSignificantParameterChanges = functionData.hasParameterChanges(originalFunctionData);
			checkUnassignedStorage();
		}
	}

	private boolean hasValidReturnStorage() {

		if (!functionData.canCustomizeStorage()) {
			return true;
		}

		ParamInfo returnInfo = functionData.getReturnInfo();
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
		return true;
	}

	private void checkUnassignedStorage() {

		ParamInfo returnInfo = functionData.getReturnInfo();
		VariableStorage returnStorage = returnInfo.getStorage();
		DataType returnType = returnInfo.getFormalDataType();

		boolean hasUnassignedStorage = returnStorage != null && returnStorage.isUnassignedStorage();

		if (!hasUnassignedStorage) {
			for (ParamInfo param : functionData.getParameters()) {
				if (param.getStorage().isUnassignedStorage()) {
					hasUnassignedStorage = true;
					break;
				}
			}
		}

		if (hasUnassignedStorage) {
			statusText = "Warning: Return Storage and/or Parameter Storage is Unassigned";
		}
		else if (!functionData.canCustomizeStorage() && Function.UNKNOWN_CALLING_CONVENTION_STRING
				.equals(functionData.getCallingConventionName())) {
			if (!(VoidDataType.isVoidDataType(returnType) && !functionData.hasParameters())) {
				statusText =
					"Warning: No calling convention specified. Ghidra may automatically assign one later.";
			}
		}

	}

	private boolean hasValidParams() {
		for (ParamInfo param : functionData.getParameters()) {
			if (!(isValidParamType(param) && isValidParamName(param) && isValidStorage(param))) {
				return false;
			}
		}
		return hasNonConflictingStorage();
	}

	private void clearStorageConflicts() {
		for (ParamInfo p : functionData.getParameters()) {
			p.setHasStorageConflict(false);
		}
	}

	private void setStorageConflict(int ordinal) {
		for (ParamInfo p : functionData.getParameters()) {
			if (p.getOrdinal() == ordinal) {
				p.setHasStorageConflict(true);
			}
		}
	}

	private boolean hasNonConflictingStorage() {
		clearStorageConflicts();
		if (!functionData.canCustomizeStorage()) {
			return true;
		}
		ArrayList<Parameter> params = new ArrayList<>();
		for (ParamInfo paramInfo : functionData.getParameters()) {
			params.add(paramInfo.getParameter(SourceType.USER_DEFINED));
		}
		for (Parameter p : params) {
			if (identifyStorageConflicts(p, params)) {
				statusText = "One or more parameter storage conflicts exist";
				return false;
			}
		}
		return true;
	}

	/**
	 * Scan the list of function parameters for those whose storage conflicts with the specified
	 * parameter.
	 * @param p parameter whose storage should be examined for conflict with others
	 * @param params list of function parameters to search
	 * @return true if storage conflict detected, else false
	 */
	private boolean identifyStorageConflicts(Parameter p, ArrayList<Parameter> params) {
		try {
			VariableUtilities.checkVariableConflict(params, p, p.getVariableStorage(),
				conflicts -> handleConflicts(conflicts));
		}
		catch (VariableSizeException e) {
			// This exception occurs when any parameter storage conflict is detected/
			// Mark the tested parameter as being in conflict.
			setStorageConflict(p.getOrdinal());
			return true;
		}
		return false;
	}

	/**
	 * Mark all storage conflicts identified by
	 * {@link VariableUtilities#checkVariableConflict(List, Variable, VariableStorage, VariableConflictHandler)}
	 * @param conflicts parameters whose storage conflicts
	 * @return return false to indicate conflicts have not been resolved and additional checks
	 * should be disconctinued.
	 * @see VariableConflictHandler
	 */
	private boolean handleConflicts(List<Variable> conflicts) {
		conflicts.forEach(var -> setStorageConflict(((Parameter) var).getOrdinal()));
		return false;
	}

	private boolean isValidStorage(ParamInfo param) {
		if (!functionData.canCustomizeStorage()) {
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

		int paramSize = datatype.getLength();

		if (storageSize < paramSize) {
			statusText = "Insufficient storage (" + storageSize + "-bytes) for datatype (" +
				paramSize + "-bytes) assigned to parameter " + (param.getOrdinal() + 1);
			return false;
		}
//		else if (paramSize == 0) {
//			// assume 0-sized structure which we need to allow
//		}
//		else if (storageSize > paramSize && storageSize <= 8 && paramSize <= 8 &&
//			Undefined.isUndefined(param.getDataType())) {
//			// grow undefined type size if needed
//			param.setFormalDataType(Undefined.getUndefinedDataType(storageSize));
//		}
		return true;
	}

	boolean hasValidName() {
		String name = functionData.getName();
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

	private boolean hasValidReturnType() {
		DataType returnType = functionData.getReturnInfo().getDataType();
		if (VoidDataType.isVoidDataType(returnType)) {
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
		for (ParamInfo info : functionData.getParameters()) {
			if (info != param && info.getName().equals(paramName)) {
				statusText = "Duplicate parameter name: " + paramName;
				return false;
			}
		}
		return true;
	}

	private boolean isValidParamType(ParamInfo param) {
		DataType dataType = param.getDataType();
		if (VoidDataType.isVoidDataType(dataType)) {
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

	boolean isValid() {
		return isValid;
	}

	String getStatusText() {
		if (isInParsingMode) {
			return PARSING_MODE_STATUS_TEXT;
		}
		return statusText;
	}

	boolean isInlineAllowed() {
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

	String getFunctionSignatureTextFromModel() {
		return functionData.getFunctionSignatureText();
	}

	String getNameString() {
		return functionData.getNameString();
	}

	String getName() {
		return functionData.getName();
	}

	void setName(String name) {
		if (getName().equals(name)) {
			return;
		}
		functionData.setName(name.trim());
		notifyDataChanged();
	}

	String getCallingConventionName() {
		return functionData.getCallingConventionName();
	}

	public void setCallingConventionName(String callingConventionName) {
		if (Objects.equals(getCallingConventionName(), callingConventionName)) {
			return;
		}
		functionData.setCallingConventionName(callingConventionName);
		notifyDataChanged();
	}

	boolean hasVarArgs() {
		return functionData.hasVarArgs();
	}

	void setHasVarArgs(boolean b) {
		if (b == hasVarArgs()) {
			return;
		}
		functionData.setVarArgs(b);
		notifyDataChanged();
	}

	DataType getReturnType() {
		return functionData.getReturnInfo().getDataType();
	}

	DataType getFormalReturnType() {
		return functionData.getReturnInfo().getFormalDataType();
	}

	public boolean setFormalReturnType(DataType formalReturnType) {
		return setParameterFormalDataType(functionData.getReturnInfo(), formalReturnType);
	}

	boolean isInLine() {
		return functionData.isInline();
	}

	void setIsInLine(boolean isInLine) {
		if (isInLine == functionData.isInline()) {
			return;
		}
		functionData.setInline(isInLine);
		if (isInLine && functionData.hasCallFixup()) {
			functionData.clearCallFixup();
		}
		notifyDataChanged();
	}

	boolean isNoReturn() {
		return functionData.hasNoReturn();
	}

	void setNoReturn(boolean hasNoReturn) {
		if (hasNoReturn == functionData.hasNoReturn()) {
			return;
		}
		functionData.setHasNoReturn(hasNoReturn);
		notifyDataChanged();
	}

	String getCallFixupChoice() {
		String fixupName = functionData.getCallFixupName();
		return fixupName == null ? NONE_CHOICE : fixupName;
	}

	void setCallFixupChoice(String callFixupName) {
		if (callFixupName.equals(getCallFixupChoice())) {
			return;
		}
		if (NONE_CHOICE.equals(callFixupName)) {
			callFixupName = null;
		}
		functionData.setCallFixupName(callFixupName);
		if (isInLine() && functionData.hasCallFixup()) {
			functionData.setInline(false);
		}
		notifyDataChanged();
	}

	public void setSelectedParameterRows(int[] selectedRows) {
		selectedParams.clear();
		List<ParamInfo> parameters = functionData.getParameters();
		for (int i : selectedRows) {
			ParamInfo p;
			if (i == 0) {
				p = functionData.getReturnInfo();
			}
			else {
				p = parameters.get(i - 1);
			}
			selectedParams.add(p);
		}
		Collections.sort(selectedParams);
		notifyDataChanged();
	}

	private ParamInfo getSelectedParam() {
		return selectedParams.iterator().next();
	}

	private void setSelectedParam(ParamInfo p) {
		selectedParams.clear();
		selectedParams.add(p);
	}

	int[] getSelectedParameterRows() {
		List<Integer> list = new ArrayList<>();
		for (ParamInfo p : selectedParams) {
			list.add(p.getOrdinal() + 1);
		}
		Collections.sort(list);
		int[] selectedRows = new int[list.size()];
		for (int i = 0; i < selectedRows.length; i++) {
			selectedRows[i] = list.get(i);
		}
		return selectedRows;
	}

	void addParameter() {
		if (listener != null) {
			listener.tableRowsChanged();
		}
		ParamInfo p = functionData.addNewParameter();
		setSelectedParam(p);
		notifyDataChanged();
	}

	public void removeParameters() {
		if (!canRemoveParameters()) {
			throw new AssertException("Attempted to remove parameters when not allowed.");
		}
		if (listener != null) {
			listener.tableRowsChanged();
		}
		int ordinal = selectedParams.get(0).getOrdinal();
		functionData.removeParameters(selectedParams);
		selectedParams.clear();
		ParamInfo selectParam = null;
		for (ParamInfo p : functionData.getParameters()) {
			selectParam = p;
			if (ordinal == p.getOrdinal()) {
				break;
			}
		}
		if (selectParam != null) {
			setSelectedParam(selectParam);
		}
		notifyDataChanged();
	}

	void moveSelectedParameterUp() {
		if (!canMoveParameterUp()) {
			throw new AssertException("Attempted to move parameters up when not allowed.");
		}
		if (listener != null) {
			listener.tableRowsChanged();
		}
		ParamInfo p = getSelectedParam();
		functionData.moveParameterUp(p.getOrdinal());
		notifyDataChanged();
	}

	void moveSelectedParameterDown() {
		if (!canMoveParameterDown()) {
			throw new AssertException("Attempted to move parameters down when not allowed.");
		}
		if (listener != null) {
			listener.tableRowsChanged();
		}
		ParamInfo p = getSelectedParam();
		functionData.moveParameterDown(p.getOrdinal());
		notifyDataChanged();
	}

	// TODO: Exposing this method is inappropriate
	public List<ParamInfo> getParameters() {
		return functionData.getParameters();
	}

	boolean canRemoveParameters() {
		if (selectedParams.size() == 0) {
			return false;
		}
		for (ParamInfo p : selectedParams) {
			if (p.isAutoParameter() || p.isReturnParameter()) {
				return false;
			}
		}
		return true;
	}

	boolean canMoveParameterUp() {
		if (selectedParams.size() != 1) {
			return false;
		}
		ParamInfo p = selectedParams.iterator().next();
		if (p.getOrdinal() <= getAutoParamCount()) {
			return false;
		}
		return true;
	}

	boolean canMoveParameterDown() {
		if (selectedParams.size() != 1) {
			return false;
		}
		ParamInfo p = selectedParams.iterator().next();
		if (p.getOrdinal() < getAutoParamCount() || p.getOrdinal() >= (getParamCount() - 1)) {
			return false;
		}
		if (canUseCustomStorage() && functionData.hasParameters()) {
			List<ParamInfo> parameters = getParameters();
			if ("this".equals(parameters.get(0).getName())) {
				return false;
			}
		}
		return true;
	}

	void setParameterName(ParamInfo param, String newName) {
		param.setName(newName);
		notifyDataChanged();
	}

	boolean setParameterFormalDataType(ParamInfo param, DataType formalDataType) {
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

		if (canUseCustomStorage()) {
			if (isReturn && VoidDataType.isVoidDataType(formalDataType)) {
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
			functionData.updateParameterAndReturnStorage();
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

	VariableStorage getReturnStorage() {
		return functionData.getReturnInfo().getStorage();
	}

	Function getFunction() {
		return function;
	}

	public void setReturnStorage(VariableStorage storage) {
		if (storage == null) {
			storage = VariableStorage.UNASSIGNED_STORAGE;
		}
		if (storage.equals(getReturnStorage())) {
			return;
		}
		functionData.getReturnInfo().setStorage(storage);
		notifyDataChanged();
	}

	// TODO: Exposing this method is inappropriate
	public void setParameterStorage(ParamInfo param, VariableStorage storage) {
		if (storage == null) {
			storage = VariableStorage.UNASSIGNED_STORAGE;
		}
		if (storage.equals(param.getStorage())) {
			return;
		}
		param.setStorage(storage);
		notifyDataChanged();
	}

	/**
	 * Change custom storage enablement
	 * @param b enablement state
	 */
	public void setUseCustomizeStorage(boolean b) {
		if (b == canUseCustomStorage()) {
			return;
		}
		functionData.setUseCustomStorage(b);
		isSignatureTransformed = !functionData.getFunctionSignatureText()
				.equals(originalFunctionData.getFunctionSignatureText());
		notifyDataChanged();
	}

	public boolean canUseCustomStorage() {
		return functionData.canCustomizeStorage();
	}

	boolean apply() {
		return apply(true);
	}

	boolean apply(boolean commitFullParamDetails) {
		int id = program.startTransaction("Edit Function");
		try {
			if (applyFunctionData(commitFullParamDetails)) {
				setModelUnchanged();
				return true;
			}
			return false;
		}
		finally {
			program.endTransaction(id, true);
		}
	}

	private boolean applyFunctionData(boolean commitFullParamDetails) {

		try {

			String name = functionData.getName();
			if (!name.equals(function.getName())) {
				function.setName(name, SourceType.USER_DEFINED);
			}

			boolean isInline = functionData.isInline();
			if (function.isInline() != isInline) {
				function.setInline(isInline);
			}

			boolean hasNoReturn = functionData.hasNoReturn();
			if (function.hasNoReturn() != hasNoReturn) {
				function.setNoReturn(hasNoReturn);
			}

			String fixupName = functionData.getCallFixupName();
			if (!SystemUtilities.isEqual(fixupName, function.getCallFixup())) {
				function.setCallFixup(fixupName);
			}

			boolean hasVarArgs = hasVarArgs();
			if (function.hasVarArgs() != hasVarArgs) {
				function.setVarArgs(hasVarArgs);
			}

			String callingConventionName = functionData.getCallingConventionName();
			boolean isCallingConventionChanged =
				!Objects.equals(callingConventionName, originalFunctionData.callingConventionName);

			boolean useCustomStorage = functionData.canCustomizeStorage();

			if (!commitFullParamDetails) {

				// Partial commit without return/parameter details - no need for source type change

				if (useCustomStorage != function.hasCustomVariableStorage()) {
					function.setCustomVariableStorage(useCustomStorage);
				}

				if (isCallingConventionChanged) {
					function.setCallingConvention(callingConventionName);
				}

				if (!hasSignificantParameterChanges &&
					functionData.hasParameterNamesChanged(originalFunctionData)) {

					for (ParamInfo paramInfo : functionData.getParameters()) {
						Parameter param = function.getParameter(paramInfo.getOrdinal());
						if (param != null) {
							if (param.getSymbol().isDeleted()) {
								// concurrent removal of param - must do full update
								break;
							}
							param.setName(paramInfo.getName(), SourceType.USER_DEFINED);
						}
					}
				}

				return true;
			}

			SourceType sigSource =
				hasSignificantParameterChanges ? SourceType.USER_DEFINED : SourceType.ANALYSIS;

			SymbolTable symbolTable = program.getSymbolTable();

			List<Parameter> params = new ArrayList<>();
			for (ParamInfo paramInfo : functionData.getParameters()) {
				if (paramInfo.isAutoParameter()) {
					continue;
				}
				SourceType source = SourceType.USER_DEFINED;
				Symbol var = symbolTable.getLocalVariableSymbol(paramInfo.getName(), function);
				if (var instanceof Parameter) {
					source = var.getSource();
				}
				params.add(paramInfo.getParameter(source));
			}

			// TODO: How should we handle conflicts with locals?
			function.updateFunction(callingConventionName,
				functionData.getReturnInfo().getParameter(SourceType.DEFAULT), params,
				useCustomStorage ? FunctionUpdateType.CUSTOM_STORAGE
						: FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
				true, sigSource);
		}
		catch (DuplicateNameException e) {
			Msg.showError(this, null, "Function Edit Error", e.getMessage());
			return false;
		}
		catch (InvalidInputException e) {
			Msg.showError(this, null, "Function Edit Error", e.getMessage());
			return false;
		}

		return true;
	}

	private FunctionSignature getFunctionSignature() {
		FunctionDefinitionDataType funDt = new FunctionDefinitionDataType(getName());
		funDt.setReturnType(getFormalReturnType());
		List<ParameterDefinition> params = new ArrayList<>();

		for (ParamInfo paramInfo : getParameters()) {
			if (paramInfo.isAutoParameter()) {
				continue;
			}
			String paramName = paramInfo.getName();
			DataType paramDt = paramInfo.getFormalDataType();
			params.add(new ParameterDefinitionImpl(paramName, paramDt, null));
		}
		funDt.setArguments(params.toArray(new ParameterDefinition[params.size()]));
		funDt.setVarArgs(hasVarArgs());
		return funDt;
	}

	Program getProgram() {
		return program;
	}

	DataTypeManagerService getDataTypeManagerService() {
		return dataTypeManagerService;
	}

	int getAutoParamCount() {
		return functionData.getAutoParamCount();
	}

	int getParamCount() {
		return functionData.getParamCount();
	}

	private boolean isSameSize(DataType dt1, DataType dt2) {
		if (dt1 == null || dt2 == null) {
			return false;
		}
		return dt1.getLength() == dt2.getLength();
	}

	public void setFunctionData(FunctionDefinitionDataType functionDefinition) {

		setName(functionDefinition.getName());

		setCallingConventionName(functionDefinition.getCallingConventionName());

		DataType returnDt = functionDefinition.getReturnType();
		setFormalReturnType(returnDt);

		List<ParamInfo> oldParams = new ArrayList<>(getParameters());

		functionData.removeAllParameters();

		List<ParamInfo> parameters = functionData.getParameters();
		for (ParameterDefinition paramDefinition : functionDefinition.getArguments()) {
			parameters.add(new ParamInfo(functionData, paramDefinition));
		}

		setHasVarArgs(functionDefinition.hasVarArgs());

		functionData.fixupOrdinals();

		if (canUseCustomStorage()) {
			if (VoidDataType.isVoidDataType(returnDt)) {
				setReturnStorage(VariableStorage.VOID_STORAGE);
			}
			else if (!isSameSize(getFormalReturnType(), functionDefinition.getReturnType())) {
				setReturnStorage(VariableStorage.UNASSIGNED_STORAGE);
			}
			reconcileCustomStorage(oldParams, parameters);
		}

		selectedParams.clear();

		functionData.updateParameterAndReturnStorage();

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

	boolean isInParsingMode() {
		return isInParsingMode;
	}

	void setSignatureFieldText(String text) {
		signatureFieldText = text;
		boolean signatureTextFieldInSync =
			signatureFieldText.equals(getFunctionSignatureTextFromModel());
		if (isInParsingMode == signatureTextFieldInSync) {
			isInParsingMode = !isInParsingMode;
			notifyDataChanged();
		}
	}

	void resetSignatureTextField() {
		setSignatureFieldText(getFunctionSignatureTextFromModel());
	}

	boolean hasSignatureTextChanges() {
		return !Objects.equals(getFunctionSignatureTextFromModel(), signatureFieldText);
	}

	void parseSignatureFieldText() throws ParseException, CancelledException {
		FunctionSignatureParser parser =
			new FunctionSignatureParser(program.getDataTypeManager(), dataTypeManagerService);
		FunctionDefinitionDataType f = parser.parse(getFunctionSignature(), signatureFieldText);

		// Preserve calling convention and noreturn flag from current model
		f.setNoReturn(functionData.hasNoReturn());
		try {
			f.setCallingConvention(getCallingConventionName());
		}
		catch (InvalidInputException e) {
			// ignore
		}

		setFunctionData(f);
		isInParsingMode = false;
	}

	int getFunctionNameStartPosition() {
		return getFormalReturnType().getName().length() + 1;
	}

	/**
	 * Sets the change state of the model to unchanged. Normally, the model sets the modelChanged
	 * variable to true every time something is changed. This provides a way to for applications
	 * to make some initial changes but make the dialog think that nothing has changed.
	 */
	public void setModelUnchanged() {
		originalFunctionData = new FunctionDataView(functionData);
		resetSignatureTextField();
		validate();
		if (listener != null) {
			Swing.runLater(() -> listener.dataChanged());
		}
	}

}
