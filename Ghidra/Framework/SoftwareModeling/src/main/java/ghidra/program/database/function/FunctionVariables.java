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
package ghidra.program.database.function;

import static ghidra.program.util.FunctionChangeRecord.FunctionChangeType.*;

import java.util.*;

import ghidra.program.database.ProgramDB;
import ghidra.program.database.symbol.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;

class FunctionVariables {
	private Map<SymbolDB, VariableDB> symbolMap;
	private ReturnParameterDB returnParam;
	private List<AutoParameterImpl> autoParams;
	private List<ParameterDB> params;
	private List<VariableDB> locals;

	/**
	 * foundBadVariables is set true when one or more variable symbols are found
	 * which no longer decode a valid storage address (indicated by Address.NO_ADDRESS).
	 * Any time a variable is added while this flag is set, such bad variables should be purged.
	 */
	private boolean foundBadVariables;
	/**
	 * Use of stack frame to compute parameter ordinals and validate stack offsets
	 * should not be done while <code>validateEnabled</code> is false.  This may be
	 * necessary during a language upgrade in which case a dummy compiler-spec
	 * may be in-use.
	 */
	private boolean validateEnabled = true;

	FunctionVariables(FunctionDB function, boolean hasCustomStorage) {
		loadSymbolBasedVariables(function);
		loadReturn(function, hasCustomStorage);
		if (foundBadVariables) {
			Msg.warn(this,
				"Found one or more bad variables in function " + function.getName() + " at " +
					function.getEntryPoint());
		}
		if (!hasCustomStorage) {
			updateParametersAndReturn(function, hasCustomStorage); // assign dynamic storage (includes return and auto-params)
		}
	}

	ReturnParameterDB getReturnParam() {
		return returnParam;
	}

	private boolean loadSymbolBasedVariables(FunctionDB function) {
		if (symbolMap != null) {
			return false;
		}
		symbolMap = new HashMap<>();
		locals = new ArrayList<>();
		params = new ArrayList<>();
		autoParams = null;
		Symbol functionSymbol = function.getSymbol();
		SymbolIterator it = function.getProgram().getSymbolTable().getChildren(functionSymbol);
		while (it.hasNext()) {
			SymbolDB s = (SymbolDB) it.next();
			if (s instanceof VariableSymbolDB) {
				VariableSymbolDB varSym = (VariableSymbolDB) s;
				if (isBadVariable(varSym)) {
					// silently ignore bad variable if address no longer decodes
					// This can happen due to changes in stack address space dimensions
					// TODO: it would be nice to cleanup such bad variables
					foundBadVariables = true;
					continue;
				}
				if (s.getSymbolType() == SymbolType.PARAMETER) {
					ParameterDB p = new ParameterDB(function, s);
					symbolMap.put(s, p);
					params.add(p);
				}
				else {
					VariableDB var = new LocalVariableDB(function, s);
					symbolMap.put(s, var);
					locals.add(var);
				}
			}
		}
		Collections.sort(params);
		Collections.sort(locals);
		return true;
	}

	/**
	 * Update parameter ordinals and re-assign dynamic parameter storage
	 * NOTE: loadVariables must have been called first
	 */
	void updateParametersAndReturn(FunctionDB function, boolean hasCustomStorage) {

		if (hasCustomStorage) {
			autoParams = null;
			renumberParameterOrdinals();
			return;
		}

		DataType[] dataTypes = new DataType[params.size() + 1];

		for (int i = 0; i < params.size(); i++) {
			ParameterDB param = params.get(i);
			param.setDynamicStorage(VariableStorage.UNASSIGNED_STORAGE);
			dataTypes[i + 1] = param.getDataType();
		}

		dataTypes[0] = returnParam.getFormalDataType();
		returnParam.setDynamicStorage(
			VoidDataType.isVoidDataType(dataTypes[0]) ? VariableStorage.VOID_STORAGE
					: VariableStorage.UNASSIGNED_STORAGE);

		PrototypeModel callingConvention = function.getCallingConvention();
		if (callingConvention == null) {
			callingConvention = function.getFunctionManager().getDefaultCallingConvention();
		}
		if (callingConvention == null) {
			return;
		}

		VariableStorage[] variableStorage =
			callingConvention.getStorageLocations(function.getProgram(), dataTypes, true);
		returnParam.setDynamicStorage(variableStorage[0]);

		int autoIndex = 0;
		int paramIndex = 0;

		autoParams = null;

		for (int i = 1; i < variableStorage.length; i++) {
			VariableStorage storage = variableStorage[i];
			if (storage.isAutoStorage()) {
				if (autoParams == null) {
					autoParams = new ArrayList<>();
				}
				DataType dt = VariableUtilities.getAutoDataType(function,
					returnParam.getFormalDataType(), storage);
				try {
					autoParams.add(new AutoParameterImpl(dt, autoIndex++, storage, function));
				}
				catch (InvalidInputException e) {
					Msg.error(this,
						"Unexpected error during dynamic storage assignment for function at " +
							function.getEntryPoint(),
						e);
					break;
				}
			}
			else {
				ParameterDB parameterDB = params.get(paramIndex++);
				parameterDB.setDynamicStorage(storage);
			}
		}

		renumberParameterOrdinals();
	}

	private boolean loadReturn(FunctionDB function, boolean hasCustomStorage) {
		DataType dt = function.getReturnDataType();
		VariableStorage returnStorage = function.getReturnStorage(hasCustomStorage);
		if (returnStorage.isBadStorage()) {
			foundBadVariables = true;
		}
		returnParam = new ReturnParameterDB(function, dt, returnStorage);
		return true;
	}

	private void renumberParameterOrdinals() {
		int autoParamCount = getAutoParamCount();
		int ordinal = autoParamCount;

		for (ParameterDB param : params) {
			param.setOrdinal(ordinal++, autoParamCount);
		}
	}

	int getAutoParamCount() {
		return autoParams != null ? autoParams.size() : 0;
	}

	Variable[] getLocalVariables(VariableFilter filter) {
		ArrayList<Variable> list = new ArrayList<>();
		for (VariableDB var : locals) {
			if (filter == null || filter.matches(var)) {
				list.add(var);
			}
		}
		Variable[] vars = new Variable[list.size()];
		return list.toArray(vars);
	}

	Variable[] getVariables(VariableFilter filter) {
		ArrayList<Variable> list = new ArrayList<>();
		if (autoParams != null) {
			for (AutoParameterImpl p : autoParams) {
				if (filter == null || filter.matches(p)) {
					list.add(p);
				}
			}
		}
		for (ParameterDB p : params) {
			if (filter == null || filter.matches(p)) {
				list.add(p);
			}
		}
		for (VariableDB var : locals) {
			if (filter == null || filter.matches(var)) {
				list.add(var);
			}
		}
		Variable[] vars = new Variable[list.size()];
		return list.toArray(vars);

	}

	private static boolean isBadVariable(VariableSymbolDB varSym) {
		return varSym.getAddress() == Address.NO_ADDRESS ||
			varSym.getVariableStorage().isBadStorage();
	}

	private void purgeBadVariables(FunctionDB function) {
		if (!foundBadVariables) {
			return;
		}
		Program program = function.getProgram();
		List<Symbol> badSymbols = new ArrayList<>();
		SymbolIterator it = program.getSymbolTable().getChildren(function.getSymbol());
		while (it.hasNext()) {
			SymbolDB s = (SymbolDB) it.next();
			if (s instanceof VariableSymbolDB) {
				VariableSymbolDB varSym = (VariableSymbolDB) s;
				if (isBadVariable(varSym)) {
					badSymbols.add(s);
				}
			}
		}
		program.getBookmarkManager()
				.setBookmark(function.getEntryPoint(), BookmarkType.ERROR, "Bad Variables Removed",
					"Removed " + badSymbols.size() + " bad variables");
		for (Symbol s : badSymbols) {
			s.delete();
		}
		if (function.hasCustomVariableStorage()) {
			ReturnParameterDB rtnParam = getReturnParam();
			if (rtnParam.getVariableStorage().isBadStorage()) {
				DataType dt = rtnParam.getDataType();
				VariableStorage storage =
					VoidDataType.isVoidDataType(dt) ? VariableStorage.VOID_STORAGE
							: VariableStorage.UNASSIGNED_STORAGE;
				rtnParam.setStorageAndDataType(storage, dt);
			}
		}
		foundBadVariables = false;
	}

	Parameter[] getParameters(VariableFilter filter) {
		ArrayList<Parameter> list = new ArrayList<>();
		if (autoParams != null) {
			for (AutoParameterImpl p : autoParams) {
				if (filter == null || filter.matches(p)) {
					list.add(p);
				}
			}
		}
		for (ParameterDB p : params) {
			if (filter == null || filter.matches(p)) {
				list.add(p);
			}
		}
		Parameter[] vars = new Parameter[list.size()];
		return list.toArray(vars);
	}

	VariableDB addLocalVariable(FunctionDB function, Variable var, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		purgeBadVariables(function);

		var = getResolvedVariable(function, var, false, false);

		String name = var.getName();
		if (name == null || name.length() == 0 ||
			SymbolUtilities.isDefaultParameterName(name)) {
			name = Function.DEFAULT_LOCAL_PREFIX;
			source = SourceType.DEFAULT;
		}

		VariableStorage storage = var.getVariableStorage();
		int firstUseOffset = var.getFirstUseOffset();
		if (var.hasStackStorage() && firstUseOffset != 0) {
			Msg.info(this, "WARNING! Stack variable firstUseOffset forced to 0 for function " +
				this + " at " + storage);
			firstUseOffset = 0;
		}

		// Check for duplicate storage address
		VariableDB v = null;
		for (VariableDB oldVar : locals) {
			if (oldVar.getFirstUseOffset() == firstUseOffset &&
				oldVar.getVariableStorage().intersects(storage)) {
				v = oldVar;
				break;
			}
		}

		try {
			if (validateEnabled) {
				VariableUtilities.checkVariableConflict(function, (v != null ? v : var), storage,
					true);
			}
			if (v != null) {
				// update existing variable
				Msg.info(this, "WARNING! Adding overlapping local variable for function " +
					this + " at " + v.getVariableStorage() + " - Modifying existing variable!");
				if (!Function.DEFAULT_LOCAL_PREFIX.equals(name)) {
					v.setName(name, source);
				}
				v.setStorageAndDataType(storage, var.getDataType());
			}
			else {
				SymbolManager symbolMgr = function.getProgram().getSymbolTable();
				VariableSymbolDB s = symbolMgr.createVariableSymbol(name, function,
					SymbolType.LOCAL_VAR, firstUseOffset, storage, source);
				s.setStorageAndDataType(storage, var.getDataType());
				v = new LocalVariableDB(function, s);
				locals.add(v);
				Collections.sort(locals);
				symbolMap.put(v.symbol, v);
			}
			if (var.getComment() != null) {
				v.symbol.setSymbolComment(var.getComment());
			}
			function.functionChanged(null);
			return v;
		}
		finally {
			function.invalidateFrame();
		}
	}

	/**
	 * Resolve a variable's type and storage.
	 * @param var variable to be resolved
	 * @param voidOK if true the use of a 0-length {@link VoidDataType} for the specified
	 * variable is allowed (i.e., {@link ReturnParameterDB}), else false should be specified.
	 * @param useUnassignedStorage if true storage should be set to {@link VariableStorage#UNASSIGNED_STORAGE}
	 * else an attempt should be made to adjust the storage.
	 * @return resolved variable
	 * @throws InvalidInputException if unable to resize variable storage due to
	 * resolved datatype size change
	 */
	Variable getResolvedVariable(FunctionDB function, Variable var, boolean voidOK,
			boolean useUnassignedStorage)
			throws InvalidInputException {
		Program program = function.getProgram();
		DataType dt = var.getDataType();
		if (var instanceof Parameter) {
			dt = ((Parameter) var).getFormalDataType();
		}
		dt = VariableUtilities.checkDataType(dt, voidOK, Math.min(1, var.getLength()), program);
		DataType resolvedDt = program.getDataTypeManager().resolve(dt, null);
		VariableStorage storage = VariableStorage.UNASSIGNED_STORAGE;
		if (!useUnassignedStorage) {
			storage = var.getVariableStorage();
			if (storage.isAutoStorage()) {
				storage = new VariableStorage(program, storage.getVarnodes());
			}
			if (resolvedDt.getLength() != storage.size()) {
				try {
					storage = VariableUtilities.resizeStorage(storage, resolvedDt, true, function);
				}
				catch (Exception e) {
					// ignore sizing issues
				}
			}
		}

		LocalVariableImpl resolvedVar = new LocalVariableImpl(var.getName(),
			var.getFirstUseOffset(), resolvedDt, storage, true, program, var.getSource());
		resolvedVar.setComment(var.getComment());
		return resolvedVar;
	}

	void setValidataionEnabled(boolean state) {
		validateEnabled = state;
	}

	int getParameterCount() {
		int count = params.size();
		if (autoParams != null) {
			count += autoParams.size();
		}
		return count;
	}

	void updateFunction(FunctionDB function, String callingConvention,
			Variable returnVar, List<? extends Variable> newParams, FunctionUpdateType updateType,
			boolean force, SourceType source) throws DuplicateNameException, InvalidInputException {

		if (returnVar == null) {
			returnVar = returnParam;
		}
		else if (returnVar.isUniqueVariable()) {
			throw new IllegalArgumentException(
				"Invalid return specified: UniqueVariable not allowed");
		}
		ProgramDB program = function.getProgram();
		boolean useCustomStorage = function.hasCustomVariableStorage();
		DataType returnType = returnVar.getDataType();
		VariableStorage returnStorage = returnVar.getVariableStorage();

		if (!function.hasCustomVariableStorage()) {
			// remove auto params and forced-indirect return
			newParams = new ArrayList<Variable>(newParams); // copy for edit
			boolean thisParamRemoved = removeExplicitThisParameter(newParams, callingConvention);
			DataType dt = removeExplicitReturnStoragePtrParameter(newParams);
			if (dt != null) {
				returnVar = revertIndirectParameter(returnVar, dt, true);
			}
			if (returnVar instanceof Parameter) {
				returnType = ((Parameter) returnVar).getFormalDataType();
			}
			returnStorage = VariableStorage.UNASSIGNED_STORAGE;

			if (updateType == FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS &&
				!thisParamRemoved &&
				CompilerSpec.CALLING_CONVENTION_thiscall.equals(callingConvention) &&
				newParams.size() != 0) {
				// Attempt to remove inferred unnamed 'this' parameter
				// WARNING! This is a bit of a hack - not sure how to account for what may be auto-params
				// within a list of parameters computed via analysis
				Variable firstParam = newParams.get(0);
				if (firstParam.getSource() == SourceType.DEFAULT &&
					firstParam.getLength() == program.getDefaultPointerSize()) {
					newParams.remove(0);
				}
			}
		}

		// Update return data type
		returnParam.setDataType(returnType, returnStorage, true, source);

		Set<String> nonParamNames = new HashSet<>();
		for (Symbol s : program.getSymbolTable().getSymbols(function)) {
			if (s.getSource() != SourceType.DEFAULT &&
				s.getSymbolType() != SymbolType.PARAMETER) {
				nonParamNames.add(s.getName());
			}
		}

		// Must ensure that all names do not conflict and that variable types are
		// resolved to this program so that they have the proper sizes
		List<Variable> clonedParams = new ArrayList<>();
		for (int i = 0; i < newParams.size(); i++) {
			Variable p = newParams.get(i);
			if (!useCustomStorage && (p instanceof AutoParameterImpl)) {
				continue;
			}
			if (p.isUniqueVariable()) {
				throw new IllegalArgumentException(
					"Invalid parameter specified: UniqueVariable not allowed");
			}
			checkForParameterNameConflict(p, newParams, nonParamNames);
			clonedParams.add(getResolvedVariable(function, p, false, !useCustomStorage));
		}
		newParams = clonedParams;

		if (useCustomStorage) {
			checkStorageConflicts(function, newParams, force);
		}

		// Repopulate params list
		List<ParameterDB> oldParams = params;
		params = new ArrayList<>();

		// Clear current param names
		for (ParameterDB param : oldParams) {
			param.setName(null, SourceType.DEFAULT);
		}

		int newParamIndex = 0;

		// Reassign old parameters if possible
		while (newParamIndex < oldParams.size() && newParamIndex < newParams.size()) {
			ParameterDB oldParam = oldParams.get(newParamIndex);
			Variable newParam = newParams.get(newParamIndex++);
			DataType dt = (newParam instanceof Parameter && !useCustomStorage)
					? ((Parameter) newParam).getFormalDataType()
					: newParam.getDataType();
			oldParam.setName(newParam.getName(), newParam.getSource());
			oldParam.setStorageAndDataType(newParam.getVariableStorage(), dt);
			oldParam.setComment(newParam.getComment());
			params.add(oldParam); // re-add to list
		}

		// Remove unused old parameters
		for (int i = newParamIndex; i < oldParams.size(); i++) {
			ParameterDB oldParam = oldParams.get(i);
			Symbol s = oldParam.getSymbol();
			symbolMap.remove(s);
			s.delete();
		}

		// Append new parameters if needed
		SymbolManager symbolMgr = program.getSymbolTable();
		for (int i = newParamIndex; i < newParams.size(); i++) {
			Variable newParam = newParams.get(i);
			DataType dt = (newParam instanceof Parameter && !useCustomStorage)
					? ((Parameter) newParam).getFormalDataType()
					: newParam.getDataType();
			VariableStorage storage = useCustomStorage ? newParam.getVariableStorage()
					: VariableStorage.UNASSIGNED_STORAGE;
			String name = newParam.getName();
			if (name == null || name.length() == 0) {
				name = SymbolUtilities.getDefaultParamName(i);
			}
			VariableSymbolDB s = symbolMgr.createVariableSymbol(name, function,
				SymbolType.PARAMETER, i, storage, newParam.getSource());
			s.setStorageAndDataType(storage, dt);
			ParameterDB paramDb = new ParameterDB(function, s);
			paramDb.setComment(newParam.getComment());
			params.add(i, paramDb);
			symbolMap.put(s, paramDb);
		}

		// assign dynamic storage
		updateParametersAndReturn(function, useCustomStorage);

	}

	/**
	 * Remove 'this' parameter if using __thiscall and first non-auto parameter is
	 * a pointer and named 'this'.
	 * @param params list of parameters to search and affect
	 * @param callingConventionName current function calling convention
	 * @return true if 'this' parameter removed (applies to __thiscall callingConventionName only), else false
	 */
	private static boolean removeExplicitThisParameter(List<? extends Variable> params,
			String callingConventionName) {
		if (CompilerSpec.CALLING_CONVENTION_thiscall.equals(callingConventionName)) {
			int thisIndex = findExplicitThisParameter(params);
			if (thisIndex >= 0) {
				params.remove(thisIndex); // remove explicit 'this' parameter
				return true;
			}
		}
		return false;
	}

	/**
	 * Remove 'this' parameter if using __thiscall and first non-auto parameter is
	 * a pointer and named 'this'.  Variables must be pre-loaded.
	 * @return true if 'this' parameter removed
	 */
	boolean removeExplicitThisParameter(FunctionDB function) {
		if (CompilerSpec.CALLING_CONVENTION_thiscall.equals(function.getCallingConventionName())) {
			int thisIndex = findExplicitThisParameter(params);
			if (thisIndex >= 0) {
				removeParameter(thisIndex); // remove explicit 'this' parameter
				return true;
			}
		}
		return false;
	}

	private static int findExplicitReturnStoragePtrParameter(List<? extends Variable> params) {
		for (int i = 0; i < params.size(); i++) {
			Variable p = params.get(i);
			if (Function.RETURN_PTR_PARAM_NAME.equals(p.getName()) &&
				(p.getDataType() instanceof Pointer)) {
				return i;
			}
		}
		return -1;
	}

	private static DataType removeExplicitReturnStoragePtrParameter(
			List<? extends Variable> params) {
		int paramIndex = findExplicitReturnStoragePtrParameter(params);
		if (paramIndex >= 0) {
			Variable returnStoragePtrParameter = params.remove(paramIndex); // remove return storage parameter
			DataType dt = returnStoragePtrParameter.getDataType();
			if (dt instanceof Pointer ptr) {
				return ptr.getDataType();
			}
		}
		return null;
	}

	private DataType removeExplicitReturnStoragePtrParameter() {
		int paramIndex = findExplicitReturnStoragePtrParameter(params);
		if (paramIndex >= 0) {
			ParameterDB returnStoragePtrParameter = params.get(paramIndex);
			DataType dt = returnStoragePtrParameter.getDataType();
			removeParameter(paramIndex); // remove return storage parameter
			if (dt instanceof Pointer ptr) {
				return ptr.getDataType();
			}
		}
		return null;
	}

	/**
	 * Strip indirect pointer data type from a parameter.
	 * @param param parameter to be examined and optionally modified
	 * @param dt return datatype to be applied
	 * @param create if true the specified param will not be affected and a new parameter
	 * instance will be returned if strip performed, otherwise orginal param will be changed
	 * if possible and returned.
	 * @return parameter with pointer stripped or original param if pointer not used.
	 * Returned parameter will have unassigned storage if affected.
	 */
	private static Variable revertIndirectParameter(Variable param, DataType dt, boolean create) {
		try {
			if (create) {
				param = new ParameterImpl(param.getName(), dt, param.getProgram());
			}
			else {
				param.setDataType(dt, VariableStorage.UNASSIGNED_STORAGE, false, param.getSource());
			}
		}
		catch (InvalidInputException e) {
			throw new AssertException(e); // unexpected
		}
		return param;
	}

	private void checkForParameterNameConflict(Variable param, List<? extends Variable> newParams,
			Set<String> nonParamNames) throws DuplicateNameException {

		String name = param.getName();
		if (name == null || name.length() == 0 || SymbolUtilities.isDefaultParameterName(name)) {
			return;
		}

		// Check for duplicate names
		for (Variable chkParam : newParams) {
			if (param == chkParam) {
				continue;
			}
			if (name.equals(chkParam.getName())) {
				throw new DuplicateNameException("Duplicate parameter name '" + name + "'");
			}
		}

		if (nonParamNames.contains(name)) {
			throw new DuplicateNameException(
				"Parameter name conflicts with a symbol within function named '" + name + "'");
		}
	}

	private void checkStorageConflicts(FunctionDB function, List<? extends Variable> newParams,
			boolean removeConflictingLocals) throws VariableSizeException {

		VariableUtilities.VariableConflictHandler localConflictHandler = null;
		if (removeConflictingLocals) {
			localConflictHandler = conflicts -> {
				for (Variable var : conflicts) {
					removeVariable(var);
				}
				return true;
			};
		}

		for (Variable p : newParams) {
			// check for storage conflicts if custom storage used
			VariableUtilities.checkVariableConflict(newParams, p, p.getVariableStorage(), null);
			VariableUtilities.checkVariableConflict(locals, p, p.getVariableStorage(),
				localConflictHandler);
		}

	}

	void removeVariable(Variable variable) {
		if (variable instanceof VariableDB) {
			Symbol s = ((VariableDB) variable).symbol;
			if (symbolMap.containsKey(s)) {
				s.delete(); // results in callback to doDeleteVariable
			}
		}
	}

	private static int findExplicitThisParameter(List<? extends Variable> params) {
		for (int i = 0; i < params.size(); i++) {
			Variable p = params.get(i);
			if (Function.THIS_PARAM_NAME.equals(p.getName()) &&
				(p.getDataType() instanceof Pointer)) {
				return i;
			}
		}
		return -1;
	}

	void removeParameter(int ordinal) {
		if (ordinal < 0) {
			throw new IndexOutOfBoundsException();
		}
		if (autoParams != null) {
			if (ordinal < autoParams.size()) {
				return; // ignore
			}
			ordinal -= autoParams.size();
		}
		if (ordinal >= params.size()) {
			throw new IndexOutOfBoundsException();
		}
		ParameterDB param = params.get(ordinal);
		param.symbol.delete(); // results in callback to doDeleteVariable
	}

	Parameter addParameter(FunctionDB function, Variable var, SourceType source)
			throws InvalidInputException, DuplicateNameException {
		purgeBadVariables(function);

		return insertParameter(function, getParameterCount(), var, source);
	}

	ParameterDB insertParameter(FunctionDB function, int ordinal, Variable var,
			SourceType source) throws InvalidInputException, DuplicateNameException {
		purgeBadVariables(function);
		boolean hasCustomStorage = function.hasCustomVariableStorage();
		int autoCnt = 0;
		if (autoParams != null) {
			autoCnt = autoParams.size();
			if (ordinal < autoCnt) {
				throw new InvalidInputException(
					"Parameter may not be inserted before auto-parameter");
			}
		}

		ordinal -= autoCnt;
		if (ordinal < 0 || ordinal > params.size()) {
			throw new IndexOutOfBoundsException("Ordinal value must be " + autoCnt +
				" <= ordinal < " + (params.size() + autoCnt) + ": " + (ordinal + autoCnt));
		}

		if (var.isUniqueVariable()) {
			throw new IllegalArgumentException(
				"Invalid parameter specified: UniqueVariable not allowed");
		}

		if (hasCustomStorage) {
			if (validateEnabled && var.hasStackStorage()) {
				int stackOffset = (int) var.getLastStorageVarnode().getOffset();
				if (!function.getStackFrame().isParameterOffset(stackOffset)) {
					throw new InvalidInputException(
						"Variable contains invalid stack parameter offset: " + var.getName() +
							"  offset " + stackOffset);
				}
			}
		}

		var = getResolvedVariable(function, var, false, !hasCustomStorage);
		ProgramDB program = function.getProgram();

		String name = var.getName();
		SourceType paramSource = source;
		if (name == null || name.length() == 0 || paramSource == SourceType.DEFAULT ||
			SymbolUtilities.isDefaultParameterName(name)) {
			name = Function.DEFAULT_PARAM_PREFIX;
			paramSource = SourceType.DEFAULT;
		}

		VariableStorage storage = var.getVariableStorage();
		if (!hasCustomStorage) {
			storage = VariableStorage.UNASSIGNED_STORAGE;
		}
		else if (storage.isAutoStorage()) {
			storage = new VariableStorage(program, storage.getVarnodes());
		}

		try {

			// Check for duplicate storage address
			ParameterDB p = null;
			if (storage != VariableStorage.UNASSIGNED_STORAGE) {
				for (ParameterDB oldParam : params) {
					if (oldParam.getVariableStorage().intersects(storage)) {
						p = oldParam;
						break;
					}
				}
				if (validateEnabled) {
					VariableUtilities.checkVariableConflict(function, (p != null ? p : var),
						storage, true);
				}
			}
			if (p != null) {
				// storage has been specified
				// move and update existing parameter
				if (ordinal >= params.size()) {
					ordinal = params.size() - 1;
				}
				Msg.info(this, "WARNING! Inserting overlapping parameter for function " + this +
					" at " + p.getVariableStorage() + " - Replacing existing parameter!");
				if (p.getOrdinal() != ordinal) {
					if (p != params.remove(p.getOrdinal())) {
						throw new AssertException("Inconsistent function parameter cache");
					}

					params.add(ordinal, p);
					updateParametersAndReturn(function, hasCustomStorage);
					function.functionChanged(PARAMETERS_CHANGED);
				}
				if (!Function.DEFAULT_PARAM_PREFIX.equals(name)) {
					p.setName(name, paramSource);
				}
				p.setStorageAndDataType(storage, var.getDataType());
			}
			else {
				// create new parameter
				if (ordinal > params.size()) {
					ordinal = params.size();
				}
				if (ordinal != params.size()) {
					// shift params to make room for inserted param
					for (ParameterDB param : params) {
						int paramOrdinal = param.getOrdinal();
						if (paramOrdinal >= ordinal) {
							param.setOrdinal(paramOrdinal + 1, autoCnt);
						}
					}
				}
				SymbolManager symbolMgr = program.getSymbolTable();
				VariableSymbolDB s =
					symbolMgr.createVariableSymbol(name, function, SymbolType.PARAMETER, ordinal,
						storage, paramSource);
				s.setStorageAndDataType(storage, var.getDataType());
				p = new ParameterDB(function, s);

				params.add(ordinal, p);
				updateParametersAndReturn(function, hasCustomStorage);
				symbolMap.put(p.symbol, p);
				function.functionChanged(PARAMETERS_CHANGED);
			}
			if (var.getComment() != null) {
				p.symbol.setSymbolComment(var.getComment());
			}
			function.updateSignatureSourceAfterVariableChange(source, p.getDataType());
			return p;
		}
		finally {
			function.invalidateFrame();
		}

	}

	void doDeleteVariable(FunctionDB function, VariableSymbolDB symbol) {
		if (isBadVariable(symbol)) {
			// don't do anything here with bad variable symbol
			return;
		}
		VariableDB var = symbolMap.remove(symbol);

		if (var != null) {
			if (var instanceof Parameter) {
				if (removeVariable(params, var)) {
					updateParametersAndReturn(function, function.hasCustomVariableStorage());
				}
			}
			else {
				removeVariable(locals, var);
			}
		}

		function.functionChanged((var instanceof Parameter) ? PARAMETERS_CHANGED : null);
		function.invalidateFrame();
	}

	/**
	 * Remove variable instance from list.
	 *
	 * @param list
	 *            variable list
	 * @param var
	 *            variable instance
	 * @return true if deleted
	 */
	private static boolean removeVariable(List<?> list, VariableDB var) {
		int cnt = list.size();
		for (int i = 0; i < cnt; i++) {
			if (var == list.get(i)) {
				list.remove(i);
				return true;
			}
		}
		return false;
	}

	Variable getVariable(VariableSymbolDB symbol) {
		return symbolMap.get(symbol);
	}

	Parameter getParameter(int ordinal) {
		if (autoParams != null) {
			if (ordinal < autoParams.size()) {
				return autoParams.get(ordinal);
			}
			ordinal -= autoParams.size();
		}
		if (ordinal < params.size()) {
			return params.get(ordinal);
		}
		return null;
	}

	Parameter moveParameter(FunctionDB function, int fromOrdinal, int toOrdinal)
			throws InvalidInputException {
		int autoCnt = 0;
		if (autoParams != null) {
			autoCnt = autoParams.size();
			if (fromOrdinal < autoCnt) {
				throw new InvalidInputException("Auto-parameter may not be moved");
			}
			if (toOrdinal < autoCnt) {
				throw new InvalidInputException(
					"Parameter may not be moved before an auto-parameter");
			}
		}

		fromOrdinal -= autoCnt;
		toOrdinal -= autoCnt;

		if (fromOrdinal < 0 || fromOrdinal >= params.size()) {
			return null;
		}
		ParameterDB param = params.get(fromOrdinal);
		if (param.getOrdinal() == toOrdinal) {
			return param;
		}
		params.remove(fromOrdinal);
		if (toOrdinal >= params.size()) {
			params.add(param);
		}
		else {
			params.add(toOrdinal, param);
		}
		updateParametersAndReturn(function, function.hasCustomVariableStorage());
		function.functionChanged(PARAMETERS_CHANGED);
		return param;

	}

	void setCustomVariableStorage(FunctionDB function, boolean hasCustomVariableStorage)
			throws InvalidInputException {
		Program program = function.getProgram();
		if (!hasCustomVariableStorage) {
			// remove explicit 'this' param and return storage use if switching to dynamic storage
			removeExplicitThisParameter(function);
			DataType returnDt = removeExplicitReturnStoragePtrParameter();
			if (returnDt != null) {
				revertIndirectParameter(returnParam, returnDt, false);
			}
		}

		// get params and return prior to change
		Parameter[] parameters = getParameters(null);

		// remove auto-parameters
		autoParams = null;

		function.setFunctionFlag(FunctionAdapter.FUNCTION_CUSTOM_PARAM_STORAGE_FLAG,
			hasCustomVariableStorage);

		int ordinal = 0;
		for (Parameter p : parameters) {
			if (p.isAutoParameter()) {
				// must insert auto-params when switching to custom storage
				try {
					insertParameter(function, ordinal, new ParameterImpl(p, program),
						SourceType.ANALYSIS);
					++ordinal;
				}
				catch (DuplicateNameException e) {
					// skip - we don't want to rename auto-param
				}
			}
			else {
				// if not an auto-param p is a ParameterDB object
				// commit parameter storage and forced-indirect pointer when switching to custom
				// or switch to UNASSIGNED_STORAGE when switching to dynamic
				VariableStorage storage =
					hasCustomVariableStorage ? p.getVariableStorage().clone(program)
							: VariableStorage.UNASSIGNED_STORAGE;
				((ParameterDB) p).setStorageAndDataType(storage, p.getDataType());
			}
		}

		// commit return storage and forced-indirect pointer when switching to custom
		// or switch to UNASSIGNED_STORAGE when switching to dynamic
		VariableStorage storage =
			hasCustomVariableStorage ? returnParam.getVariableStorage().clone(program)
					: VariableStorage.UNASSIGNED_STORAGE;
		returnParam.setStorageAndDataType(storage, returnParam.getDataType());

		if (!hasCustomVariableStorage) {
			updateParametersAndReturn(function, hasCustomVariableStorage); // assign dynamic storage
		}

	}

}
