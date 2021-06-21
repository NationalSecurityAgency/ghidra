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

import java.io.IOException;
import java.util.*;

import db.DBRecord;
import ghidra.program.database.*;
import ghidra.program.database.data.DataTypeManagerDB;
import ghidra.program.database.external.ExternalManagerDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.program.util.ChangeManager;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Database implementation of a Function.
 *
 */
public class FunctionDB extends DatabaseObject implements Function {

	final FunctionManagerDB manager;

	private FunctionDB thunkedFunction;

	private ProgramDB program;
	private Address entryPoint;
	private Symbol functionSymbol;
	private DBRecord rec;

	private FunctionStackFrame frame;

	// NOTE: FunctionDB discards the following data when invalidated/refreshed
	// All function variables instances should be dropped/re-acquired when
	// a domain object restored event occurs

	private Map<SymbolDB, VariableDB> symbolMap;
	private ReturnParameterDB returnParam;
	private List<AutoParameterImpl> autoParams;
	private List<ParameterDB> params;
	private List<VariableDB> locals;

	// Tags associated with this function. This is here to keep db requests
	// to a minimum requesting all tags. Note that this list is invalidated
	// only when tags have been edited or deleted from the system.
	private Set<FunctionTag> tags;

	/**
	 * foundBadVariables is set true when one or more variable symbols are found
	 * which no longer decode a valid storage address (indicated by Address.NO_ADDRESS).
	 * Any time a variable is added while this flag is set, such bad variables should be purged.
	 */
	private boolean foundBadVariables = false;

	/**
	 * Use of stack frame to compute parameter ordinals and validate stack offsets
	 * should not be done while <code>validateEnabled</code> is false.  This may be
	 * necessary during a language upgrade in which case a dummy compiler-spec
	 * may be in-use.
	 */
	private boolean validateEnabled = true;

	private int updateInProgressCount = 0;
	private boolean updateRefreshRequired = false;

	FunctionDB(FunctionManagerDB manager, DBObjectCache<FunctionDB> cache, AddressMap addrMap,
			DBRecord rec) {
		super(cache, rec.getKey());
		this.manager = manager;
		program = manager.getProgram();
		this.rec = rec;
		init();
		frame = new FunctionStackFrame(this);
	}

	@Override
	public boolean isDeleted() {
		return isDeleted(manager.lock);
	}

	public void setValidationEnabled(boolean state) {
		validateEnabled = state;
	}

	private void init() {
		thunkedFunction = manager.getThunkedFunction(this);
		functionSymbol = program.getSymbolTable().getSymbol(key);
		entryPoint = functionSymbol.getAddress();
	}

	@Override
	protected void checkDeleted() {
		// expose method to function package
		super.checkDeleted();
	}

	@Override
	public boolean isThunk() {
		manager.lock.acquire();
		try {
			checkIsValid();
			return thunkedFunction != null;
		}
		finally {
			manager.lock.release();
		}
	}

	@Override
	public Function getThunkedFunction(boolean recursive) {
		manager.lock.acquire();
		try {
			checkIsValid();
			if (!recursive || thunkedFunction == null) {
				return thunkedFunction;
			}
			FunctionDB endFunction = thunkedFunction;
			while (endFunction.thunkedFunction != null) {
				endFunction = endFunction.thunkedFunction;
			}
			return endFunction;
		}
		finally {
			manager.lock.release();
		}
	}

	@Override
	public void setThunkedFunction(Function referencedFunction) {
		if ((referencedFunction != null) && !(referencedFunction instanceof FunctionDB)) {
			throw new IllegalArgumentException("FunctionDB expected for referenced function");
		}
		manager.lock.acquire();
		try {
			startUpdate();
			checkDeleted();
			// TODO: Removal all children / reset flags, etc. ??
			manager.setThunkedFunction(this, (FunctionDB) referencedFunction);
		}
		finally {
			endUpdate();
			manager.lock.release();
		}
	}

	@Override
	public Address[] getFunctionThunkAddresses() {
		manager.lock.acquire();
		try {
			checkIsValid();
			List<Long> functionIds = manager.getThunkFunctionIds(key);
			if (functionIds == null) {
				return null;
			}
			SymbolTable symMgr = program.getSymbolTable();
			Address[] addresses = new Address[functionIds.size()];
			int index = 0;
			for (long functionId : functionIds) {
				Symbol s = symMgr.getSymbol(functionId);
				addresses[index++] = s.getAddress();
			}
			return addresses;
		}
		finally {
			manager.lock.release();
		}
	}

	@Override
	public boolean isExternal() {
		return entryPoint.isExternalAddress();
	}

	@Override
	public ExternalLocation getExternalLocation() {
		if (isExternal()) {
			ExternalManagerDB extMgr = (ExternalManagerDB) program.getExternalManager();
			return extMgr.getExternalLocation(getSymbol());
		}
		return null;
	}

	@Override
	public boolean equals(Object obj) {
		// there can only be one functionDB object per unique function entry point
		//   just use the built-in equals method.
		return super.equals(obj);
	}

	@Override
	public int hashCode() {
		// there can only be one functionDB object per unique function entry point
		//    just use normal hashcode()
		return super.hashCode();
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return getName(true);
	}

	@Override
	public String getName() {
		manager.lock.acquire();
		try {
			checkIsValid();
			return functionSymbol.getName();
		}
		finally {
			manager.lock.release();
		}
	}

	@Override
	public void setName(String name, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		manager.lock.acquire();
		try {
			startUpdate();
			checkDeleted();
			functionSymbol.setName(name, source);
		}
		finally {
			endUpdate();
			manager.lock.release();
		}
	}

	@Override
	public Program getProgram() {
		return manager.getProgram();
	}

	@Override
	public String getComment() {
		manager.lock.acquire();
		try {
			checkIsValid();
			return manager.getCodeManager().getComment(CodeUnit.PLATE_COMMENT, getEntryPoint());
		}
		finally {
			manager.lock.release();
		}
	}

	@Override
	public String[] getCommentAsArray() {
		return StringUtilities.toLines(getComment());
	}

	@Override
	public void setComment(String comment) {
		manager.lock.acquire();
		try {
			startUpdate();
			checkDeleted();
			manager.getCodeManager().setComment(getEntryPoint(), CodeUnit.PLATE_COMMENT, comment);
		}
		finally {
			endUpdate();
			manager.lock.release();
		}
	}

	@Override
	public String getRepeatableComment() {
		manager.lock.acquire();
		try {
			checkIsValid();
			return manager.getCodeManager()
					.getComment(CodeUnit.REPEATABLE_COMMENT, getEntryPoint());
		}
		finally {
			manager.lock.release();
		}
	}

	@Override
	public String[] getRepeatableCommentAsArray() {
		return StringUtilities.toLines(getRepeatableComment());
	}

	@Override
	public void setRepeatableComment(String comment) {
		manager.lock.acquire();
		try {
			checkDeleted();
			manager.getCodeManager()
					.setComment(getEntryPoint(), CodeUnit.REPEATABLE_COMMENT, comment);
		}
		finally {
			manager.lock.release();
		}
	}

	@Override
	public Address getEntryPoint() {
		manager.lock.acquire();
		try {
			checkIsValid();
			return entryPoint;
		}
		finally {
			manager.lock.release();
		}
	}

	@Override
	public AddressSetView getBody() {
		return program.getNamespaceManager().getAddressSet(this);
	}

	@Override
	public void setBody(AddressSetView set) throws OverlappingFunctionException {
		manager.lock.acquire();
		try {
			startUpdate();
			checkDeleted();
			manager.setFunctionBody(this, set);
		}
		finally {
			endUpdate();
			manager.lock.release();
		}
	}

	@Override
	public DataType getReturnType() {
		return getReturn().getDataType();
	}

	@Override
	public ReturnParameterDB getReturn() {
		manager.lock.acquire();
		try {
			checkIsValid();
			if (thunkedFunction != null) {
				return thunkedFunction.getReturn();
			}
			loadVariables();
			return returnParam;
		}
		finally {
			manager.lock.release();
		}
	}

	@Override
	public void setReturn(DataType type, VariableStorage storage, SourceType source)
			throws InvalidInputException {
		manager.lock.acquire();
		try {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				thunkedFunction.setReturn(type, storage, source);
				return;
			}
			type = type.clone(program.getDataTypeManager());
			if (storage.isValid() && (storage.size() != type.getLength())) {
				try {
					storage = VariableUtilities.resizeStorage(storage, type, true, this);
				}
				catch (Exception e) {
					// ignore
				}
			}
			getReturn().setDataType(type, storage, true, source);
		}
		finally {
			endUpdate();
			manager.lock.release();
		}
	}

	@Override
	public void setReturnType(DataType type, SourceType source) throws InvalidInputException {
		manager.lock.acquire();
		try {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				thunkedFunction.setReturnType(type, source);
				return;
			}
			getReturn().setDataType(type, source);
		}
		finally {
			endUpdate();
			manager.lock.release();
		}
	}

	void setReturnStorageAndDataType(VariableStorage storage, DataType type) throws IOException {
		if (storage != null && storage.isUnassignedStorage()) {
			storage = null;
		}
		long typeId = ((DataTypeManagerDB) program.getDataTypeManager()).getResolvedID(type);
		rec.setLongValue(FunctionAdapter.RETURN_DATA_TYPE_ID_COL, typeId);
		rec.setString(FunctionAdapter.RETURN_STORAGE_COL,
			storage != null ? storage.getSerializationString() : null);
		manager.getFunctionAdapter().updateFunctionRecord(rec);
	}

	DataType getReturnDataType() {
		long typeId = rec.getLongValue(FunctionAdapter.RETURN_DATA_TYPE_ID_COL);
		DataType dt = program.getDataTypeManager().getDataType(typeId);
		if (dt == null) {
			dt = DataType.DEFAULT;
			if (hasCustomVariableStorage()) {
				VariableStorage storage =
					deserializeStorage(rec.getString(FunctionAdapter.RETURN_STORAGE_COL));
				if (storage.isVoidStorage()) {
					dt = VoidDataType.dataType;
				}
				else {
					dt = Undefined.getUndefinedDataType(storage.size());
				}
			}
		}
		return dt;
	}

	private VariableStorage deserializeStorage(String serializedStorage) {
		if (serializedStorage == null) {
			return VariableStorage.UNASSIGNED_STORAGE;
		}
		try {
			return VariableStorage.deserialize(program, serializedStorage);
		}
		catch (InvalidInputException e) {
			return VariableStorage.BAD_STORAGE;
		}
	}

//	VariableStorage getReturnStorage(DataType type) {
//		VariableStorage returnStorage;
//		String serializedStorage = rec.getString(FunctionAdapter.RETURN_STORAGE_COL);
//		if (serializedStorage == null) {
//			// Use compiler spec to determine return storage
//			PrototypeModel callingConvention = getCallingConvention();
//			if (callingConvention == null) {
//				callingConvention = getDefaultCallingConvention();
//			}
//			if (callingConvention == null) {
//				returnStorage = VariableStorage.UNASSIGNED_STORAGE;
//			}
//			else {
//				returnStorage = callingConvention.getReturnLocation(type, program);
//			}
//		}
//		else {
//			returnStorage = deserializeStorage(serializedStorage);
//		}
//		return returnStorage;
//	}

	@Override
	public FunctionSignature getSignature(boolean formalSignature) {
		manager.lock.acquire();
		try {
			startUpdate();
			checkIsValid();
			if (thunkedFunction == null) {
				// If not a thunk be sure to load variables first
				loadVariables();
			}
			return new FunctionDefinitionDataType(this, formalSignature);
		}
		finally {
			endUpdate();
			manager.lock.release();
		}
	}

	@Override
	public FunctionSignature getSignature() {
		return getSignature(false);
	}

	@Override
	public String getPrototypeString(boolean formalSignature, boolean includeCallingConvention) {
		manager.lock.acquire();
		try {
			if (!checkIsValid()) {
				return "undefined " + getName() + "()";
			}
			if (thunkedFunction == null) {
				// If not a thunk be sure to load variables first
				loadVariables();
			}

			StringBuffer buf = new StringBuffer();
			ReturnParameterDB rtn = getReturn();
			buf.append(formalSignature ? rtn.getFormalDataType().getDisplayName()
					: rtn.getDataType().getDisplayName());
			buf.append(" ");
			if (includeCallingConvention) {
				String callingConvention = getRealCallingConventionName();
				if (callingConvention != null) {
					buf.append(callingConvention);
					buf.append(" ");
				}
			}
			buf.append(getName());
			buf.append("(");

			boolean hasVarArgs = hasVarArgs();
			Parameter[] parameters = getParameters();
			int n = parameters.length;
			boolean emptyList = true;
			for (int i = 0; i < n; i++) {
				Parameter param = parameters[i];
				if (formalSignature && param.isAutoParameter()) {
					continue;
				}
				DataType dt = formalSignature ? param.getFormalDataType() : param.getDataType();
				buf.append(dt.getDisplayName());
				buf.append(" ");
				buf.append(param.getName());
				emptyList = false;
				if ((i < (n - 1)) || hasVarArgs) {
					buf.append(", ");
				}
			}
			if (hasVarArgs) {
				buf.append(FunctionSignature.VAR_ARGS_DISPLAY_STRING);
			}
			else if (emptyList && getSignatureSource() != SourceType.DEFAULT) {
				buf.append(FunctionSignature.VOID_PARAM_DISPLAY_STRING);
			}
			buf.append(")");

			return buf.toString();
		}
		finally {
			manager.lock.release();
		}
	}

	void updateSignatureSourceAfterVariableChange(SourceType variableSourceType,
			DataType variableDataType) {
		if (Undefined.isUndefined(variableDataType)) {
			return;
		}
		SourceType type = SourceType.ANALYSIS;
		if (variableSourceType != type && variableSourceType.isHigherPriorityThan(type)) {
			type = variableSourceType;
		}
		if (type.isHigherPriorityThan(getStoredSignatureSource())) {
			setSignatureSource(type);
		}
	}

	/**
	 * Get the inferred signature source type for use during upgrade
	 * @return inferred signature source
	 */
	SourceType getInferredSignatureSource() {

		DataType returnType = getReturnType();
		boolean isReturnUndefined = Undefined.isUndefined(returnType);
		SourceType type = isReturnUndefined ? SourceType.DEFAULT : SourceType.ANALYSIS;

		Parameter[] parameters = getParameters();
		for (Parameter parameter : parameters) {
			if (Undefined.isUndefined(parameter.getDataType())) {
				continue;
			}
			SourceType paramSourceType = parameter.getSource();
			if (paramSourceType != SourceType.ANALYSIS &&
				paramSourceType.isHigherPriorityThan(SourceType.ANALYSIS)) {
				type = paramSourceType;
			}
			else {
				type = SourceType.ANALYSIS;
			}
		}
		return type;
	}

	/**
	 * @see ghidra.program.model.listing.Function#getStackFrame()
	 */
	@Override
	public StackFrame getStackFrame() {
		manager.lock.acquire();
		try {
			checkIsValid();
			if (thunkedFunction != null) {
				return thunkedFunction.frame;
			}
			return frame;
		}
		finally {
			manager.lock.release();
		}
	}

	@Override
	public int getStackPurgeSize() {
		manager.lock.acquire();
		try {
			checkIsValid();
			if (thunkedFunction != null) {
				return thunkedFunction.getStackPurgeSize();
			}
			return rec.getIntValue(FunctionAdapter.STACK_PURGE_COL);
		}
		finally {
			manager.lock.release();
		}
	}

	@Override
	public void setStackPurgeSize(int change) {
		manager.lock.acquire();
		try {
			startUpdate();
			if (change == getStackPurgeSize()) {
				return;
			}
			checkDeleted();
			if (thunkedFunction != null) {
				thunkedFunction.setStackPurgeSize(change);
				return;
			}
			try {
				rec.setIntValue(FunctionAdapter.STACK_PURGE_COL, change);
				manager.getFunctionAdapter().updateFunctionRecord(rec);
				manager.functionChanged(this, ChangeManager.FUNCTION_CHANGED_PURGE);
			}
			catch (IOException e) {
				manager.dbError(e);
			}
			frame.setInvalid();
		}
		finally {
			endUpdate();
			manager.lock.release();
		}
	}

	@Override
	public boolean isStackPurgeSizeValid() {
		manager.lock.acquire();
		try {
			checkIsValid();
			if (thunkedFunction != null) {
				return thunkedFunction.isStackPurgeSizeValid();
			}
			if (getStackPurgeSize() > 0xffffff) {
				return false;
			}
			return true;
		}
		finally {
			manager.lock.release();
		}
	}

	@Override
	public long getID() {
		return key;
	}

	private static boolean isBadVariable(VariableSymbolDB varSym) {
		return varSym.getAddress() == Address.NO_ADDRESS ||
			varSym.getVariableStorage().isBadStorage();
	}

	private void loadVariables() {
		manager.lock.acquire();
		try {
			if (!loadSymbolBasedVariables()) {
				return; // already loaded
			}
			boolean hasCustomVariableStorage = hasCustomVariableStorage();
			loadReturn(hasCustomVariableStorage);
			if (foundBadVariables) {
				Msg.warn(this, "Found one or more bad variables in function " + getName() + " at " +
					getEntryPoint());
			}
			if (!hasCustomVariableStorage) {
				updateParametersAndReturn(); // assign dynamic storage (includes return and auto-params)
			}
		}
		finally {
			manager.lock.release();
		}
	}

	private boolean loadSymbolBasedVariables() {
		if (symbolMap != null) {
			return false;
		}
		symbolMap = new HashMap<>();
		locals = new ArrayList<>();
		params = new ArrayList<>();
		autoParams = null;
		SymbolIterator it = program.getSymbolTable().getChildren(functionSymbol);
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
					ParameterDB p = new ParameterDB(this, s);
					symbolMap.put(s, p);
					params.add(p);
				}
				else {
					VariableDB var = new LocalVariableDB(this, s);
					symbolMap.put(s, var);
					locals.add(var);
				}
			}
		}
		Collections.sort(params);
		Collections.sort(locals);
		return true;
	}

	private boolean loadReturn(boolean hasCustomVariableStorage) {

		if (returnParam != null) {
			return false;
		}
		DataType dt = getReturnDataType();

		VariableStorage returnStorage = VariableStorage.UNASSIGNED_STORAGE;
		if (hasCustomVariableStorage) {
			String serializedStorage = rec.getString(FunctionAdapter.RETURN_STORAGE_COL);
			if (serializedStorage != null) {
				returnStorage = deserializeStorage(serializedStorage);
				if (returnStorage.isBadStorage()) {
					foundBadVariables = true;
				}
			}
		}

		returnParam = new ReturnParameterDB(this, dt, returnStorage);

		return true;
	}

	/**
	 * Update parameter ordinals and re-assign dynamic parameter storage
	 * NOTE: loadVariables must have been called first
	 */
	void updateParametersAndReturn() {

		if (params == null) {
			loadVariables();
			return;
		}

		if (hasCustomVariableStorage()) {
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
		DataType baseType = dataTypes[0];
		if (baseType instanceof TypeDef) {
			baseType = ((TypeDef) baseType).getBaseDataType();
		}
		returnParam
				.setDynamicStorage((baseType instanceof VoidDataType) ? VariableStorage.VOID_STORAGE
						: VariableStorage.UNASSIGNED_STORAGE);

		PrototypeModel callingConvention = getCallingConvention();
		if (callingConvention == null) {
			callingConvention = getDefaultCallingConvention();
		}
		if (callingConvention == null) {
			return;
		}

		VariableStorage[] variableStorage =
			callingConvention.getStorageLocations(program, dataTypes, true);
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
				DataType dt = VariableUtilities.getAutoDataType(this,
					returnParam.getFormalDataType(), storage);
				try {
					autoParams.add(new AutoParameterImpl(dt, autoIndex++, storage, this));
				}
				catch (InvalidInputException e) {
					Msg.error(this,
						"Unexpected error during dynamic storage assignment for function at " +
							getEntryPoint(),
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

	int getAutoParamCount() {
		return autoParams != null ? autoParams.size() : 0;
	}

	private void renumberParameterOrdinals() {
		int ordinal = autoParams != null ? autoParams.size() : 0;
		for (ParameterDB param : params) {
			param.setOrdinal(ordinal++);
		}
	}

	/**
	 * Re-assign dynamic storage for return
	 */
//	void updateReturn() {
//
//		if (returnParam == null) {
//			return;
//		}
//
//		// allow lazy update of return dynamic storage
//		returnParam.setDynamicStorage(null);
//	}

	private void purgeBadVariables() {
		if (!foundBadVariables) {
			return;
		}
		List<Symbol> badSymbols = new ArrayList<>();
		SymbolIterator it = program.getSymbolTable().getChildren(functionSymbol);
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
				.setBookmark(getEntryPoint(), BookmarkType.ERROR, "Bad Variables Removed",
					"Removed " + badSymbols.size() + " bad variables");
		for (Symbol s : badSymbols) {
			s.delete();
		}
		if (hasCustomVariableStorage()) {
			ReturnParameterDB rtnParam = getReturn();
			if (rtnParam.getVariableStorage().isBadStorage()) {
				DataType dt = rtnParam.getDataType();
				DataType baseType = dt;
				if (baseType instanceof TypeDef) {
					baseType = ((TypeDef) baseType).getBaseDataType();
				}
				VariableStorage storage =
					(baseType instanceof VoidDataType) ? VariableStorage.VOID_STORAGE
							: VariableStorage.UNASSIGNED_STORAGE;
				rtnParam.setStorageAndDataType(storage, dt);
			}
		}
		foundBadVariables = false;
	}

	FunctionManagerDB getFunctionManager() {
		return manager;
	}

	/**
	 * @see ghidra.program.model.listing.Function#addLocalVariable(ghidra.program.model.listing.Variable, ghidra.program.model.symbol.SourceType)
	 */
	@Override
	public VariableDB addLocalVariable(Variable var, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		manager.lock.acquire();
		try {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				return thunkedFunction.addLocalVariable(var, source);
			}
			loadVariables();
			purgeBadVariables();

			var = getResolvedVariable(var, false, false);

			String name = var.getName();
			if (name == null || name.length() == 0 ||
				SymbolUtilities.isDefaultParameterName(name)) {
				name = DEFAULT_LOCAL_PREFIX;
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
					VariableUtilities.checkVariableConflict(this, (v != null ? v : var), storage,
						true);
				}
				if (v != null) {
					// update existing variable
					Msg.info(this, "WARNING! Adding overlapping local variable for function " +
						this + " at " + v.getVariableStorage() + " - Modifying existing variable!");
					if (!DEFAULT_LOCAL_PREFIX.equals(name)) {
						v.setName(name, source);
					}
					v.setStorageAndDataType(storage, var.getDataType());
				}
				else {
					SymbolManager symbolMgr = (SymbolManager) program.getSymbolTable();
					VariableSymbolDB s = symbolMgr.createVariableSymbol(name, this,
						SymbolType.LOCAL_VAR, firstUseOffset, storage, source);
					s.setStorageAndDataType(storage, var.getDataType());
					v = new LocalVariableDB(this, s);
					locals.add(v);
					Collections.sort(locals);
					symbolMap.put(v.symbol, v);
				}
				if (var.getComment() != null) {
					v.symbol.setSymbolData3(var.getComment());
				}
				manager.functionChanged(this, 0);
				return v;
			}
			finally {
				frame.setInvalid();
			}
		}
		finally {
			endUpdate();
			manager.lock.release();
		}
	}

	private static class ThunkVariableFilter implements VariableFilter {
		private VariableFilter otherFilter;

		ThunkVariableFilter(VariableFilter otherFilter) {
			this.otherFilter = otherFilter;
		}

		@Override
		public boolean matches(Variable variable) {
			return (variable instanceof Parameter) &&
				(otherFilter == null || otherFilter.matches(variable));
		}

	}

	/**
	 * Adjust thunk 'this' auto-param if function has non-default source and
	 * does not reside within the global namespace.
	 * @param variables array of thunk variables
	 * @return variables array with 'this' auto-param adjusted if needed
	 */
	private Variable[] adjustThunkThisParameter(Variable[] variables) {
		Symbol s = getSymbol();
		if (s.getParentNamespace().getID() == Namespace.GLOBAL_NAMESPACE_ID) {
			return variables;
		}
		for (int i = 0; i < variables.length; i++) {
			if (variables[i] instanceof AutoParameterImpl) {
				variables[i] = adjustThunkThisParameter((AutoParameterImpl) variables[i]);
			}
		}
		return variables;
	}

	/**
	 * Adjust thunk 'this' auto-param if function has non-default source and
	 * does not reside within the global namespace.
	 * @param parameters array of thunk parameters
	 * @return variables array with 'this' auto-param adjusted if needed
	 */
	private Parameter[] adjustThunkThisParameter(Parameter[] parameters) {
		Symbol s = getSymbol();
		if (s.getParentNamespace().getID() == Namespace.GLOBAL_NAMESPACE_ID) {
			return parameters;
		}
		for (int i = 0; i < parameters.length; i++) {
			if (parameters[i] instanceof AutoParameterImpl) {
				parameters[i] = adjustThunkThisParameter(parameters[i]);
			}
		}
		return parameters;
	}

	/**
	 * Adjust the specified parameter for a thunk function if required.
	 * This method will return a newly minted this auto-param if required
	 * to reflect the overriden name and class within which this thunk
	 * resides.
	 * @param parameter thunk parameter
	 * @return an adjusted auto-parameter or the original parameter
	 * if no adjustment was required
	 */
	private Parameter adjustThunkThisParameter(Parameter parameter) {
		if (!parameter.isAutoParameter()) {
			return parameter;
		}
		Symbol s = getSymbol();
		if (s.getParentNamespace().getID() == Namespace.GLOBAL_NAMESPACE_ID) {
			return parameter;
		}
		VariableStorage variableStorage = parameter.getVariableStorage();
		if (variableStorage.getAutoParameterType() == AutoParameterType.THIS) {
			DataType dt = VariableUtilities.getAutoDataType(this, null, variableStorage);
			try {
				return new AutoParameterImpl(dt, parameter.getOrdinal(), variableStorage, this);
			}
			catch (InvalidInputException e) {
				Msg.error(this,
					"Unexpected error during dynamic storage assignment for function at " +
						getEntryPoint(),
					e);
			}
		}
		return parameter;
	}

	@Override
	public Variable[] getVariables(VariableFilter filter) {
		manager.lock.acquire();
		try {
			checkIsValid();
			if (thunkedFunction != null) {
				Variable[] variables =
					thunkedFunction.getVariables(new ThunkVariableFilter(filter));
				return adjustThunkThisParameter(variables);
			}
			loadVariables();
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
		finally {
			manager.lock.release();
		}
	}

	@Override
	public Variable[] getAllVariables() {
		return getVariables(null);
	}

	@Override
	public Parameter[] getParameters(VariableFilter filter) {
		manager.lock.acquire();
		try {
			checkIsValid();
			if (thunkedFunction != null) {
				Parameter[] parameters = thunkedFunction.getParameters(filter);
				return adjustThunkThisParameter(parameters);
			}
			loadVariables();
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
		finally {
			manager.lock.release();
		}
	}

	@Override
	public Parameter[] getParameters() {
		return getParameters(null);
	}

	@Override
	public Variable[] getLocalVariables(VariableFilter filter) {
		manager.lock.acquire();
		try {
			checkIsValid();
			if (thunkedFunction != null) {
				return new Variable[0];
			}
			loadVariables();
			ArrayList<Variable> list = new ArrayList<>();
			for (VariableDB var : locals) {
				if (filter == null || filter.matches(var)) {
					list.add(var);
				}
			}
			Variable[] vars = new Variable[list.size()];
			return list.toArray(vars);
		}
		finally {
			manager.lock.release();
		}
	}

	@Override
	public Variable[] getLocalVariables() {
		return getLocalVariables(null);
	}

	@Override
	public int getParameterCount() {
		manager.lock.acquire();
		try {
			checkIsValid();
			if (thunkedFunction != null) {
				return thunkedFunction.getParameterCount();
			}
			loadVariables();
			int count = params.size();
			if (autoParams != null) {
				count += autoParams.size();
			}
			return count;
		}
		finally {
			manager.lock.release();
		}
	}

	@Override
	public int getAutoParameterCount() {
		manager.lock.acquire();
		try {
			checkIsValid();
			if (thunkedFunction != null) {
				return thunkedFunction.getParameterCount();
			}
			loadVariables();
			if (autoParams != null) {
				return autoParams.size();
			}
			return 0;
		}
		finally {
			manager.lock.release();
		}
	}

	/**
	 * Resolve a variable's type and storage.
	 * @param var variable to be resolved
	 * @return resolved variable
	 * @throws InvalidInputException if unable to resize variable storage due to
	 * resolved datatype size change
	 */
	Variable getResolvedVariable(Variable var, boolean voidOK, boolean useUnassignedStorage)
			throws InvalidInputException {
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
					storage = VariableUtilities.resizeStorage(storage, resolvedDt, true, this);
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

	@Override
	public void replaceParameters(FunctionUpdateType updateType, boolean force, SourceType source,
			Variable... newParams) throws DuplicateNameException, InvalidInputException {
		updateFunction(null, null, Arrays.asList(newParams), updateType, force, source);
	}

	@Override
	public void replaceParameters(List<? extends Variable> newParams, FunctionUpdateType updateType,
			boolean force, SourceType source) throws DuplicateNameException, InvalidInputException {
		updateFunction(null, null, newParams, updateType, force, source);
	}

	@Override
	public void updateFunction(String callingConvention, Variable returnValue,
			FunctionUpdateType updateType, boolean force, SourceType source, Variable... newParams)
			throws DuplicateNameException, InvalidInputException {
		updateFunction(callingConvention, returnValue, Arrays.asList(newParams), updateType, force,
			source);
	}

	/**
	 * Increment updateInProgressCount indicating that an update operation is in progress and 
	 * that any attempted refresh should be deferred.  The updateRefreshReqd flag will be set
	 * if a refresh was attempted while an update operation was in progress.
	 */
	synchronized void startUpdate() {
		++updateInProgressCount;
	}

	/**
	 * Decrement updateInProgressCount indicating that an update operation has completed and 
	 * check the updateRefreshReqd flag and perform refresh if needed.
	 */
	synchronized void endUpdate() {
		if (--updateInProgressCount == 0 && updateRefreshRequired) {
			refresh();
		}
	}

	@Override
	public void updateFunction(String callingConvention, Variable returnVar,
			List<? extends Variable> newParams, FunctionUpdateType updateType, boolean force,
			SourceType source) throws DuplicateNameException, InvalidInputException {

		manager.lock.acquire();
		try {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				thunkedFunction.updateFunction(callingConvention, returnVar, newParams, updateType,
					force, source);
				return;
			}

			loadVariables();
			purgeBadVariables();

			boolean useCustomStorage = (updateType == FunctionUpdateType.CUSTOM_STORAGE);
			setCustomVariableStorage(useCustomStorage);

			if (callingConvention != null) {
				setCallingConvention(callingConvention);
			}

			callingConvention = getCallingConventionName();

			if (returnVar == null) {
				returnVar = returnParam;
			}
			else if (returnVar.isUniqueVariable()) {
				throw new IllegalArgumentException(
					"Invalid return specified: UniqueVariable not allowed");
			}

			DataType returnType = returnVar.getDataType();
			VariableStorage returnStorage = returnVar.getVariableStorage();

			if (!useCustomStorage) {
				// remove auto params and forced-indirect return
				newParams = new ArrayList<Variable>(newParams); // copy for edit
				boolean thisParamRemoved =
					removeExplicitThisParameter(newParams, callingConvention);
				if (removeExplicitReturnStorageParameter(newParams)) {
					returnVar = revertIndirectParameter(returnVar, true);
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
			getReturn().setDataType(returnType, returnStorage, true, source);

			Set<String> nonParamNames = new HashSet<>();
			for (Symbol s : program.getSymbolTable().getSymbols(this)) {
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
				clonedParams.add(getResolvedVariable(p, false, !useCustomStorage));
			}
			newParams = clonedParams;

			if (useCustomStorage) {
				checkStorageConflicts(newParams, force);
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
			SymbolManager symbolMgr = (SymbolManager) program.getSymbolTable();
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
				VariableSymbolDB s = symbolMgr.createVariableSymbol(name, this,
					SymbolType.PARAMETER, i, storage, newParam.getSource());
				s.setStorageAndDataType(storage, dt);
				ParameterDB paramDb = new ParameterDB(this, s);
				paramDb.setComment(newParam.getComment());
				params.add(i, paramDb);
				symbolMap.put(s, paramDb);
			}

			if (source.isHigherPriorityThan(getStoredSignatureSource())) {
				setSignatureSource(source);
			}

			// assign dynamic storage
			updateParametersAndReturn();

			manager.functionChanged(this, ChangeManager.FUNCTION_CHANGED_PARAMETERS);
		}
		finally {
			frame.setInvalid();
			endUpdate();
			manager.lock.release();
		}
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

	private void checkStorageConflicts(List<? extends Variable> newParams,
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

	@Override
	public Parameter addParameter(Variable var, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		manager.lock.acquire();
		try {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				return thunkedFunction.addParameter(var, source);
			}
			loadVariables();
			purgeBadVariables();

			return insertParameter(getParameterCount(), var, source);
		}
		finally {
			endUpdate();
			manager.lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.listing.Function#insertParameter(int, ghidra.program.model.listing.Variable, ghidra.program.model.symbol.SourceType)
	 */
	@Override
	public ParameterDB insertParameter(int ordinal, Variable var, SourceType source)
			throws DuplicateNameException, InvalidInputException {

		manager.lock.acquire();
		try {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				return thunkedFunction.insertParameter(ordinal, var, source);
			}
			loadVariables();
			purgeBadVariables();

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

			boolean hasCustomStorage = hasCustomVariableStorage();
			if (hasCustomStorage) {
				if (validateEnabled && var.hasStackStorage()) {
					int stackOffset = (int) var.getLastStorageVarnode().getOffset();
					if (!frame.isParameterOffset(stackOffset)) {
						throw new InvalidInputException(
							"Variable contains invalid stack parameter offset: " + var.getName() +
								"  offset " + stackOffset);
					}
				}
			}

			var = getResolvedVariable(var, false, !hasCustomStorage);

			String name = var.getName();
			SourceType paramSource = source;
			if (name == null || name.length() == 0 || paramSource == SourceType.DEFAULT ||
				SymbolUtilities.isDefaultParameterName(name)) {
				name = DEFAULT_PARAM_PREFIX;
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
						VariableUtilities.checkVariableConflict(this, (p != null ? p : var),
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
						updateParametersAndReturn();
						manager.functionChanged(this, ChangeManager.FUNCTION_CHANGED_PARAMETERS);
					}
					if (!DEFAULT_PARAM_PREFIX.equals(name)) {
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
								param.setOrdinal(paramOrdinal + 1);
							}
						}
					}
					SymbolManager symbolMgr = (SymbolManager) program.getSymbolTable();
					VariableSymbolDB s = symbolMgr.createVariableSymbol(name, this,
						SymbolType.PARAMETER, ordinal, storage, paramSource);
					s.setStorageAndDataType(storage, var.getDataType());
					p = new ParameterDB(this, s);

					params.add(ordinal, p);
					updateParametersAndReturn();
					symbolMap.put(p.symbol, p);
					manager.functionChanged(this, ChangeManager.FUNCTION_CHANGED_PARAMETERS);
				}
				if (var.getComment() != null) {
					p.symbol.setSymbolData3(var.getComment());
				}
				updateSignatureSourceAfterVariableChange(source, p.getDataType());
				return p;
			}
			finally {
				frame.setInvalid();
			}
		}
		finally {
			endUpdate();
			manager.lock.release();
		}
	}

	@Override
	public void removeVariable(Variable variable) {
		manager.lock.acquire();
		try {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				thunkedFunction.removeVariable(variable);
				return;
			}
			loadVariables();

			if (variable instanceof VariableDB) {
				Symbol s = ((VariableDB) variable).symbol;
				if (symbolMap.containsKey(s)) {
					s.delete(); // results in callback to doDeleteVariable
				}
			}
		}
		finally {
			endUpdate();
			manager.lock.release();
		}
	}

	@Override
	public void removeParameter(int ordinal) {
		manager.lock.acquire();
		try {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				thunkedFunction.removeParameter(ordinal);
				return;
			}
			loadVariables();
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
		finally {
			endUpdate();
			manager.lock.release();
		}
	}

	@Override
	protected boolean refresh() {
		return refresh(null);
	}

	@Override
	protected boolean refresh(DBRecord refreshRec) {
		if (updateInProgressCount != 0) {
			// update may have caused variable/data-type changes which may trigger a
			// refresh of this function - must defer until update completed
			updateRefreshRequired = true;
			return true;
		}
		symbolMap = null;
		params = null;
		locals = null;
		autoParams = null;
		returnParam = null;
		foundBadVariables = false;
		tags = null;
		try {
			if (refreshRec == null) {
				refreshRec = manager.getFunctionAdapter().getFunctionRecord(key);
			}
			if (refreshRec != null) {
				this.rec = refreshRec;
				init();
				return true;
			}
		}
		catch (IOException e) {
			manager.dbError(e);
		}
		finally {
			frame.setInvalid();
		}

		return false;
	}

	/**
	 * Callback to remove variable just prior to removal
	 * of the underlying symbol.
	 * @param symbol variable symbol which is about to be deleted.
	 */
	public void doDeleteVariable(VariableSymbolDB symbol) {
		manager.lock.acquire();
		try {
			startUpdate();
			if (!checkIsValid()) {
				return;
			}

			if (isBadVariable(symbol)) {
				// don't do anything here with bad variable symbol
				return;
			}

			loadVariables();
			VariableDB var = symbolMap.remove(symbol);

			if (var != null) {
				if (var instanceof Parameter) {
					if (removeVariable(params, var)) {
						updateParametersAndReturn();
					}
				}
				else {
					removeVariable(locals, var);
				}
			}

			manager.functionChanged(this,
				(var instanceof Parameter) ? ChangeManager.FUNCTION_CHANGED_PARAMETERS : 0);
			frame.setInvalid();
		}
		finally {
			endUpdate();
			manager.lock.release();
		}
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
	private boolean removeVariable(List<?> list, VariableDB var) {
		int cnt = list.size();
		for (int i = 0; i < cnt; i++) {
			if (var == list.get(i)) {
				list.remove(i);
				return true;
			}
		}
		return false;
	}

	/**
	 * Return the Variable for the given symbol.
	 *
	 * @param symbol
	 *            variable symbol
	 */
	public Variable getVariable(VariableSymbolDB symbol) {
		manager.lock.acquire();
		try {
			checkIsValid();
			loadVariables();
			return symbolMap.get(symbol);
		}
		finally {
			manager.lock.release();
		}
	}

	@Override
	public Parameter getParameter(int ordinal) {
		manager.lock.acquire();
		try {
			checkIsValid();
			if (thunkedFunction != null) {
				Parameter parameter = thunkedFunction.getParameter(ordinal);
				return parameter != null ? adjustThunkThisParameter(parameter) : null;
			}
			if (ordinal == Parameter.RETURN_ORIDINAL) {
				return getReturn();
			}
			if (ordinal < 0) {
				return null;
			}
			loadVariables();
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
		finally {
			manager.lock.release();
		}
	}

	/**
	 * @throws InvalidInputException
	 * @see ghidra.program.model.listing.Function#moveParameter(int, int)
	 */
	@Override
	public Parameter moveParameter(int fromOrdinal, int toOrdinal) throws InvalidInputException {
		if (toOrdinal < 0) {
			throw new InvalidInputException("invalid toOrdinal specified: " + toOrdinal);
		}
		manager.lock.acquire();
		try {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				return thunkedFunction.moveParameter(fromOrdinal, toOrdinal);
			}
			loadVariables();

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
			updateParametersAndReturn();
			manager.functionChanged(this, ChangeManager.FUNCTION_CHANGED_PARAMETERS);
			return param;
		}
		finally {
			endUpdate();
			manager.lock.release();
		}
	}

//	int getLocalSize() {
//		manager.lock.acquire();
//		try {
//			checkIsValid();
//			return rec.getIntValue(FunctionAdapter.STACK_LOCAL_SIZE_COL);
//		}
//		finally {
//			manager.lock.release();
//		}
//	}

//	int getParameterOffset() {
//		manager.lock.acquire();
//		try {
//			checkIsValid();
//			return rec.getIntValue(FunctionAdapter.STACK_PARAM_OFFSET_COL);
//		}
//		finally {
//			manager.lock.release();
//		}
//	}

	void setLocalSize(int size) {
		manager.lock.acquire();
		try {
			startUpdate();
			checkDeleted();
			if (size < 0) {
				throw new IllegalArgumentException("invalid local size: " + size);
			}
			rec.setIntValue(FunctionAdapter.STACK_LOCAL_SIZE_COL, size);
			try {
				manager.getFunctionAdapter().updateFunctionRecord(rec);
				manager.functionChanged(this, 0);
			}
			catch (IOException e) {
				manager.dbError(e);
			}
			frame.setInvalid();
		}
		finally {
			endUpdate();
			manager.lock.release();
		}
	}

//	void setParameterOffset(int offset) {
//		manager.lock.acquire();
//		try {
//			checkDeleted();
////			if (validateEnabled && !frame.isParameterOffset(offset)) {
////				throw new InvalidInputException("Invalid parameter offset " + offset);
////			}
//			rec.setIntValue(FunctionAdapter.STACK_PARAM_OFFSET_COL, offset);
//			try {
//				manager.getFunctionAdapter().updateFunctionRecord(rec);
//				manager.functionChanged(this);
//			}
//			catch (IOException e) {
//				manager.dbError(e);
//			}
//			frame.setInvalid();
//		}
//		finally {
//			manager.lock.release();
//		}
//	}

	int getReturnAddressOffset() {
		manager.lock.acquire();
		try {
			checkIsValid();
			return rec.getIntValue(FunctionAdapter.STACK_RETURN_OFFSET_COL);
		}
		finally {
			manager.lock.release();
		}
	}

	void setReturnAddressOffset(int offset) {
		manager.lock.acquire();
		try {
			startUpdate();
			checkDeleted();
			rec.setIntValue(FunctionAdapter.STACK_RETURN_OFFSET_COL, offset);
			try {
				manager.getFunctionAdapter().updateFunctionRecord(rec);
				manager.functionChanged(this, 0);
			}
			catch (IOException e) {
				manager.dbError(e);
			}
			frame.setInvalid();
		}
		finally {
			endUpdate();
			manager.lock.release();
		}
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see ghidra.program.model.symbol.Namespace#getSymbol()
	 */
	@Override
	public Symbol getSymbol() {
		return functionSymbol;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see ghidra.program.model.listing.Function#setParentScope(ghidra.program.model.symbol.Scope)
	 */
	@Override
	public void setParentNamespace(Namespace newParentScope)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {

		if (functionSymbol.getParentNamespace().equals(newParentScope)) {
			return;
		}
		functionSymbol.setNamespace(newParentScope);
	}

	/**
	 * @see ghidra.program.model.symbol.Namespace#getParentNamespace()
	 */
	@Override
	public Namespace getParentNamespace() {
		return functionSymbol.getParentNamespace();
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see ghidra.program.model.symbol.Namespace#getName(boolean)
	 */
	@Override
	public String getName(boolean includeNamespacePath) {
		return functionSymbol.getName(includeNamespacePath);
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see ghidra.program.model.listing.Function#hasVarArgs()
	 */
	@Override
	public boolean hasVarArgs() {
		return isFunctionFlagSet(FunctionAdapter.FUNCTION_VARARG_FLAG);
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see ghidra.program.model.listing.Function#setVarArgs(boolean)
	 */
	@Override
	public void setVarArgs(boolean hasVarArgs) {
		manager.lock.acquire();
		try {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				thunkedFunction.setVarArgs(hasVarArgs);
			}
			else if (hasVarArgs != hasVarArgs()) {
				setFunctionFlag(FunctionAdapter.FUNCTION_VARARG_FLAG, hasVarArgs);
				manager.functionChanged(this, ChangeManager.FUNCTION_CHANGED_PARAMETERS);
			}
		}
		finally {
			endUpdate();
			manager.lock.release();
		}
	}

	@Override
	public boolean isInline() {
		return isFunctionFlagSet(FunctionAdapter.FUNCTION_INLINE_FLAG);
	}

	@Override
	public void setInline(boolean isInline) {
		manager.lock.acquire();
		try {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				thunkedFunction.setInline(isInline);
			}
			else if (!isExternal() && isInline != isInline()) {
				// only non-external functions may be inline
				setFunctionFlag(FunctionAdapter.FUNCTION_INLINE_FLAG, isInline);
				manager.functionChanged(this, ChangeManager.FUNCTION_CHANGED_INLINE);
			}
		}
		finally {
			endUpdate();
			manager.lock.release();
		}
	}

	@Override
	public boolean hasNoReturn() {
		return isFunctionFlagSet(FunctionAdapter.FUNCTION_NO_RETURN_FLAG);
	}

	@Override
	public void setNoReturn(boolean hasNoReturn) {
		manager.lock.acquire();
		try {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				thunkedFunction.setNoReturn(hasNoReturn);
			}
			else if (hasNoReturn != hasNoReturn()) {
				setFunctionFlag(FunctionAdapter.FUNCTION_NO_RETURN_FLAG, hasNoReturn);
				manager.functionChanged(this, ChangeManager.FUNCTION_CHANGED_NORETURN);
			}
		}
		finally {
			endUpdate();
			manager.lock.release();
		}
	}

	@Override
	public boolean hasCustomVariableStorage() {
		return isFunctionFlagSet(FunctionAdapter.FUNCTION_CUSTOM_PARAM_STORAGE_FLAG);
	}

//	private DataType getPointer(DataType dt, VariableStorage storage) {
//		if (program.getDefaultPointerSize() == storage.size()) {
//			return program.getDataTypeManager().getPointer(dt);
//		}
//		ProgramDataTypeManager dtm = program.getDataTypeManager();
//		int defaultPtrSize = dtm.getDataOrganization().getPointerSize();
//		int ptrSize = storage.size();
//		if (ptrSize == 0 || defaultPtrSize == ptrSize) {
//			return dtm.getPointer(dt);
//		}
//		return dtm.getPointer(dt, ptrSize);
//	}

	private static int findExplicitThisParameter(List<? extends Variable> params) {
		for (int i = 0; i < params.size(); i++) {
			Variable p = params.get(i);
			if (THIS_PARAM_NAME.equals(p.getName()) && (p.getDataType() instanceof Pointer)) {
				return i;
			}
		}
		return -1;
	}

	/**
	 * Remove 'this' parameter if using __thiscall and first non-auto parameter is
	 * a pointer and named 'this'.
	 * @param params list of parameters to search and affect
	 * @param callingConventionName
	 * @return true if 'this' parameter removed
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
	private boolean removeExplicitThisParameter() {
		if (CompilerSpec.CALLING_CONVENTION_thiscall.equals(getCallingConventionName())) {
			int thisIndex = findExplicitThisParameter(params);
			if (thisIndex >= 0) {
				removeParameter(thisIndex); // remove explicit 'this' parameter
				return true;
			}
		}
		return false;
	}

	private static int findExplicitReturnStorageParameter(List<? extends Variable> params) {
		for (int i = 0; i < params.size(); i++) {
			Variable p = params.get(i);
			if (RETURN_PTR_PARAM_NAME.equals(p.getName()) && (p.getDataType() instanceof Pointer)) {
				return i;
			}
		}
		return -1;
	}

	private static boolean removeExplicitReturnStorageParameter(List<? extends Variable> params) {
		int paramIndex = findExplicitReturnStorageParameter(params);
		if (paramIndex >= 0) {
			params.remove(paramIndex); // remove return storage parameter
			return true;
		}
		return false;
	}

	private boolean removeExplicitReturnStorageParameter() {
		int paramIndex = findExplicitReturnStorageParameter(params);
		if (paramIndex >= 0) {
			removeParameter(paramIndex); // remove return storage parameter
			return true;
		}
		return false;
	}

	/**
	 * Strip indirect pointer data type from a parameter.
	 * @param param parameter to be examined and optionally modified
	 * @param create if true the specified param will not be affected and a new parameter
	 * instance will be returned if strip performed, otherwise orginal param will be changed
	 * if possible and returned.
	 * @return parameter with pointer stripped or original param if pointer not used.
	 * Returned parameter will have unassigned storage if affected.
	 */
	private static Variable revertIndirectParameter(Variable param, boolean create) {
		DataType dt = param.getDataType();
		if (dt instanceof Pointer) {
			try {
				dt = ((Pointer) dt).getDataType();
				if (create) {
					param = new ParameterImpl(param.getName(), dt, param.getProgram());
				}
				else {
					param.setDataType(dt, VariableStorage.UNASSIGNED_STORAGE, false,
						param.getSource());
				}
			}
			catch (InvalidInputException e) {
				throw new AssertException(e); // unexpected
			}
		}
		return param;
	}

	@Override
	public void setCustomVariableStorage(boolean hasCustomVariableStorage) {
		manager.lock.acquire();
		try {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				thunkedFunction.setCustomVariableStorage(hasCustomVariableStorage);
				return;
			}
			if (hasCustomVariableStorage == hasCustomVariableStorage()) {
				return;
			}
			loadVariables();

			if (!hasCustomVariableStorage) {
				// remove explicit 'this' param and return storage use if switching to dynamic storage
				removeExplicitThisParameter();
				if (removeExplicitReturnStorageParameter()) {
					revertIndirectParameter(returnParam, false);
				}
			}

			// get params and return prior to change
			Parameter[] parameters = getParameters();

			// remove auto-parameters
			autoParams = null;

			setFunctionFlag(FunctionAdapter.FUNCTION_CUSTOM_PARAM_STORAGE_FLAG,
				hasCustomVariableStorage);

			int ordinal = 0;
			for (Parameter p : parameters) {
				if (p.isAutoParameter()) {
					// must insert auto-params when switching to custom storage
					try {
						insertParameter(ordinal, new ParameterImpl(p, program),
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
				updateParametersAndReturn(); // assign dynamic storage
			}

			manager.functionChanged(this, ChangeManager.FUNCTION_CHANGED_PARAMETERS);
		}
		catch (InvalidInputException e) {
			throw new AssertException(e); // should not occur
		}
		finally {
			endUpdate();
			manager.lock.release();
		}
	}

	/**
	 * Determines whether the indicated function flag is set.
	 *
	 * @param functionFlagIndicator
	 *            the function flag from the FunctionAdapter class (i.e.
	 *            FunctionAdapter.FUNCTION_VARARG_FLAG,
	 *            FunctionAdapter.FUNCTION_INLINE_FLAG,
	 *            FunctionAdapter.FUNCTION_NO_RETURN_FLAG)
	 * @return true if the indicated flag is set
	 */
	private boolean isFunctionFlagSet(byte functionFlagIndicator) {
		manager.lock.acquire();
		try {
			checkIsValid();
			if (thunkedFunction != null) {
				return thunkedFunction.isFunctionFlagSet(functionFlagIndicator);
			}
			byte flags = rec.getByteValue(FunctionAdapter.FUNCTION_FLAGS_COL);
			return ((flags & functionFlagIndicator) != 0);
		}
		finally {
			manager.lock.release();
		}
	}

	/**
	 * Sets the indicated function flag to true or false.
	 *
	 * @param functionFlagIndicator
	 *            the function flag from the FunctionAdapter class (i.e.
	 *            FunctionAdapter.FUNCTION_VARARG_FLAG,
	 *            FunctionAdapter.FUNCTION_INLINE_FLAG,
	 *            FunctionAdapter.FUNCTION_NO_RETURN_FLAG,
	 *            FunctionAdapter.FUNCTION_CUSTOM_PARAM_STORAGE_FLAG)
	 * @param shouldBeSet
	 *            true means the indicated flag should be set.
	 */
	private void setFunctionFlag(byte functionFlagIndicator, boolean shouldBeSet) {
		byte flags = rec.getByteValue(FunctionAdapter.FUNCTION_FLAGS_COL);
		if (shouldBeSet) {
			flags |= functionFlagIndicator;
		}
		else {
			flags &= ~functionFlagIndicator;
		}
		rec.setByteValue(FunctionAdapter.FUNCTION_FLAGS_COL, flags);
		try {
			manager.getFunctionAdapter().updateFunctionRecord(rec);
		}
		catch (IOException e) {
			manager.dbError(e);
		}
		frame.setInvalid();
	}

	@Override
	public SourceType getSignatureSource() {
		manager.lock.acquire();
		try {
			checkIsValid();
			if (thunkedFunction != null) {
				return thunkedFunction.getSignatureSource();
			}

			// Force DEFAULT source if any param has unassigned storage
			if (!getReturn().isValid()) {
				return SourceType.DEFAULT;
			}
			for (Parameter param : getParameters()) {
				if (!param.isValid()) {
					return SourceType.DEFAULT;
				}
			}

			return getStoredSignatureSource();
		}
		finally {
			manager.lock.release();
		}
	}

	SourceType getStoredSignatureSource() {
		byte flags = rec.getByteValue(FunctionAdapter.FUNCTION_FLAGS_COL);
		int typeOrdinal = (flags &
			FunctionAdapter.FUNCTION_SIGNATURE_SOURCE) >>> FunctionAdapter.FUNCTION_SIGNATURE_SOURCE_SHIFT;
		return SourceType.values()[typeOrdinal];
	}

	@Override
	public void setSignatureSource(SourceType signatureSource) {
		manager.lock.acquire();
		try {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				thunkedFunction.setSignatureSource(signatureSource);
				return;
			}

			byte flags = rec.getByteValue(FunctionAdapter.FUNCTION_FLAGS_COL);
			flags &= ~FunctionAdapter.FUNCTION_SIGNATURE_SOURCE;
			flags |= FunctionAdapter.getSignatureSourceFlagBits(signatureSource);

			rec.setByteValue(FunctionAdapter.FUNCTION_FLAGS_COL, flags);
			try {
				manager.getFunctionAdapter().updateFunctionRecord(rec);
				manager.functionChanged(this, 0);
			}
			catch (IOException e) {
				manager.dbError(e);
			}
		}
		finally {
			endUpdate();
			manager.lock.release();
		}
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see ghidra.program.model.listing.Function#getCallingConvention()
	 */
	@Override
	public PrototypeModel getCallingConvention() {
		String name = getCallingConventionName();
		if (name == null || name.equals(Function.UNKNOWN_CALLING_CONVENTION_STRING)) {
			return null;
		}
		FunctionManager functionMgr = getFunctionManager();
		if (name.equals(Function.DEFAULT_CALLING_CONVENTION_STRING)) {
			return functionMgr.getDefaultCallingConvention();
		}
		return functionMgr.getCallingConvention(name);
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see ghidra.program.model.listing.Function#getCallingConventionName()
	 */
	@Override
	public String getCallingConventionName() {
		manager.lock.acquire();
		try {
			if (!checkIsValid()) {
				return null;
			}
			if (thunkedFunction != null) {
				return thunkedFunction.getCallingConventionName();
			}
			byte callingConventionID = rec.getByteValue(FunctionAdapter.CALLING_CONVENTION_ID_COL);
			if (callingConventionID == CallingConventionDBAdapter.UNKNOWN_CALLING_CONVENTION_ID) {
				return Function.UNKNOWN_CALLING_CONVENTION_STRING;
			}
			if (callingConventionID == CallingConventionDBAdapter.DEFAULT_CALLING_CONVENTION_ID) {
				return Function.DEFAULT_CALLING_CONVENTION_STRING;
			}
			String name = manager.getCallingConventionName(callingConventionID);
			return name != null ? name : UNKNOWN_CALLING_CONVENTION_STRING;
		}
		finally {
			manager.lock.release();
		}
	}

	private String getRealCallingConventionName() {
		if (thunkedFunction != null) {
			return thunkedFunction.getRealCallingConventionName();
		}
		String name = null;
		byte callingConventionID = rec.getByteValue(FunctionAdapter.CALLING_CONVENTION_ID_COL);
		if (callingConventionID != CallingConventionDBAdapter.UNKNOWN_CALLING_CONVENTION_ID &&
			callingConventionID != CallingConventionDBAdapter.DEFAULT_CALLING_CONVENTION_ID) {
			name = manager.getCallingConventionName(callingConventionID);
		}
		// null returned for unknown or default calling convention
		return name;
	}

	private PrototypeModel getDefaultCallingConvention() {
		CompilerSpec compilerSpec = getProgram().getCompilerSpec();
		if (compilerSpec != null) {
			return compilerSpec.getDefaultCallingConvention();
		}
		return null;
	}

	@Override
	public String getDefaultCallingConventionName() {
		PrototypeModel defaultPrototype = getDefaultCallingConvention();
		if (defaultPrototype != null) {
			String defaultPrototypeName = defaultPrototype.getName();
			if (defaultPrototypeName != null) {
				return defaultPrototypeName;
			}
		}
		return Function.DEFAULT_CALLING_CONVENTION_STRING;
	}

	@Override
	public void setCallingConvention(String name) throws InvalidInputException {
		manager.lock.acquire();
		try {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				thunkedFunction.setCallingConvention(name);
				return;
			}

			byte newCallingConventionID = manager.getCallingConventionID(name);
			byte oldCallingConventionID =
				rec.getByteValue(FunctionAdapter.CALLING_CONVENTION_ID_COL);

			if (oldCallingConventionID != newCallingConventionID) {

				loadVariables();

				rec.setByteValue(FunctionAdapter.CALLING_CONVENTION_ID_COL, newCallingConventionID);
				manager.getFunctionAdapter().updateFunctionRecord(rec);

				boolean hasCustomStorage = hasCustomVariableStorage();
				if (!hasCustomStorage) {
					// remove 'this' param if switching to __thiscall with dynamic storage
					removeExplicitThisParameter();
				}

				frame.setInvalid();

				if (!hasCustomStorage) {
					createClassStructIfNeeded(); // TODO: How should thunks within Class namespace be handled?
					loadVariables();
					removeExplicitThisParameter();
					updateParametersAndReturn(); // assign dynamic storage
					manager.functionChanged(this, ChangeManager.FUNCTION_CHANGED_PARAMETERS);
					manager.functionChanged(this, ChangeManager.FUNCTION_CHANGED_RETURN);
				}
				else {
					manager.functionChanged(this, 0); // change did not affect parameters
				}
			}
		}
		catch (IOException e) {
			manager.dbError(e);
		}
		finally {
			endUpdate();
			manager.lock.release();
		}
	}

	void createClassStructIfNeeded() {
		PrototypeModel callingConvention = getCallingConvention();
		if (callingConvention == null ||
			callingConvention.getGenericCallingConvention() != GenericCallingConvention.thiscall) {
			return;
		}
		Namespace parent = getParentNamespace();
		if (!(parent instanceof GhidraClass)) {
			return;
		}

		DataTypeManager dataTypeManager = program.getDataTypeManager();
		// resolve 'this' pointer types to ensure related types are pre-resolved for auto-param use
		DataType classStruct = VariableUtilities.findExistingClassStruct(this);
		if (classStruct == null) {
			// NOTE: Adding structure to program every time the class name changes
			// could be problematic since this could accumulate types.  A stronger
			// relationship between a class namespace and its structure is needed
			// so its name and category can track properly.
			classStruct = VariableUtilities.findOrCreateClassStruct(this);
			dataTypeManager.resolve(classStruct, null);
		}
	}

	void dataTypeChanged(VariableDB var) {
		manager.functionChanged(this,
			(var instanceof Parameter) ? ChangeManager.FUNCTION_CHANGED_PARAMETERS : 0);
	}

	@Override
	public String getCallFixup() {
		manager.lock.acquire();
		try {
			checkIsValid();
			if (thunkedFunction != null) {
				return thunkedFunction.getCallFixup();
			}
			StringPropertyMap callFixupMap = manager.getCallFixupMap(false);
			if (callFixupMap == null) {
				return null;
			}
			return callFixupMap.getString(entryPoint);
		}
		finally {
			manager.lock.release();
		}
	}

	@Override
	public void setCallFixup(String name) {
		manager.lock.acquire();
		try {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				thunkedFunction.setCallFixup(name);
				return;
			}
			if (SystemUtilities.isEqual(name, getCallFixup())) {
				return;
			}
			StringPropertyMap callFixupMap = manager.getCallFixupMap(name != null);
			if (callFixupMap == null) {
				return;
			}
			if (name == null) {
				callFixupMap.remove(entryPoint);
			}
			else {
				if (program.getCompilerSpec()
						.getPcodeInjectLibrary()
						.getPayload(InjectPayload.CALLFIXUP_TYPE, name) == null) {
					Msg.warn(this, "Undefined CallFixup set at " + entryPoint + ": " + name);
				}
				callFixupMap.add(entryPoint, name);
			}
			manager.functionChanged(this, ChangeManager.FUNCTION_CHANGED_CALL_FIXUP);
		}
		finally {
			endUpdate();
			manager.lock.release();
		}
	}

	@Override
	public Set<Function> getCallingFunctions(TaskMonitor monitor) {
		monitor = TaskMonitor.dummyIfNull(monitor);
		Set<Function> set = new HashSet<>();
		ReferenceIterator iter = program.getReferenceManager().getReferencesTo(getEntryPoint());
		while (iter.hasNext()) {
			if (monitor.isCancelled()) {
				return set;
			}
			Reference reference = iter.next();
			Address fromAddress = reference.getFromAddress();
			Function callerFunction = manager.getFunctionContaining(fromAddress);
			if (callerFunction != null) {
				set.add(callerFunction);
			}
		}
		return set;
	}

	@Override
	public Set<Function> getCalledFunctions(TaskMonitor monitor) {
		monitor = TaskMonitor.dummyIfNull(monitor);
		Set<Function> set = new HashSet<>();
		Set<Reference> references = getReferencesFromBody(monitor);
		for (Reference reference : references) {
			if (monitor.isCancelled()) {
				return set;
			}
			Address toAddress = reference.getToAddress();
			Function calledFunction = manager.getFunctionAt(toAddress);
			if (calledFunction != null) {
				set.add(calledFunction);
			}
		}
		return set;
	}

	private Set<Reference> getReferencesFromBody(TaskMonitor monitor) {
		Set<Reference> set = new HashSet<>();
		ReferenceManager referenceManager = program.getReferenceManager();
		AddressSetView addresses = getBody();
		AddressIterator addressIterator = addresses.getAddresses(true);
		while (addressIterator.hasNext()) {
			if (monitor.isCancelled()) {
				return set;
			}
			Address address = addressIterator.next();
			Reference[] referencesFrom = referenceManager.getReferencesFrom(address);
			if (referencesFrom != null) {
				for (Reference reference : referencesFrom) {
					set.add(reference);
				}
			}
		}
		return set;
	}

	@Override
	public Set<FunctionTag> getTags() {

		// Don't go the database to retrieve tags unless absolutely necessary. The local
		// cache will have the current tag state unless tags have been deleted or edited; in
		// those cases the validity check will fail and we'll be forced to go back to
		// the db.
		manager.lock.acquire();

		try {

			if (checkIsValid() && tags != null) {
				return tags;
			}

			// Get a list of all tag records that map to our function.
			FunctionTagManagerDB tagManager =
				(FunctionTagManagerDB) manager.getFunctionTagManager();
			tags = tagManager.getFunctionTagsByFunctionID(getID());
		}
		catch (IOException e) {
			manager.dbError(e);
		}
		finally {
			manager.lock.release();
		}
		return tags;

	}

	@Override
	public boolean addTag(String name) {
		manager.lock.acquire();
		try {
			startUpdate();
			checkDeleted();
			FunctionTagManagerDB tagManager =
				(FunctionTagManagerDB) manager.getFunctionTagManager();
			FunctionTag tag = tagManager.getFunctionTag(name);
			if (tag == null) {
				tag = tagManager.createFunctionTag(name, "");
			}

			if (!tagManager.isTagApplied(getID(), tag.getId())) {
				tagManager.applyFunctionTag(getID(), tag.getId());

				Address addr = getEntryPoint();
				program.setChanged(ChangeManager.DOCR_TAG_ADDED_TO_FUNCTION, addr, addr, tag, tag);
			}

			// Add to local cache
			if (tags != null) {
				tags.add(tag);
			}
		}
		finally {
			endUpdate();
			manager.lock.release();
		}

		return true;
	}

	@Override
	public void removeTag(String name) {
		manager.lock.acquire();
		try {
			startUpdate();
			checkDeleted();
			FunctionTag tag = manager.getFunctionTagManager().getFunctionTag(name);
			if (tag == null) {
				return;
			}

			FunctionTagManagerDB tagManager =
				(FunctionTagManagerDB) manager.getFunctionTagManager();
			boolean removed = tagManager.removeFunctionTag(getID(), tag.getId());

			if (removed) {
				Address addr = getEntryPoint();
				program.setChanged(ChangeManager.DOCR_TAG_REMOVED_FROM_FUNCTION, addr, addr, tag,
					tag);

				// Remove from the local cache.
				if (tags != null) {
					tags.remove(tag);
				}
			}
		}
		finally {
			endUpdate();
			manager.lock.release();
		}
	}

	@Override
	public void promoteLocalUserLabelsToGlobal() {
		if (isExternal()) {
			return;
		}
		manager.lock.acquire();
		try {
			checkDeleted();
			ArrayList<Symbol> list = new ArrayList<>(20);
			for (Symbol childSymbol : program.getSymbolTable().getSymbols(this)) {
				if ((childSymbol.getSymbolType() == SymbolType.LABEL) &&
					(childSymbol.getSource() == SourceType.USER_DEFINED)) {
					list.add(childSymbol);
				}
			}
			Namespace globalNamespace = program.getGlobalNamespace();
			for (Symbol s : list) {
				try {
					s.setNamespace(globalNamespace);
				}
				catch (DuplicateNameException e) {
					// This can only occur if named symbol already exists at same address, remove symbol
					s.delete();
				}
				catch (InvalidInputException | CircularDependencyException e) {
					throw new AssertException(e);
				}
			}
		}
		finally {
			manager.lock.release();
		}
	}
}
