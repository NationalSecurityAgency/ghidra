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

import java.io.IOException;
import java.util.*;

import javax.help.UnsupportedOperationException;

import db.DBRecord;
import ghidra.program.database.DbObject;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.external.ExternalManagerDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.database.symbol.VariableSymbolDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.program.util.FunctionChangeRecord.FunctionChangeType;
import ghidra.program.util.ProgramEvent;
import ghidra.util.*;
import ghidra.util.Lock.Closeable;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Database implementation of a Function.
 *
 */
public class FunctionDB extends DbObject implements Function {

	final FunctionManagerDB manager;

	private FunctionDB thunkedFunction;

	private ProgramDB program;
	private Address entryPoint;
	private FunctionSymbol functionSymbol;
	private DBRecord rec;

	private FunctionStackFrame frame;

	// NOTE: FunctionDB discards the following data when invalidated/refreshed
	// All function variables instances should be dropped/re-acquired when
	// a domain object restored event occurs
	private FunctionVariables lazyVariables;

	// Tags associated with this function. This is here to keep db requests
	// to a minimum requesting all tags. Note that this list is invalidated
	// only when tags have been edited or deleted from the system.
	private Set<FunctionTag> tags;
	private int updateInProgressCount = 0;
	private boolean updateRefreshRequired = false;
	private Lock lock;

	FunctionDB(FunctionManagerDB manager, AddressMap addrMap, DBRecord rec) {
		super(rec.getKey());
		this.manager = manager;
		program = manager.getProgram();
		this.rec = rec;
		init();
		frame = new FunctionStackFrame(this);
		lock = manager.lock;
	}

	@Override
	public boolean isDeleted() {
		return isDeleted(lock);
	}

	public void setValidationEnabled(boolean state) {
		getFunctionVariables().setValidataionEnabled(state);
	}

	private void init() {
		thunkedFunction = manager.getThunkedFunction(this);
		functionSymbol = (FunctionSymbol) program.getSymbolTable().getSymbol(key);
		entryPoint = functionSymbol.getAddress();
	}

	@Override
	protected void checkDeleted() {
		// expose method to function package
		super.checkDeleted();
	}

	@Override
	public boolean isThunk() {
		validate(lock);
		return thunkedFunction != null;
	}

	@Override
	public Function getThunkedFunction(boolean recursive) {
		validate(lock);
		FunctionDB localThunkFunc = thunkedFunction;
		if (!recursive || localThunkFunc == null) {
			return localThunkFunc;
		}
		FunctionDB endFunction = localThunkFunc;
		while ((localThunkFunc = endFunction.thunkedFunction) != null) {
			endFunction = localThunkFunc;
		}
		return endFunction;
	}

	@Override
	public void setThunkedFunction(Function referencedFunction) {
		if (isExternal()) {
			throw new UnsupportedOperationException("External functions may not be a thunk");
		}
		if ((referencedFunction != null) && !(referencedFunction instanceof FunctionDB)) {
			throw new IllegalArgumentException("FunctionDB expected for referenced function");
		}
		try (Closeable c = lock.write()) {
			startUpdate();
			checkDeleted();
			// TODO: Removal all children / reset flags, etc. ??
			manager.setThunkedFunction(this, (FunctionDB) referencedFunction);
		}
		finally {
			endUpdate();
		}
	}

	private List<Address> getFunctionThunkAddresses(long functionId, boolean recursive) {
		List<Long> functionIds = manager.getThunkFunctionIds(functionId);
		if (functionIds == null) {
			return null;
		}
		SymbolTable symMgr = program.getSymbolTable();
		List<Address> thunkAddrList = new ArrayList<>();
		for (long id : functionIds) {
			Symbol s = symMgr.getSymbol(id);
			thunkAddrList.add(s.getAddress());
			if (recursive) {
				List<Address> thunkAddrs = getFunctionThunkAddresses(id, true);
				if (thunkAddrs != null) {
					thunkAddrList.addAll(thunkAddrs);
				}
			}
		}
		return thunkAddrList;
	}

	@Override
	public Address[] getFunctionThunkAddresses(boolean recursive) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			List<Address> thunkAddrList = getFunctionThunkAddresses(key, recursive);
			if (thunkAddrList == null) {
				return null;
			}
			return thunkAddrList.toArray(new Address[thunkAddrList.size()]);
		}
	}

	@Override
	public boolean isExternal() {
		return entryPoint.isExternalAddress();
	}

	@Override
	public ExternalLocation getExternalLocation() {
		if (isExternal()) {
			ExternalManagerDB extMgr = program.getExternalManager();
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

	@Override
	public String toString() {
		return getName(true);
	}

	@Override
	public String getName() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return functionSymbol.getName();
		}
	}

	@Override
	public void setName(String name, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		try (Closeable c = lock.write()) {
			startUpdate();
			checkDeleted();
			functionSymbol.setName(name, source);
		}
		finally {
			endUpdate();
		}
	}

	@Override
	public ProgramDB getProgram() {
		return manager.getProgram();
	}

	@Override
	public String getComment() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return manager.getCodeManager().getComment(CommentType.PLATE, getEntryPoint());
		}
	}

	@Override
	public String[] getCommentAsArray() {
		return StringUtilities.toLines(getComment());
	}

	@Override
	public void setComment(String comment) {
		try (Closeable c = lock.write()) {
			startUpdate();
			checkDeleted();
			manager.getCodeManager().setComment(getEntryPoint(), CommentType.PLATE, comment);
		}
		finally {
			endUpdate();
		}
	}

	@Override
	public String getRepeatableComment() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return manager.getCodeManager().getComment(CommentType.REPEATABLE, getEntryPoint());
		}
	}

	@Override
	public String[] getRepeatableCommentAsArray() {
		return StringUtilities.toLines(getRepeatableComment());
	}

	@Override
	public void setRepeatableComment(String comment) {
		try (Closeable c = lock.write()) {
			checkDeleted();
			manager.getCodeManager().setComment(getEntryPoint(), CommentType.REPEATABLE, comment);
		}
	}

	@Override
	public Address getEntryPoint() {
		validate(lock);
		return entryPoint;
	}

	@Override
	public AddressSetView getBody() {
		try (Closeable c = lock.read()) {
			if (!refreshIfNeeded()) {
				// Function or its symbol has been deleted
				return new AddressSet(entryPoint, entryPoint);
			}
			return program.getNamespaceManager().getAddressSet(this);
		}
	}

	@Override
	public void setBody(AddressSetView set) throws OverlappingFunctionException {
		try (Closeable c = lock.write()) {
			startUpdate();
			checkDeleted();
			manager.setFunctionBody(this, set);
		}
		finally {
			endUpdate();
		}
	}

	@Override
	public DataType getReturnType() {
		return getReturn().getDataType();
	}

	@Override
	public ReturnParameterDB getReturn() {
		try (Closeable c = lock.read()) {
			validate(lock);
			FunctionDB localThunkFunc = thunkedFunction;
			if (localThunkFunc != null) {
				return localThunkFunc.getReturn();
			}
			FunctionVariables vars = getFunctionVariables();
			return vars.getReturnParam();
		}
	}

	private FunctionVariables getFunctionVariables() {
		FunctionVariables local = lazyVariables;
		if (local == null) {
			local = new FunctionVariables(this, hasCustomVariableStorage());
			lazyVariables = local;
		}
		return local;
	}

	@Override
	public void setReturn(DataType type, VariableStorage storage, SourceType source)
			throws InvalidInputException {
		try (Closeable c = lock.write()) {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				thunkedFunction.setReturn(type, storage, source);
				return;
			}
			type = type.clone(program.getDataTypeManager());
			if (VoidDataType.isVoidDataType(type)) {
				storage = VariableStorage.VOID_STORAGE;
			}
			else if (storage.isValid() && (storage.size() != type.getLength())) {
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
		}
	}

	@Override
	public void setReturnType(DataType type, SourceType source) throws InvalidInputException {
		try (Closeable c = lock.write()) {
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
		}
	}

	void setReturnStorageAndDataType(VariableStorage storage, DataType type) throws IOException {
		if (storage != null && storage.isUnassignedStorage()) {
			storage = null;
		}
		long typeId = program.getDataTypeManager().getResolvedID(type);
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

	VariableStorage getReturnStorage(boolean hasCustomStorage) {
		VariableStorage returnStorage = VariableStorage.UNASSIGNED_STORAGE;
		if (hasCustomStorage) {
			String serializedStorage = rec.getString(FunctionAdapter.RETURN_STORAGE_COL);
			if (serializedStorage != null) {
				returnStorage = deserializeStorage(serializedStorage);
			}
		}
		return returnStorage;
	}

	VariableStorage deserializeStorage(String serializedStorage) {
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

	@Override
	public FunctionSignature getSignature(boolean formalSignature) {
		return new FunctionDefinitionDataType(this, formalSignature);
	}

	@Override
	public FunctionSignature getSignature() {
		return getSignature(false);
	}

	@Override
	public String getPrototypeString(boolean formalSignature, boolean includeCallingConvention) {
		try (Closeable c = lock.read()) {
			if (!refreshIfNeeded()) {
				return "undefined " + getName() + "()";
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
	}

	void updateSignatureSourceAfterVariableChange(SourceType variableSourceType,
			DataType variableDataType) {
		if (Undefined.isUndefined(variableDataType)) {
			return;
		}
		// TODO: It seems that the lowest parameter priority should win out (see GP-6013)
		if (variableSourceType.isHigherPriorityThan(getStoredSignatureSource())) {
			setSignatureSource(variableSourceType);
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

		// TODO: It seems that the lowest parameter priority should win out (see GP-6013)
		Parameter[] parameters = getParameters();
		for (Parameter parameter : parameters) {
			if (Undefined.isUndefined(parameter.getDataType())) {
				continue;
			}
			SourceType paramSourceType = parameter.getSource();
			if (paramSourceType.isHigherOrEqualPriorityThan(SourceType.IMPORTED)) {
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
		validate(lock);
		FunctionDB localThunkFunc = thunkedFunction;
		if (localThunkFunc != null) {
			return thunkedFunction.getStackFrame();
		}
		return frame;
	}

	@Override
	public int getStackPurgeSize() {
		validate(lock);
		FunctionDB localThunkFunc = thunkedFunction;
		if (localThunkFunc != null) {
			return localThunkFunc.getStackPurgeSize();
		}
		return rec.getIntValue(FunctionAdapter.STACK_PURGE_COL);
	}

	@Override
	public void setStackPurgeSize(int change) {
		try (Closeable c = lock.write()) {
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
				manager.functionChanged(this, PURGE_CHANGED);
			}
			catch (IOException e) {
				manager.dbError(e);
			}
			frame.setInvalid();
		}
		finally {
			endUpdate();
		}
	}

	@Override
	public boolean isStackPurgeSizeValid() {
		validate(lock);
		FunctionDB localThunkFunc = thunkedFunction;
		if (localThunkFunc != null) {
			return localThunkFunc.isStackPurgeSizeValid();
		}
		return getStackPurgeSize() <= 0xffffff;
	}

	@Override
	public long getID() {
		return key;
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
		try (Closeable c = lock.write()) {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				return thunkedFunction.addLocalVariable(var, source);
			}
			return getFunctionVariables().addLocalVariable(this, var, source);
		}
		finally {
			endUpdate();
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
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			if (thunkedFunction != null) {
				Variable[] variables =
					thunkedFunction.getVariables(new ThunkVariableFilter(filter));
				return adjustThunkThisParameter(variables);
			}
			FunctionVariables variables = getFunctionVariables();
			return variables.getVariables(filter);
		}
	}

	@Override
	public Variable[] getAllVariables() {
		return getVariables(null);
	}

	@Override
	public Parameter[] getParameters(VariableFilter filter) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			if (thunkedFunction != null) {
				Parameter[] parameters = thunkedFunction.getParameters(filter);
				return adjustThunkThisParameter(parameters);
			}
			return getFunctionVariables().getParameters(filter);
		}
	}

	@Override
	public Parameter[] getParameters() {
		return getParameters(null);
	}

	@Override
	public Variable[] getLocalVariables(VariableFilter filter) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			if (thunkedFunction != null) {
				return new Variable[0];
			}
			return getFunctionVariables().getLocalVariables(filter);
		}
	}

	@Override
	public Variable[] getLocalVariables() {
		return getLocalVariables(null);
	}

	@Override
	public int getParameterCount() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			if (thunkedFunction != null) {
				return thunkedFunction.getParameterCount();
			}
			return getFunctionVariables().getParameterCount();
		}
	}

	@Override
	public int getAutoParameterCount() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			if (thunkedFunction != null) {
				return thunkedFunction.getParameterCount();
			}
			return getFunctionVariables().getAutoParamCount();
		}
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

		try (Closeable c = lock.write()) {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				thunkedFunction.updateFunction(callingConvention, returnVar, newParams, updateType,
					force, source);
				return;
			}
			boolean useCustomStorage = (updateType == FunctionUpdateType.CUSTOM_STORAGE);
			setCustomVariableStorage(useCustomStorage);
			if (callingConvention != null) {
				setCallingConvention(callingConvention);
			}

			callingConvention = getCallingConventionName();

			getFunctionVariables().updateFunction(this, callingConvention, returnVar, newParams,
				updateType, force, source);

			if (source != getStoredSignatureSource()) {
				setSignatureSource(source);
			}
			manager.functionChanged(this, PARAMETERS_CHANGED);
		}
		finally {
			frame.setInvalid();
			endUpdate();
		}
	}

	@Override
	public Parameter addParameter(Variable var, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		try (Closeable c = lock.write()) {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				return thunkedFunction.addParameter(var, source);
			}
			return getFunctionVariables().insertParameter(this, getParameterCount(), var, source);

		}
		finally {
			endUpdate();
		}
	}

	/**
	 * @see ghidra.program.model.listing.Function#insertParameter(int, ghidra.program.model.listing.Variable, ghidra.program.model.symbol.SourceType)
	 */
	@Override
	public ParameterDB insertParameter(int ordinal, Variable var, SourceType source)
			throws DuplicateNameException, InvalidInputException {

		try (Closeable c = lock.write()) {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				return thunkedFunction.insertParameter(ordinal, var, source);
			}
			return getFunctionVariables().insertParameter(this, ordinal, var, source);
		}
		finally {
			endUpdate();
		}
	}

	@Override
	public void removeVariable(Variable variable) {
		try (Closeable c = lock.write()) {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				thunkedFunction.removeVariable(variable);
				return;
			}
			getFunctionVariables().removeVariable(variable);
		}
		finally {
			endUpdate();
		}
	}

	@Override
	public void removeParameter(int ordinal) {
		try (Closeable c = lock.write()) {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				thunkedFunction.removeParameter(ordinal);
				return;
			}
			getFunctionVariables().removeParameter(ordinal);
		}
		finally {
			endUpdate();
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
		lazyVariables = null;
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
		try {
			startUpdate();
			if (!refreshIfNeeded()) {
				return;
			}
			getFunctionVariables().doDeleteVariable(this, symbol);
		}
		finally {
			endUpdate();
		}
	}

	/**
	 * Return the Variable for the given symbol.
	 *
	 * @param symbol variable symbol
	 * @return Variable which corresponds to specified symbol
	 */
	public Variable getVariable(VariableSymbolDB symbol) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return getFunctionVariables().getVariable(symbol);
		}
	}

	@Override
	public Parameter getParameter(int ordinal) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			if (ordinal == Parameter.RETURN_ORIDINAL) {
				return getReturn();
			}
			return getFunctionVariables().getParameter(ordinal);
		}
	}

	@Override
	public Parameter moveParameter(int fromOrdinal, int toOrdinal) throws InvalidInputException {
		if (toOrdinal < 0) {
			throw new InvalidInputException("invalid toOrdinal specified: " + toOrdinal);
		}
		try (Closeable c = lock.write()) {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				return thunkedFunction.moveParameter(fromOrdinal, toOrdinal);
			}
			return getFunctionVariables().moveParameter(this, fromOrdinal, toOrdinal);
		}
		finally {
			endUpdate();
		}
	}

	void setLocalSize(int size) {
		try (Closeable c = lock.write()) {
			startUpdate();
			checkDeleted();
			if (size < 0) {
				throw new IllegalArgumentException("invalid local size: " + size);
			}
			rec.setIntValue(FunctionAdapter.STACK_LOCAL_SIZE_COL, size);
			try {
				manager.getFunctionAdapter().updateFunctionRecord(rec);
				manager.functionChanged(this, null);
			}
			catch (IOException e) {
				manager.dbError(e);
			}
			frame.setInvalid();
		}
		finally {
			endUpdate();
		}
	}

	int getReturnAddressOffset() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return rec.getIntValue(FunctionAdapter.STACK_RETURN_OFFSET_COL);
		}
	}

	void setReturnAddressOffset(int offset) {
		try (Closeable c = lock.write()) {
			startUpdate();
			checkDeleted();
			rec.setIntValue(FunctionAdapter.STACK_RETURN_OFFSET_COL, offset);
			try {
				manager.getFunctionAdapter().updateFunctionRecord(rec);
				manager.functionChanged(this, null);
			}
			catch (IOException e) {
				manager.dbError(e);
			}
			frame.setInvalid();
		}
		finally {
			endUpdate();
		}
	}

	@Override
	public Symbol getSymbol() {
		return functionSymbol;
	}

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
		try (Closeable c = lock.write()) {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				thunkedFunction.setVarArgs(hasVarArgs);
			}
			else if (hasVarArgs != hasVarArgs()) {
				setFunctionFlag(FunctionAdapter.FUNCTION_VARARG_FLAG, hasVarArgs);
				manager.functionChanged(this, PARAMETERS_CHANGED);
			}
		}
		finally {
			endUpdate();
		}
	}

	@Override
	public boolean isInline() {
		return isFunctionFlagSet(FunctionAdapter.FUNCTION_INLINE_FLAG);
	}

	@Override
	public void setInline(boolean isInline) {
		try (Closeable c = lock.write()) {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				thunkedFunction.setInline(isInline);
			}
			else if (!isExternal() && isInline != isInline()) {
				// only non-external functions may be inline
				setFunctionFlag(FunctionAdapter.FUNCTION_INLINE_FLAG, isInline);
				manager.functionChanged(this, INLINE_CHANGED);
			}
		}
		finally {
			endUpdate();
		}
	}

	@Override
	public boolean hasNoReturn() {
		return isFunctionFlagSet(FunctionAdapter.FUNCTION_NO_RETURN_FLAG);
	}

	@Override
	public void setNoReturn(boolean hasNoReturn) {
		try (Closeable c = lock.write()) {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				thunkedFunction.setNoReturn(hasNoReturn);
			}
			else if (hasNoReturn != hasNoReturn()) {
				setFunctionFlag(FunctionAdapter.FUNCTION_NO_RETURN_FLAG, hasNoReturn);
				manager.functionChanged(this, NO_RETURN_CHANGED);
			}
		}
		finally {
			endUpdate();
		}
	}

	@Override
	public boolean hasCustomVariableStorage() {
		return isFunctionFlagSet(FunctionAdapter.FUNCTION_CUSTOM_PARAM_STORAGE_FLAG);
	}

	@Override
	public void setCustomVariableStorage(boolean hasCustomVariableStorage) {
		try (Closeable c = lock.write()) {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				thunkedFunction.setCustomVariableStorage(hasCustomVariableStorage);
				return;
			}
			if (hasCustomVariableStorage == hasCustomVariableStorage()) {
				return;
			}
			try {
				getFunctionVariables().setCustomVariableStorage(this, hasCustomVariableStorage);
			}
			catch (InvalidInputException e) {
				throw new AssertException(e); // should not occur
			}
			manager.functionChanged(this, PARAMETERS_CHANGED);
		}
		finally {
			endUpdate();
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
		validate(lock);
		FunctionDB localThunkFunc = thunkedFunction;
		if (localThunkFunc != null) {
			return localThunkFunc.isFunctionFlagSet(functionFlagIndicator);
		}
		byte flags = rec.getByteValue(FunctionAdapter.FUNCTION_FLAGS_COL);
		return ((flags & functionFlagIndicator) != 0);
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
	void setFunctionFlag(byte functionFlagIndicator, boolean shouldBeSet) {
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
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			if (thunkedFunction != null) {
				return thunkedFunction.getSignatureSource();
			}

			return getStoredSignatureSource();
		}
	}

	SourceType getStoredSignatureSource() {
		byte flags = rec.getByteValue(FunctionAdapter.FUNCTION_FLAGS_COL);
		int sourceTypeId = (flags &
			FunctionAdapter.FUNCTION_SIGNATURE_SOURCE) >>> FunctionAdapter.FUNCTION_SIGNATURE_SOURCE_SHIFT;
		return SourceType.getSourceType(sourceTypeId);
	}

	@Override
	public void setSignatureSource(SourceType signatureSource) {
		try (Closeable c = lock.write()) {
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
				manager.functionChanged(this, null);
			}
			catch (IOException e) {
				manager.dbError(e);
			}
		}
		finally {
			endUpdate();
		}
	}

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

	@Override
	public String getCallingConventionName() {
		if (!validate(lock)) {
			return UNKNOWN_CALLING_CONVENTION_STRING;
		}
		FunctionDB localThunkFunc = thunkedFunction;
		if (localThunkFunc != null) {
			return localThunkFunc.getCallingConventionName();
		}
		byte callingConventionID = rec.getByteValue(FunctionAdapter.CALLING_CONVENTION_ID_COL);
		// NOTE: If ID is invalid unknown calling convention name will be returned
		return program.getDataTypeManager().getCallingConventionName(callingConventionID);
	}

	private String getRealCallingConventionName() {
		// NOTE: Method only invoked from locked-block
		if (thunkedFunction != null) {
			return thunkedFunction.getRealCallingConventionName();
		}
		byte callingConventionID = rec.getByteValue(FunctionAdapter.CALLING_CONVENTION_ID_COL);
		String name = program.getDataTypeManager().getCallingConventionName(callingConventionID);
		if (UNKNOWN_CALLING_CONVENTION_STRING.equals(name) ||
			DEFAULT_CALLING_CONVENTION_STRING.equals(name)) {
			name = null;
		}
		// null returned for unknown or default calling convention
		return name;
	}

	@Override
	public void setCallingConvention(String name) throws InvalidInputException {
		try (Closeable c = lock.write()) {
			startUpdate();
			checkDeleted();
			if (thunkedFunction != null) {
				thunkedFunction.setCallingConvention(name);
				return;
			}

			byte newCallingConventionID =
				program.getDataTypeManager().getCallingConventionID(name, true);
			byte oldCallingConventionID =
				rec.getByteValue(FunctionAdapter.CALLING_CONVENTION_ID_COL);

			if (oldCallingConventionID == newCallingConventionID) {
				return; // no change
			}

			rec.setByteValue(FunctionAdapter.CALLING_CONVENTION_ID_COL, newCallingConventionID);
			manager.getFunctionAdapter().updateFunctionRecord(rec);

			boolean hasCustomStorage = hasCustomVariableStorage();
			FunctionVariables variables = getFunctionVariables();
			frame.setInvalid();

			if (!hasCustomStorage) {
				createClassStructIfNeeded(); // TODO: How should thunks within Class namespace be handled?
				variables.removeExplicitThisParameter(this);
				variables.updateParametersAndReturn(this, hasCustomStorage); // assign dynamic storage
				manager.functionChanged(this, PARAMETERS_CHANGED);
				manager.functionChanged(this, RETURN_TYPE_CHANGED);
			}
			else {
				manager.functionChanged(this, null); // change did not affect parameters
			}
		}
		catch (IOException e) {
			manager.dbError(e);
		}
		finally {
			endUpdate();
		}
	}

	void createClassStructIfNeeded() {
		PrototypeModel callingConvention = getCallingConvention();
		if (callingConvention == null ||
			!CompilerSpec.CALLING_CONVENTION_thiscall.equals(callingConvention.getName())) {
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
			if (classStruct != null) {
				dataTypeManager.resolve(classStruct, null);
			}
		}
	}

	void dataTypeChanged(VariableDB var) {
		manager.functionChanged(this, (var instanceof Parameter) ? PARAMETERS_CHANGED : null);
	}

	@Override
	public String getCallFixup() {
		if (!validate(lock)) {
			return null;
		}
		FunctionDB localThunkFunc = thunkedFunction;
		if (localThunkFunc != null) {
			return localThunkFunc.getCallFixup();
		}
		StringPropertyMap callFixupMap = manager.getCallFixupMap(false);
		if (callFixupMap == null) {
			return null;
		}
		return callFixupMap.getString(entryPoint);
	}

	@Override
	public void setCallFixup(String name) {
		try (Closeable c = lock.write()) {
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
			manager.functionChanged(this, CALL_FIXUP_CHANGED);
		}
		finally {
			endUpdate();
		}
	}

	@Override
	public Set<Function> getCallingFunctions(TaskMonitor monitor) {
		monitor = TaskMonitor.dummyIfNull(monitor);
		Set<Function> callers = new HashSet<>();
		ReferenceIterator iter = program.getReferenceManager().getReferencesTo(getEntryPoint());

		while (iter.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}
			Reference reference = iter.next();
			if (!reference.getReferenceType().isCall()) {
				continue;
			}
			Address fromAddress = reference.getFromAddress();
			Function callerFunction = manager.getFunctionContaining(fromAddress);
			if (callerFunction != null) {
				callers.add(callerFunction);
			}
		}
		return callers;
	}

	@Override
	public Set<Function> getCalledFunctions(TaskMonitor monitor) {
		monitor = TaskMonitor.dummyIfNull(monitor);
		Set<Function> callees = new HashSet<>();
		ReferenceManager refManager = program.getReferenceManager();
		AddressRangeIterator rangeIter = getBody().getAddressRanges();

		while (rangeIter.hasNext()) {
			AddressRange range = rangeIter.next();
			ReferenceIterator refIter = refManager.getReferenceIterator(range.getMinAddress());
			while (refIter.hasNext()) {
				if (monitor.isCancelled()) {
					return callees;
				}
				Reference ref = refIter.next();
				if (!range.contains(ref.getFromAddress())) {
					break; // exhausted all addresses in the AddressRange, check next AddressRange
				}
				if (!ref.getReferenceType().isCall()) {
					continue; // reference is not a call, check next reference
				}
				Function callee = manager.getFunctionAt(ref.getToAddress());
				if (callee != null) {  // sanity check
					callees.add(callee);
				}
			}
		}
		return callees;
	}

	@Override
	public Set<FunctionTag> getTags() {

		// Don't go the database to retrieve tags unless absolutely necessary. The local
		// cache will have the current tag state unless tags have been deleted or edited; in
		// those cases the validity check will fail and we'll be forced to go back to
		// the db.
		try (Closeable c = lock.read()) {

			if (refreshIfNeeded() && tags != null) {
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
		return tags;

	}

	@Override
	public boolean addTag(String name) {
		try (Closeable c = lock.write()) {
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
				program.setChanged(ProgramEvent.FUNCTION_TAG_APPLIED, addr, addr, tag, tag);
			}

			// Add to local cache
			if (tags != null) {
				tags.add(tag);
			}
		}
		finally {
			endUpdate();
		}

		return true;
	}

	@Override
	public void removeTag(String name) {
		try (Closeable c = lock.write()) {
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
				program.setChanged(ProgramEvent.FUNCTION_TAG_UNAPPLIED, addr, addr, tag, tag);

				// Remove from the local cache.
				if (tags != null) {
					tags.remove(tag);
				}
			}
		}
		finally {
			endUpdate();
		}
	}

	@Override
	public void promoteLocalUserLabelsToGlobal() {
		if (isExternal()) {
			return;
		}
		try (Closeable c = lock.write()) {
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
	}

	void functionChanged(FunctionChangeType type) {
		manager.functionChanged(this, type);
	}

	void invalidateFrame() {
		frame.setInvalid();

	}

	void updateParametersAndReturn() {
		if (lazyVariables == null) {
			return;
		}
		getFunctionVariables().updateParametersAndReturn(this, hasCustomVariableStorage());
	}
}
