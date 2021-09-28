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
import java.util.function.Predicate;

import db.*;
import generic.FilteredIterator;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.code.CodeManager;
import ghidra.program.database.external.ExternalLocationDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.program.util.ChangeManager;
import ghidra.program.util.LanguageTranslator;
import ghidra.util.Lock;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Class that manages all functions within the program; there are some
 * convenience methods on Listing to create and access functions, but
 * all function related calls are routed to this class.
 *
 */
public class FunctionManagerDB implements FunctionManager {

	private final String CALLFIXUP_MAP = "CallFixup"; // string map used to store call-fixup name

	private ProgramDB program;
	private DBHandle dbHandle;
	private AddressMap addrMap;
	private DBObjectCache<FunctionDB> cache;
	private FunctionAdapter adapter;
	private ThunkFunctionAdapter thunkAdapter;
	private CallingConventionDBAdapter callingConventionAdapter;
	private Map<String, Byte> callingConventionNameToIDMap = new HashMap<>();
	private Map<Byte, String> callingConventionIDToNameMap = new HashMap<>();
	private NamespaceManager namespaceMgr;
	private SymbolManager symbolMgr;
	private CodeManager codeMgr;
	private FunctionTagManagerDB functionTagManager;
	private Namespace globalNamespace;

	private Predicate<Function> functionFilter = f -> {
		if (f != null) {
			CodeUnit codeUnitAt = program.getListing().getCodeUnitAt(f.getEntryPoint());
			if (codeUnitAt != null && codeUnitAt instanceof Instruction) {
				return true;
			}
		}
		return false;
	};

	/**
	 * TODO: use of StringPropertyMap for callFixupMap lacks the ability to listen for changes
	 * which may be made to the map directly (e.g., diff/merge)
	 */
	private StringPropertyMap callFixupMap;

	private long lastFuncID = -1;

	Lock lock;
	int oldAdapterVersion;

	/**
	 * Construct a new FunctionManager
	 * @param dbHandle data base handle
	 * @param addrMap address map for the program
	 * @param openMode CREATE, UPDATE, READ_ONLY, or UPGRADE defined in
	 * db.DBConstants
	 * @param lock the program synchronization lock
	 * @param monitor
	 * @throws VersionException if function manager's version does not match
	 * its expected version
	 * @throws CancelledException if the function table is being upgraded
	 * and the user canceled the upgrade process
	 * @throws IOException if there was a problem accessing the database
	 */
	public FunctionManagerDB(DBHandle dbHandle, AddressMap addrMap, int openMode, Lock lock,
			TaskMonitor monitor) throws VersionException, CancelledException, IOException {
		this.dbHandle = dbHandle;
		this.addrMap = addrMap;
		this.lock = lock;
		cache = new DBObjectCache<>(20);
		initializeAdapters(openMode, monitor);
		functionTagManager = new FunctionTagManagerDB(dbHandle, openMode, lock, monitor);
	}

	private void initializeAdapters(int openMode, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {
		try {
			FunctionAdapter oldAdapter = FunctionAdapter.findReadOnlyAdapter(dbHandle, addrMap);
			oldAdapterVersion = oldAdapter.getVersion();
		}
		catch (VersionException e) {
			oldAdapterVersion = -1;
		}
		adapter = FunctionAdapter.getAdapter(dbHandle, openMode, addrMap, monitor);
		thunkAdapter = ThunkFunctionAdapter.getAdapter(dbHandle, openMode, addrMap, monitor);
		callingConventionAdapter =
			CallingConventionDBAdapter.getAdapter(dbHandle, openMode, monitor);
	}

	@Override
	public ProgramDB getProgram() {
		return program;
	}

	FunctionAdapter getFunctionAdapter() {
		return adapter;
	}

	/**
	 * Get calling convention name corresponding to existing ID.  If id is no longer valid,
	 * null will be returned.
	 * @param id
	 * @return
	 */
	String getCallingConventionName(byte id) {
		if (id == CallingConventionDBAdapter.DEFAULT_CALLING_CONVENTION_ID) {
			return Function.DEFAULT_CALLING_CONVENTION_STRING;
		}
		else if (id == CallingConventionDBAdapter.UNKNOWN_CALLING_CONVENTION_ID) {
			return null;
		}
		String name = callingConventionIDToNameMap.get(id);
		if (name != null) {
			return name;
		}
		try {
			DBRecord record = callingConventionAdapter.getCallingConventionRecord(id);
			if (record == null) {
				return null;
			}

			name = record.getString(CallingConventionDBAdapter.CALLING_CONVENTION_NAME_COL);
			CompilerSpec compilerSpec = program.getCompilerSpec();
			PrototypeModel callingConvention = compilerSpec.getCallingConvention(name);
			if (callingConvention != null) {
				callingConventionIDToNameMap.put(id, name);
				callingConventionNameToIDMap.put(name, id);
				return name;
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		return null;
	}

	/**
	 * Get (and assign if needed) the ID associated with the specified calling convention name.
	 * @param name calling convention name
	 * @return calling convention ID
	 * @throws IOException
	 * @throws InvalidInputException
	 */
	byte getCallingConventionID(String name) throws InvalidInputException, IOException {
		if (name == null || name.equals(Function.UNKNOWN_CALLING_CONVENTION_STRING)) {
			return CallingConventionDBAdapter.UNKNOWN_CALLING_CONVENTION_ID;
		}
		else if (name.equals(Function.DEFAULT_CALLING_CONVENTION_STRING)) {
			return CallingConventionDBAdapter.DEFAULT_CALLING_CONVENTION_ID;
		}
		Byte id = callingConventionNameToIDMap.get(name);
		if (id != null) {
			return id;
		}
		CompilerSpec compilerSpec = program.getCompilerSpec();
		PrototypeModel callingConvention = compilerSpec.getCallingConvention(name);
		if (callingConvention == null) {
			throw new InvalidInputException("Invalid calling convention name: " + name);
		}
		DBRecord record = callingConventionAdapter.getCallingConventionRecord(name);
		if (record == null) {
			record = callingConventionAdapter.createCallingConventionRecord(name);
		}
		byte newId = record.getKeyField().getByteValue();
		callingConventionIDToNameMap.put(newId, name);
		callingConventionNameToIDMap.put(name, newId);
		return newId;
	}

	@Override
	public List<String> getCallingConventionNames() {
		CompilerSpec compilerSpec = program.getCompilerSpec();
		PrototypeModel[] namedCallingConventions = compilerSpec.getCallingConventions();
		List<String> names = new ArrayList<>(namedCallingConventions.length + 2);
		names.add(Function.UNKNOWN_CALLING_CONVENTION_STRING);
		names.add(Function.DEFAULT_CALLING_CONVENTION_STRING);
		for (PrototypeModel model : namedCallingConventions) {
			names.add(model.getName());
		}
		return names;
	}

	@Override
	public PrototypeModel getDefaultCallingConvention() {
		CompilerSpec compilerSpec = program.getCompilerSpec();
		if (compilerSpec == null) {
			return null;
		}
		return compilerSpec.getDefaultCallingConvention();
	}

	@Override
	public PrototypeModel getCallingConvention(String name) {
		CompilerSpec compilerSpec = program.getCompilerSpec();
		if (compilerSpec == null) {
			return null;
		}
		if (Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(name)) {
			return null;
		}
		if (Function.DEFAULT_CALLING_CONVENTION_STRING.equals(name)) {
			return getDefaultCallingConvention();
		}
		PrototypeModel[] models = compilerSpec.getCallingConventions();
		for (PrototypeModel model : models) {
			String modelName = model.getName();
			if (modelName != null && modelName.equals(name)) {
				return model;
			}
		}
		return null;
	}

	@Override
	public PrototypeModel[] getCallingConventions() {
		CompilerSpec compilerSpec = program.getCompilerSpec();
		if (compilerSpec == null) {
			return new PrototypeModel[0];
		}
		ArrayList<PrototypeModel> namedList = new ArrayList<>();
		PrototypeModel[] models = compilerSpec.getCallingConventions();
		for (PrototypeModel model : models) {
			String name = model.getName();
			if (name != null && name.length() > 0) {
				namedList.add(model);
			}
		}
		return namedList.toArray(new PrototypeModel[namedList.size()]);
	}

	/**
	 * Transform an existing external symbol into an external function.
	 * This method should only be invoked by an ExternalSymbol
	 * @param extSpaceAddr the external space address to use when creating this external.
	 * @param name the external function name
	 * @param nameSpace the external function namespace
	 * @param extData the external data string to store additional info (see {@link ExternalLocationDB})
	 * @param source the source of this external.
	 * @return external function
	 * @throws InvalidInputException if the name is invalid
	 * @throws DuplicateNameException if the name is an invalid duplicate
	 */
	public Function createExternalFunction(Address extSpaceAddr, String name, Namespace nameSpace,
			String extData, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		lock.acquire();
		try {

			Symbol symbol = symbolMgr.createSpecialSymbol(extSpaceAddr, name, nameSpace,
				SymbolType.FUNCTION, null, null, extData, source);

			long returnDataTypeId = program.getDataTypeManager().getResolvedID(DataType.DEFAULT);

			try {
				DBRecord rec = adapter.createFunctionRecord(symbol.getID(), returnDataTypeId);

				FunctionDB funcDB = new FunctionDB(this, cache, addrMap, rec);

				program.setObjChanged(ChangeManager.DOCR_FUNCTION_ADDED, extSpaceAddr, funcDB, null,
					null);
				return funcDB;
			}
			catch (IOException e) {
				dbError(e);
			}
			return null;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Function createFunction(String name, Address entryPoint, AddressSetView body,
			SourceType source) throws InvalidInputException, OverlappingFunctionException {
		return createFunction(name, globalNamespace, entryPoint, body, null, source);
	}

	@Override
	public Function createFunction(String name, Namespace nameSpace, Address entryPoint,
			AddressSetView body, SourceType source)
			throws InvalidInputException, OverlappingFunctionException {
		return createFunction(name, nameSpace, entryPoint, body, null, source);
	}

	@Override
	public Function createThunkFunction(String name, Namespace nameSpace, Address entryPoint,
			AddressSetView body, Function thunkedFunction, SourceType source)
			throws OverlappingFunctionException {
		try {
			return createFunction(name, nameSpace, entryPoint, body, thunkedFunction, source);
		}
		catch (InvalidInputException e) {
			throw new RuntimeException("Unexpected for default named function", e);
		}
	}

	private Function createFunction(String name, Namespace nameSpace, Address entryPoint,
			AddressSetView body, Function thunkedFunction, SourceType source)
			throws InvalidInputException, OverlappingFunctionException {

		lock.acquire();
		try {
			if (entryPoint == null || !entryPoint.isMemoryAddress()) {
				throw new IllegalArgumentException("Function entryPoint must be a memory address");
			}
			if (body == null || !body.contains(entryPoint)) {
				throw new IllegalArgumentException("Function body must contain the entrypoint");
			}
			if (codeMgr.getDefinedDataAt(entryPoint) != null &&
				!MemoryBlock.isExternalBlockAddress(entryPoint, program)) {
				throw new IllegalArgumentException(
					"Function entryPoint may not be created on defined data");
			}

			if (namespaceMgr.overlapsNamespace(body) != null) {
				throw new OverlappingFunctionException(entryPoint);
			}

			if (name == null || name.length() == 0 ||
				SymbolUtilities.isReservedDynamicLabelName(name, program.getAddressFactory())) {
				source = SourceType.DEFAULT;
				name = "";
			}

			FunctionDB refFunc = null;
			if (thunkedFunction != null) {

				refFunc = (FunctionDB) getFunctionAt(thunkedFunction.getEntryPoint());
				if (refFunc != thunkedFunction) {
					throw new IllegalArgumentException("thunkedFunction not found within program");
				}
				refFunc.checkDeleted();

				// Handle thunk function
				refFunc = (FunctionDB) getFunctionAt(thunkedFunction.getEntryPoint());
				if (refFunc != thunkedFunction) {
					throw new IllegalArgumentException("thunkedFunction not found within program");
				}

				// Check thunk function name - if name matches thunked function
				// name switch to using DEFAULT name
				if (refFunc.getName().equals(name)) {
					source = SourceType.DEFAULT;
					name = "";
				}
			}

			Symbol symbol = symbolMgr.createFunctionSymbol(entryPoint, name, nameSpace, source,
				((thunkedFunction != null) ? thunkedFunction.getEntryPoint().toString() : null));

			long returnDataTypeId = program.getDataTypeManager().getResolvedID(DataType.DEFAULT);

			try {
				if (refFunc != null) {

					String oldName = symbol.getName();
					thunkAdapter.createThunkRecord(symbol.getID(), refFunc.getID());

					// Default thunk function name changes dynamically as a result of becoming a thunk
					program.symbolChanged(symbol, ChangeManager.DOCR_SYMBOL_RENAMED, entryPoint,
						symbol, oldName, symbol.getName());
				}

				DBRecord rec = adapter.createFunctionRecord(symbol.getID(), returnDataTypeId);

				FunctionDB funcDB = new FunctionDB(this, cache, addrMap, rec);
				namespaceMgr.setBody(funcDB, body);

				program.setObjChanged(ChangeManager.DOCR_FUNCTION_ADDED, entryPoint, funcDB, null,
					null);
				return funcDB;
			}
			catch (IOException e) {
				dbError(e);
			}
			catch (OverlappingNamespaceException e) {
				throw new OverlappingFunctionException(entryPoint, e);
			}
			return null;
		}
		finally {
			lock.release();
		}
	}

	void setThunkedFunction(FunctionDB function, FunctionDB referencedFunction)
			throws IllegalArgumentException {

		if (function.isExternal()) {
			throw new UnsupportedOperationException("External functions may not be a thunk");
		}
		try {
			if (referencedFunction == null) {
				if (!function.isThunk()) {
					return;
				}
				thunkAdapter.removeThunkRecord(function.getKey());
				function.setInvalid();
			}
			else {

				FunctionDB refFunc = (FunctionDB) getFunctionAt(referencedFunction.getEntryPoint());
				if (refFunc != referencedFunction) {
					throw new IllegalArgumentException("thunkedFunction not found within program");
				}
				referencedFunction.checkDeleted();

				Function endFunction = referencedFunction;
				while (endFunction != function && endFunction.isThunk()) {
					endFunction = endFunction.getThunkedFunction(false);
				}
				if (endFunction == function) {
					throw new IllegalArgumentException(
						"Cannot create a thunk function which results in loop to itself");
				}

				Symbol s = function.getSymbol();
				String oldName = s.getName();

				thunkAdapter.createThunkRecord(function.getKey(), referencedFunction.getKey());
				function.setInvalid();

				// Default thunk function name changes dynamically as a result of becoming a thunk
				if (s.getSource() == SourceType.DEFAULT) {
					program.symbolChanged(s, ChangeManager.DOCR_SYMBOL_RENAMED,
						function.getEntryPoint(), s, oldName, s.getName());
				}
			}

			program.setObjChanged(ChangeManager.DOCR_FUNCTION_CHANGED,
				ChangeManager.FUNCTION_CHANGED_THUNK, function.getEntryPoint(), function, null,
				null);
		}
		catch (IOException e) {
			dbError(e);
		}
	}

	CodeManager getCodeManager() {
		return codeMgr;
	}

	@Override
	public int getFunctionCount() {
		return adapter.getRecordCount();
	}

	@Override
	public boolean removeFunction(Address entryPoint) {
		FunctionDB func = (FunctionDB) getFunctionAt(entryPoint);
		if (func != null) {
			return func.getSymbol().delete();
		}
		return false;
	}

	public void functionTagsChanged() {
		invalidateCache(true);
	}

	public void functionNamespaceChanged(long key) {
		lock.acquire();
		try {
			FunctionDB func = cache.get(key);
			if (func != null) {
				func.checkDeleted();
				func.createClassStructIfNeeded();
				func.updateParametersAndReturn();
			}
		}
		finally {
			lock.release();
		}
	}

	public boolean doRemoveFunction(long key) {
		lock.acquire();

		try {

			FunctionDB function = (FunctionDB) getFunction(key);
			if (function == null) {
				return false;
			}

			thunkAdapter.removeThunkRecord(key);
			function.setInvalid();

			RecordIterator thunks = thunkAdapter.iterateThunkRecords(key);
			if (thunks.hasNext()) {
				// TODO: How should thunks which refer to deleted function be handled?
				//       What about case where use is "re-creating" referenced function?
				// Delete thunks for now...
				DBRecord rec = thunks.next();
				Symbol s = symbolMgr.getSymbol(rec.getKey());
				if (s != null) {
					s.delete();
				}
			}

			Address entryPoint = function.getEntryPoint();
			function.setCallFixup(null); // clear call fixup if any exists
			AddressSetView body = new AddressSet(function.getBody());
			removeVariableRefs(function, body);
			namespaceMgr.removeBody(function);

			int n = function.getParameterCount();
			for (int i = n - 1; i >= 0; i--) {
				function.removeParameter(i);
			}

			// Remove all tag mappings associated with this function
			for (FunctionTag tag : function.getTags()) {
				function.removeTag(tag.getName());
			}

			long functionID = function.getID();
			adapter.removeFunctionRecord(functionID);
			cache.delete(functionID);

			program.setObjChanged(ChangeManager.DOCR_FUNCTION_REMOVED, entryPoint, function, body,
				null);
			return true;
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		return false;
	}

	/**
	 * Get the function with the given key.
	 * @param key ID of the function; ID is obtained by calling
	 * Function.getID()
	 * @return null if there is no function with the given key
	 */
	@Override
	public Function getFunction(long key) {
		lock.acquire();
		try {
			lastFuncID = key;
			FunctionDB func = cache.get(key);
			if (func == null) {
				try {
					DBRecord rec = adapter.getFunctionRecord(key);
					if (rec != null) {
						func = new FunctionDB(this, cache, addrMap, rec);
					}
				}
				catch (IOException e) {
					dbError(e);
				}
			}
			return func;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Function getReferencedFunction(Address address) {
		Function function = getFunctionAt(address);
		if (function != null) {
			return function;
		}
		Data data = codeMgr.getDataContaining(address);
		if (data == null) {
			return null;
		}
		Reference ref = program.getReferenceManager().getPrimaryReferenceFrom(address, 0); // assume data reference hanging on data operand
		return ref != null ? getFunctionAt(ref.getToAddress()) : null;
	}

	@Override
	public Function getFunctionAt(Address entryPoint) {
		lock.acquire();
		try {
			if (lastFuncID != -1) {
				FunctionDB function = cache.get(lastFuncID);
				if (function != null && function.getEntryPoint().equals(entryPoint)) {
					return function;
				}
			}
			Symbol symbol = program.getSymbolTable().getPrimarySymbol(entryPoint);
			if (symbol != null && symbol.getSymbolType() == SymbolType.FUNCTION) {
				return getFunction(symbol.getID());
			}
		}
		finally {
			lock.release();
		}
		return null;
	}

	@Override
	public Function getFunctionContaining(Address addr) {

		if (addr.isExternalAddress()) {
			return getFunctionAt(addr);
		}

		lock.acquire();
		try {
			if (lastFuncID != -1) {
				FunctionDB func = cache.get(lastFuncID);
				if (func != null && func.getBody().contains(addr)) {
					return func;
				}
			}
			Namespace scope = namespaceMgr.getNamespaceContaining(addr);
			Symbol symbol = scope.getSymbol();
			while (symbol != null && symbol.getSymbolType() != SymbolType.FUNCTION) {
				symbol = symbol.getParentSymbol();
			}
			if (symbol == null) {
				return null;
			}
			return getFunction(symbol.getID());
		}
		finally {
			lock.release();
		}
	}

	@Override
	public FunctionIterator getFunctions(boolean forward) {
		return new FunctionIteratorDB(false, forward);
	}

	@Override
	public FunctionIterator getFunctions(Address start, boolean foward) {
		return new FunctionIteratorDB(start, foward);
	}

	@Override
	public FunctionIterator getFunctions(AddressSetView asv, boolean forward) {
		return new FunctionIteratorDB(asv, forward);
	}

	private class FunctionFilteredIterator extends FilteredIterator<Function>
			implements FunctionIterator {
		public FunctionFilteredIterator(Iterator<Function> it) {
			super(it, functionFilter);
		}
	}

	@Override
	public FunctionIterator getFunctionsNoStubs(boolean forward) {
		return new FunctionFilteredIterator(new FunctionIteratorDB(false, forward));
	}

	@Override
	public FunctionIterator getFunctionsNoStubs(Address start, boolean foward) {
		return new FunctionFilteredIterator(new FunctionIteratorDB(start, foward));
	}

	@Override
	public FunctionIterator getFunctionsNoStubs(AddressSetView asv, boolean forward) {
		return new FunctionFilteredIterator(new FunctionIteratorDB(asv, forward));
	}

	@Override
	public FunctionIterator getExternalFunctions() {
		return new FunctionIteratorDB(true, true);
	}

	@Override
	public boolean isInFunction(Address addr) {
		if (!addr.isMemoryAddress()) {
			return false;
		}
		return getFunctionContaining(addr) != null;
	}

	/////////////////////////////////////////////////////////////////////////////////////
	//    ManagerDB methods
	////////////////////////////////////////////////////////////////////////////////////

	@Override
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException {
		invalidateCache(true);
	}

	@Override
	public void deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
		lock.acquire();
		try {
			// Remove functions which overlap deleted address range
			Iterator<Function> iter = getFunctionsOverlapping(new AddressSet(startAddr, endAddr));
			while (iter.hasNext()) {
				monitor.checkCanceled();
				FunctionDB func = (FunctionDB) iter.next();
				removeFunction(func.getEntryPoint());
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void setProgram(ProgramDB program) {
		this.program = program;
		namespaceMgr = program.getNamespaceManager();
		codeMgr = program.getCodeManager();
		symbolMgr = (SymbolManager) program.getSymbolTable();
		globalNamespace = program.getGlobalNamespace();
		functionTagManager.setProgram(program);
	}

	@Override
	public void programReady(int openMode, int currentRevision, TaskMonitor monitor)
			throws IOException, CancelledException {

		if (openMode == DBConstants.UPGRADE) {
			upgradeAllDotDotDots(monitor);
		}
	}

	/**
	 * Determine if dynamic storage will work during the upgrade of a pre-dynamic storage
	 * function.
	 * @param returnDataType
	 * @param currentParams
	 * @param paramOffset offset within currentParams for first parameter
	 * @return return variable storage if dynamic storage does not match current custom storage -
	 * this is done so that this storage can be assigned if currently <UNASSIGNED>.  If dynamic
	 * storage matches null will be returned.
	 */
	private VariableStorage checkDynamicStorageConversion(DataType returnDataType,
			Parameter[] currentParams, int paramOffset, PrototypeModel callingConvention) {
		DataType types[] = new DataType[currentParams.length - paramOffset + 1];
		types[0] = returnDataType;
		int index = 1;
		for (int i = paramOffset; i < currentParams.length; ++i) {
			types[index++] = currentParams[i].getDataType();
		}

		VariableStorage[] paramStorage =
			callingConvention.getStorageLocations(program, types, true);
// TODO: Only handles a single auto-param insertion (could be more auto-params)
		index = (paramStorage.length == types.length) ? 1 : 2; // May have inserted extra parameter
		if ((paramStorage.length - 1) != types.length) {
			return paramStorage[0];
		}
		for (int i = 0; i < currentParams.length; ++i) {
			if (!currentParams[i].getVariableStorage().equals(paramStorage[i + 1])) {
				return paramStorage[0];
			}
		}
		return null;
	}

	/**
	 * Initialize function signature source when it was first introduced and attempt to
	 * disable custom storage if possible.
	 * NOTE: This method intended to be called by ProgramDB only during appropriate upgrade.
	 * @param monitor
	 * @throws CancelledException
	 * @throws IOException
	 */
	public void initSignatureSource(TaskMonitor monitor) throws CancelledException, IOException {

		PrototypeModel defaultConvention = getDefaultCallingConvention();

		FunctionIterator functions = getFunctions(false);
		while (functions.hasNext()) {
			monitor.checkCanceled();

			// Establish signature source
			FunctionDB func = (FunctionDB) functions.next();
			func.setSignatureSource(func.getInferredSignatureSource());

			// Check to see if non-custom storage matches since it is preferred over custom
			PrototypeModel callingConvention = func.getCallingConvention();
			if (callingConvention == null) {
				callingConvention = defaultConvention;
			}
			if (callingConvention == null) {
				continue;
			}

			boolean useDynamic = false;
			DataType returnDataType = func.getReturnDataType();
			Parameter[] params = func.getParameters();

// TODO: this does not address return-storage-ptr auto-param case which will likely use custom-storage
			VariableStorage returnStorage = null;
			if (CompilerSpec.CALLING_CONVENTION_thiscall.equals(func.getCallingConventionName())) {
				if (params.length != 0 && isLikelyThisParam(params[0])) {
					returnStorage =
						checkDynamicStorageConversion(returnDataType, params, 1, callingConvention);
					if (returnStorage == null) {
						useDynamic = true;
						func.removeVariable(params[0]);
					}
				}
			}
			else {
				returnStorage =
					checkDynamicStorageConversion(returnDataType, params, 0, callingConvention);
				useDynamic = (returnStorage == null);
			}

			if (useDynamic) {
				func.setCustomVariableStorage(false);
				continue;
			}

			// Since custom storage is used (upgrade default) establish custom return storage
			if (returnStorage != null && !returnStorage.isUnassignedStorage()) {
				func.setReturnStorageAndDataType(returnStorage, returnDataType);
			}
		}
	}

	private boolean isLikelyThisParam(Parameter param) {

		if (Function.THIS_PARAM_NAME.equals(param.getName())) {
			return true;
		}
		if (param.getSource() == SourceType.DEFAULT) {
			DataType dt = param.getDataType();
			if (dt instanceof Pointer) {
				return true;
			}
			if ((dt instanceof AbstractIntegerDataType) || (dt instanceof Undefined)) {
				int pointerSize =
					program.getDataTypeManager().getDataOrganization().getPointerSize();
				return dt.getLength() == pointerSize;
			}
		}
		return false;
	}

	/**
	 * Remove parameter symbols which correspond to the 'this' parameter for all
	 * __thiscall functions using dynamic storage.
	 * NOTE: This method intended to be called by ProgramDB only during appropriate upgrade.
	 * @param monitor
	 * @throws CancelledException
	 * @throws IOException
	 */
	public void removeExplicitThisParameters(TaskMonitor monitor)
			throws CancelledException, IOException {
		FunctionIterator functions = getFunctions(false);
		while (functions.hasNext()) {
			monitor.checkCanceled();
			FunctionDB func = (FunctionDB) functions.next();
			removeExplicitThisParameters(func);
		}
		functions = getExternalFunctions();
		while (functions.hasNext()) {
			monitor.checkCanceled();
			FunctionDB func = (FunctionDB) functions.next();
			removeExplicitThisParameters(func);
		}
	}

	private void removeExplicitThisParameters(FunctionDB func) {

		// only process non-thunk __thiscall functions with dynamic storage
		if (func.isThunk() ||
			!CompilerSpec.CALLING_CONVENTION_thiscall.equals(func.getCallingConventionName()) ||
			func.hasCustomVariableStorage()) {
			return;
		}

// FIXME: this does not address return-storage-ptr auto-param case !!

		for (Parameter param : func.getParameters()) {
			if (param.isAutoParameter()) {
				continue; // ignore auto-params
			}
			if (isLikelyThisParam(param)) {
				func.removeVariable(param);
			}
			break;
		}
	}

	@Override
	public void invalidateCache(boolean all) {
		lock.acquire();
		try {
			functionTagManager.invalidateCache();
			callFixupMap = null;
			lastFuncID = -1;
			cache.invalidate();
			callingConventionIDToNameMap.clear();
			callingConventionNameToIDMap.clear();
		}
		finally {
			lock.release();
		}
	}

	StringPropertyMap getCallFixupMap(boolean create) {
		if (callFixupMap != null) {
			return callFixupMap;
		}
		PropertyMapManager usrPropertyManager = program.getUsrPropertyManager();
		callFixupMap = usrPropertyManager.getStringPropertyMap(CALLFIXUP_MAP);
		if (callFixupMap == null && create) {
			try {
				callFixupMap = usrPropertyManager.createStringPropertyMap(CALLFIXUP_MAP);
			}
			catch (DuplicateNameException e) {
				Msg.error(this, "Failed to define CallFixup due to conflicting property map name");
			}
		}
		if (callFixupMap != null) {
			// TODO: should really listen for changes made to map and generate function event
			// callFixupMap.addChangeListener(this);
		}
		return callFixupMap;
	}

	void functionChanged(FunctionDB func, int subEventType) {
		program.setObjChanged(ChangeManager.DOCR_FUNCTION_CHANGED, subEventType,
			func.getEntryPoint(), func, null, null);

		List<Long> thunkFunctionIds = getThunkFunctionIds(func.getKey());
		if (thunkFunctionIds != null) {
			for (long key : thunkFunctionIds) {
				Function thunk = getFunction(key);
				if (thunk != null) {
					program.setObjChanged(ChangeManager.DOCR_FUNCTION_CHANGED, subEventType,
						thunk.getEntryPoint(), thunk, null, null);
				}
			}
		}
	}

	void dbError(IOException e) {
		program.dbError(e);
	}

	/**
	 * Function iterator class.
	 */
	private class FunctionIteratorDB implements FunctionIterator {

		private SymbolIterator it;

		/**
		 * Construct a function iterator over all functions.
		 * @param external if true only external functions, else
		 * functions within program memory regions
		 */
		FunctionIteratorDB(boolean external, boolean forward) {
			if (external) {
				it = program.getSymbolTable()
						.getSymbols(
							new AddressSet(AddressSpace.EXTERNAL_SPACE.getMinAddress(),
								AddressSpace.EXTERNAL_SPACE.getMaxAddress()),
							SymbolType.FUNCTION, forward);
			}
			else {
				it = program.getSymbolTable()
						.getSymbols(program.getMemory(), SymbolType.FUNCTION, forward);
			}
		}

		/**
		 * Construct a function iterator over all functions residing in memory starting from the
		 * specified entry point address.
		 * @param start starting address for iteration
		 * @param forward if true iterate forward from start, otherwise iterate in reverse
		 */
		FunctionIteratorDB(Address start, boolean forward) {
			AddressFactory af = program.getAddressFactory();
			Address min = program.getMinAddress();
			Address max = program.getMaxAddress();
			AddressSet set = null;
			// Iterator only works within program memory
			if (start.isMemoryAddress() && min != null) {
				if (forward && start.compareTo(max) <= 0) {
					set = af.getAddressSet(start, max);
				}
				else if (!forward && start.compareTo(min) >= 0) {
					set = af.getAddressSet(min, start);
				}
			}
			if (set == null) {
				set = new AddressSet();
			}
			it = program.getSymbolTable().getSymbols(set, SymbolType.FUNCTION, forward);
		}

		/**
		 * Construct a function iterator over all functions residing in memory starting from the specified
		 * entry point address.
		 * @param start starting address for iteration
		 * @param forward if true iterate forward from start, otherwise iterate in reverse
		 */
		FunctionIteratorDB(AddressSetView addrSet, boolean forward) {
			it = program.getSymbolTable().getSymbols(addrSet, SymbolType.FUNCTION, forward);
		}

		/**
		 * @see java.util.Iterator#hasNext()
		 */
		@Override
		public boolean hasNext() {
			return it.hasNext();
		}

		/**
		 * @see java.util.Iterator#next()
		 */
		@Override
		public Function next() {
			SymbolDB s = (SymbolDB) it.next();
			return getFunction(s.getID());
		}

		/**
		 * @see java.util.Iterator#remove()
		 */
		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		@Override
		public Iterator<Function> iterator() {
			return this;
		}
	}

	@Override
	public Iterator<Function> getFunctionsOverlapping(AddressSetView set) {
// TODO: This may have problems once block scopes are added since
// scope manager may return block scope and not its function scope
		Iterator<Namespace> it = namespaceMgr.getNamespacesOverlapping(set);
		ArrayList<Function> list = new ArrayList<>();
		while (it.hasNext()) {
			Namespace scope = it.next();
			Symbol symbol = scope.getSymbol();
			if (symbol != null && symbol.getSymbolType() == SymbolType.FUNCTION) {
				Function f = getFunction(symbol.getID());
				if (f != null) {
					list.add(f);
				}
			}
		}
		return list.iterator();
	}

	/**
	 * Set the new body for the function.
	 */
	void setFunctionBody(FunctionDB function, AddressSetView newBody)
			throws OverlappingFunctionException {

		Address entryPoint = function.getEntryPoint();
		if (entryPoint.isExternalAddress()) {
			throw new UnsupportedOperationException("Body may not be set on external function");
		}
		if (newBody == null || !newBody.contains(entryPoint)) {
			throw new IllegalArgumentException("body must contain the entry point");
		}
		if (newBody.getNumAddresses() > Integer.MAX_VALUE) {
			throw new IllegalArgumentException(
				"Function body size must be <= 0x7fffffff byte addresses");
		}
		AddressSetView oldBody = function.getBody();

		try {
			namespaceMgr.setBody(function, newBody);
		}
		catch (OverlappingNamespaceException e) {
			throw new OverlappingFunctionException(entryPoint, e);
		}
		AddressSet set = oldBody.subtract(newBody);
		removeVariableRefs(function, set);
		removeFunctionSymbols(function, set);
		//reset the function purge, so stack references will be figures out again.
// TODO: DON'T THINK THIS SHOULD BE DONE ANYMORE!
//			function.setStackPurgeSize(Function.UNKNOWN_STACK_DEPTH_CHANGE);

		program.setObjChanged(ChangeManager.DOCR_FUNCTION_BODY_CHANGED, function.getEntryPoint(),
			function, null, null);
	}

	/**
	 * Remove symbols in the given address set and whose parent symbol is the
	 * symbol for the given function.
	 */
	private void removeFunctionSymbols(FunctionDB function, AddressSet set) {

		Symbol functionSymbol = function.getSymbol();
		ArrayList<Symbol> list = new ArrayList<>();
		SymbolIterator iter = symbolMgr.getSymbols(set, SymbolType.LABEL, true);
		while (iter.hasNext()) {
			Symbol symbol = iter.next();
			if (symbol.getParentSymbol() == functionSymbol) {
				list.add(symbol);
			}
		}
		for (Symbol symbol : list) {
			symbol.delete();
		}
	}

	/**
	 * Remove variable references in the given address set.
	 */
	private void removeVariableRefs(Function function, AddressSetView view) {
		ReferenceManager refMgr = program.getReferenceManager();
		AddressIterator iter = refMgr.getReferenceSourceIterator(view, true);
		while (iter.hasNext()) {
			Address fromAddr = iter.next();
			Reference[] refs = refMgr.getReferencesFrom(fromAddr);
			for (Reference ref : refs) {
				Address toAddr = ref.getToAddress();
				if (toAddr.isStackAddress() || toAddr.isRegisterAddress()) {
					// delete all stack and register references
					refMgr.delete(ref);
				}
				else {
					long symID = ref.getSymbolID();
					if (symID >= 0) {
						Symbol s = symbolMgr.getSymbol(symID);
						if (s instanceof VariableSymbolDB &&
							s.getParentSymbol().getID() == function.getID()) {
							if (toAddr.isMemoryAddress()) {
								// leave memory references in place
								refMgr.removeAssociation(ref);
							}
							else {
								// delete bound register references
								refMgr.delete(ref);
							}
						}
					}
				}
			}
		}
	}

	private void upgradeAllDotDotDots(TaskMonitor monitor) throws CancelledException {
		if (!isOldAdapterPreVarArgs()) {
			return;
		}
		PropertyMapManager usrPropertyManager = program.getUsrPropertyManager();
		StringPropertyMap decompilerPropertyMap =
			usrPropertyManager.getStringPropertyMap(HighFunction.DECOMPILER_TAG_MAP);
		if (decompilerPropertyMap == null) {
			return;
		}
		AddressIterator iter = decompilerPropertyMap.getPropertyIterator();
		while (iter.hasNext()) {
			monitor.checkCanceled();
			upgradeDotDotDotToVarArgs(iter.next(), decompilerPropertyMap);
		}

	}

	private void upgradeDotDotDotToVarArgs(Address addr, StringPropertyMap decompilerPropertyMap) {
		String functionString = decompilerPropertyMap.getString(addr);
		String dotstring = HighFunction.tagFindExclude("dotdotdot", functionString);
		if (dotstring != null) {
			// Since we found a dotdotdot set the function here to have VarArgs.
			Function f = getFunctionAt(addr);
			if (f != null) {
				f.setVarArgs(true);
			}
		}
	}

	private boolean isOldAdapterPreVarArgs() {
		return oldAdapterVersion == 0;
	}

	@Override
	public Variable getReferencedVariable(Address instrAddr, Address storageAddr, int size,
			boolean isRead) {

		// TODO: Add caching !!!

		lock.acquire();
		try {
			Function func = getFunctionContaining(instrAddr);
			if (func == null) {
				return null;
			}

			Variable[] variables = func.getAllVariables();

			Parameter paramCandidate = null;
			List<Variable> localCandidates = null;
			Variable firstCandidate = null;

			if (size <= 0) {
				size = 1;
			}
			Register register = program.getRegister(storageAddr, size);

			for (Variable var : variables) {

				VariableStorage variableStorage = var.getVariableStorage();

				// since we do not have size - assume any intersection with a register is a match
				if ((register != null && variableStorage.intersects(register)) ||
					(register == null && var.getVariableStorage().contains(storageAddr))) {

					if (var instanceof Parameter) {
						paramCandidate = (Parameter) var;
					}
					else if (firstCandidate != null) {
						if (localCandidates == null) {
							localCandidates = new ArrayList<>();
							localCandidates.add(firstCandidate);
						}
						localCandidates.add(var);
					}
					else {
						firstCandidate = var;
					}
				}
			}

			int useOffset = (int) instrAddr.subtract(func.getEntryPoint());
			if (isRead) {
				if (useOffset == 0) {
					return paramCandidate;
				}
				--useOffset; // read use must be in-scope prior to the use instruction
			}
			if (useOffset < 0) {
				// shift negative offsets
				useOffset = Integer.MAX_VALUE - useOffset;
			}

			if (localCandidates == null) {
				// Check single candidate
				if (firstCandidate != null) {
					int varFirstUse = firstCandidate.getFirstUseOffset();
					if (varFirstUse < 0) {
						varFirstUse = Integer.MAX_VALUE - varFirstUse;
					}
					if (varFirstUse <= useOffset) {
						return firstCandidate;
					}
				}
				return paramCandidate;
			}

			// Examine each candidate variable in list
			Variable bestVar = null;
			int bestFirstUse = 0;
			for (Variable var : localCandidates) {
				int varFirstUse = var.getFirstUseOffset();
				if (varFirstUse < 0) {
					varFirstUse = Integer.MAX_VALUE - varFirstUse;
				}
				if (varFirstUse <= useOffset && (bestVar == null || bestFirstUse < varFirstUse)) {
					bestVar = var;
					bestFirstUse = varFirstUse;
				}
			}
			if (bestVar == null) {
				bestVar = paramCandidate;
			}
			return bestVar;
		}
		finally {
			lock.release();
		}
	}

	public void replaceDataTypes(long oldDataTypeID, long newDataTypeID) {
		lock.acquire();
		try {
			RecordIterator it = adapter.iterateFunctionRecords();
			while (it.hasNext()) {
				DBRecord rec = it.next();

				if (thunkAdapter.getThunkRecord(rec.getKey()) != null) {
					continue; // skip thunks
				}

				if (rec.getLongValue(FunctionAdapter.RETURN_DATA_TYPE_ID_COL) == oldDataTypeID) {
					rec.setLongValue(FunctionAdapter.RETURN_DATA_TYPE_ID_COL, newDataTypeID);
					adapter.updateFunctionRecord(rec);
					FunctionDB functionDB = cache.get(rec);
					if (functionDB == null) {
						functionDB = new FunctionDB(this, cache, addrMap, rec);
					}
					functionChanged(functionDB, ChangeManager.FUNCTION_CHANGED_RETURN);
				}
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			cache.invalidate();
			lock.release();
		}
	}

	public boolean isThunk(long key) {
		lock.acquire();
		try {
			FunctionDB function = cache.get(key);
			if (function != null) {
				return function.isThunk();
			}
			try {
				return thunkAdapter.getThunkRecord(key) != null;
			}
			catch (IOException e) {
				dbError(e);
			}
			return false;
		}
		finally {
			lock.release();
		}
	}

	public long getThunkedFunctionId(long functionId) {
		lock.acquire();
		try {
			FunctionDB function = cache.get(functionId);
			if (function != null) {
				Function thunkedFunction = function.getThunkedFunction(false);
				return thunkedFunction != null ? thunkedFunction.getID() : -1;
			}
			try {
				DBRecord rec = thunkAdapter.getThunkRecord(functionId);
				return rec != null ? rec.getLongValue(ThunkFunctionAdapter.LINKED_FUNCTION_ID_COL)
						: -1;
			}
			catch (IOException e) {
				dbError(e);
			}
			return -1;
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Returns list of thunk function keys which reference the specified referencedFunctionKey
	 * @param referencedFunctionId
	 * @return list of thunk function IDs or null
	 */
	public List<Long> getThunkFunctionIds(long referencedFunctionId) {
		lock.acquire();
		List<Long> list = null;
		try {
			RecordIterator records = thunkAdapter.iterateThunkRecords(referencedFunctionId);
			while (records.hasNext()) {
				DBRecord rec = records.next();
				if (list == null) {
					list = new ArrayList<>(1);
				}
				list.add(rec.getKey());
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		return list;
	}

	FunctionDB getThunkedFunction(FunctionDB function) {
		DBRecord rec = null;
		try {
			rec = thunkAdapter.getThunkRecord(function.getKey());
			if (rec != null) {
				return (FunctionDB) getFunction(
					rec.getLongValue(ThunkFunctionAdapter.LINKED_FUNCTION_ID_COL));
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		return null;
	}

	/**
	 * Perform language translation.
	 * Update function return storage specifications to reflect address space and register mappings
	 * @param translator
	 * @param monitor
	 * @throws CancelledException
	 */
	public void setLanguage(LanguageTranslator translator, TaskMonitor monitor)
			throws CancelledException {
		monitor.initialize(adapter.getRecordCount());
		int cnt = 0;
		lock.acquire();
		try {
			RecordIterator recIter = adapter.iterateFunctionRecords();
			while (recIter.hasNext()) {
				monitor.checkCanceled();

				DBRecord rec = recIter.next();
				// NOTE: addrMap has already been switched-over to new language and its address spaces
				String serialization = rec.getString(FunctionAdapter.RETURN_STORAGE_COL);

				try {
					// Translate address spaces and registers
					serialization =
						VariableStorage.translateSerialization(translator, serialization);
					rec.setString(FunctionAdapter.RETURN_STORAGE_COL, serialization);
					adapter.updateFunctionRecord(rec);
				}
				catch (InvalidInputException e) {
					// Failed to process - skip record
					continue;
				}
				monitor.setProgress(++cnt);
			}
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			invalidateCache(true);
			lock.release();
		}
	}

	@Override
	public FunctionTagManager getFunctionTagManager() {
		return functionTagManager;
	}
}
