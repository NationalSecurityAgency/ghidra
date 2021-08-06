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
package ghidra.program.model.pcode;

import java.util.*;

import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.*;

/**
 * <code>HighFunctionDBUtil</code> provides various methods for updating the state of a
 * function contained within a program database.  It is important to note that the decompiler
 * result state (e.g., HighFunction, HighParam, HighLocal, etc.) is not altered by any of
 * these methods.  A new decompiler result will need to be generated to reflect any
 * changes made to the database.  Care must be taken when making incremental changes
 * to multiple elements (e.g., Variables)
 */
public class HighFunctionDBUtil {

	public static final String AUTO_CAT = "/auto_proto"; // Category for auto generated prototypes

	/**
	 * Commit the decompiler's version of the function return data-type to the database.
	 * The decompiler's version of the prototype model is committed as well
	 * @param highFunction is the decompiler's model of the function
	 * @param source is the desired SourceType for the commit
	 */
	public static void commitReturnToDatabase(HighFunction highFunction, SourceType source) {
		try {

			// Change calling convention if needed
			Function function = highFunction.getFunction();
			String convention = function.getCallingConventionName();
			String modelName = highFunction.getFunctionPrototype().getModelName();
			if (modelName != null && !modelName.equals(convention)) {
				function.setCallingConvention(modelName);
			}

			// TODO: no return storage currently returned from Decompiler
			//highFunction.getFunction().setReturn(type, storage, source)

			DataType dataType = highFunction.getFunctionPrototype().getReturnType();
			if (dataType == null) {
				dataType = DefaultDataType.dataType;
				source = SourceType.DEFAULT;
			}
			function.setReturnType(dataType, source);
		}
		catch (InvalidInputException e) {
			Msg.error(HighFunctionDBUtil.class, e.getMessage());
		}
	}

	/**
	 * Commit all parameters associated with HighFunction to the underlying database.
	 * @param highFunction is the associated HighFunction
	 * @param useDataTypes is true if the HighFunction's parameter data-types should be committed
	 * @param source is the signature source type to set
	 * @throws DuplicateNameException if commit of parameters caused conflict with other
	 * local variable/label.
	 * @throws InvalidInputException if specified storage is invalid
	 */
	public static void commitParamsToDatabase(HighFunction highFunction, boolean useDataTypes,
			SourceType source) throws DuplicateNameException, InvalidInputException {
		Function function = highFunction.getFunction();

		List<Parameter> params = getParameters(highFunction, useDataTypes);

		FunctionPrototype functionPrototype = highFunction.getFunctionPrototype();
		String modelName = (functionPrototype != null) ? functionPrototype.getModelName() : null;
		commitParamsToDatabase(function, modelName, params,
			highFunction.getFunctionPrototype().isVarArg(), true, source);
	}

	private static List<Parameter> getParameters(HighFunction highFunction, boolean useDataTypes)
			throws InvalidInputException {
		Function function = highFunction.getFunction();
		Program program = function.getProgram();
		DataTypeManager dtm = program.getDataTypeManager();
		LocalSymbolMap symbolMap = highFunction.getLocalSymbolMap();
		List<Parameter> params = new ArrayList<Parameter>();
		int paramCnt = symbolMap.getNumParams();
		for (int i = 0; i < paramCnt; ++i) {
			HighSymbol param = symbolMap.getParamSymbol(i);
			String name = param.getName();
			DataType dataType;
			if (useDataTypes) {
				dataType = param.getDataType();
			}
			else {
				dataType = Undefined.getUndefinedDataType(param.getSize());
				dataType = dataType.clone(dtm);
			}
			params.add(new ParameterImpl(name, dataType, param.getStorage(), program));
		}
		return params;
	}

	/**
	 * Commit a specified set of parameters for the given function to the database.
	 * The name, data-type, and storage is committed for each parameter.  The parameters are
	 * provided along with a formal PrototypeModel.  If the parameters fit the model, they are
	 * committed using "dynamic" storage. Otherwise, they are committed using "custom" storage.
	 * @param function is the Function being modified
	 * @param modelName is the name of the underlying PrototypeModel
	 * @param params is the formal list of parameter objects
	 * @param hasVarArgs is true if the prototype can take variable arguments
	 * @param renameConflicts if true any name conflicts will be resolved
	 * by renaming the conflicting local variable/label
	 * @param source source type
	 * @throws DuplicateNameException if commit of parameters caused conflict with other
	 * local variable/label.  Should not occur if renameConflicts is true.
	 * @throws InvalidInputException for invalid variable names or for parameter data-types that aren't fixed length
	 * @throws DuplicateNameException is there are collisions between variable names in the function's scope 
	 */
	public static void commitParamsToDatabase(Function function, String modelName,
			List<Parameter> params, boolean hasVarArgs, boolean renameConflicts, SourceType source)
			throws DuplicateNameException, InvalidInputException {

		try {
			function.updateFunction(modelName, null, params,
				FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, source);
		}
		catch (DuplicateNameException e) {
			if (!renameConflicts) {
				throw e;
			}
			for (Variable param : params) {
				changeConflictingSymbolNames(param.getName(), null, function);
			}
			function.updateFunction(modelName, null, params,
				FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, source);
		}

		if (!VariableUtilities.storageMatches(params, function.getParameters())) {
			// try again if dynamic storage assignment does not match decompiler's
			// force into custom storage mode
			function.updateFunction(modelName, null, params, FunctionUpdateType.CUSTOM_STORAGE,
				true, source);
		}

		if (function.hasVarArgs() != hasVarArgs) {
			function.setVarArgs(hasVarArgs);
		}
	}

	private static void changeConflictingSymbolNames(String name, Variable ignoreVariable,
			Function func) {

		String newName = name;

		Symbol sym = func.getProgram().getSymbolTable().getVariableSymbol(newName, func);

		// no problem if no symbol, or symbol is at this address
		if (sym == null || sym.isDynamic()) {
			return;
		}

		if (ignoreVariable != null && sym.equals(ignoreVariable.getSymbol())) {
			return;
		}

		// move the offending symbol to a new location
		for (int i = 1; i < Integer.MAX_VALUE; i++) {
			newName = name + "_" + i;
			try {
				sym.setName(newName, sym.getSource());
				break;
			}
			catch (DuplicateNameException e) {
				// Continue looping until we get a unique symbol name
			}
			catch (InvalidInputException e) {
				break;
			}
		}
	}

	/**
	 * Commit local variables from the decompiler's model of the function to the database.
	 * This does NOT include formal function parameters.
	 * @param highFunction is the decompiler's model of the function
	 * @param source is the desired SourceType for the commit
	 */
	public static void commitLocalNamesToDatabase(HighFunction highFunction, SourceType source) {

		Function function = highFunction.getFunction();

		clearObsoleteDynamicLocalsFromDatabase(highFunction);

		Iterator<HighSymbol> iter = highFunction.getLocalSymbolMap().getSymbols();
		while (iter.hasNext()) {
			HighSymbol sym = iter.next();
			if (sym.isParameter() || sym.isGlobal()) {
				continue;
			}
			String name = sym.getName();
			try {
				HighFunctionDBUtil.updateDBVariable(sym, null, null, source);
			}
			catch (UsrException e) {
				Msg.error(HighFunctionDBUtil.class, "Local variable commit failed for " +
					function.getName() + ":" + name + " : " + e.getMessage());
			}
		}
	}

	/**
	 * Create a local DB variable with a default name. Storage and data-type for the variable
	 * are provided explicitly.
	 * @param function is the function owning the new variable
	 * @param dt is the given data-type
	 * @param storage is the given storage
	 * @param pcAddr is point where the variable is instantiated or null
	 * @param source is the source type of the new variable
	 * @return the new local variable
	 * @throws InvalidInputException is a valid variable can't be created
	 */
	private static Variable createLocalVariable(Function function, DataType dt,
			VariableStorage storage, Address pcAddr, SourceType source)
			throws InvalidInputException {
		Program program = function.getProgram();
		int firstUseOffset = 0;
		if (pcAddr != null) {
			firstUseOffset = (int) pcAddr.subtract(function.getEntryPoint());
		}
		Variable var = new LocalVariableImpl(null, firstUseOffset, dt, storage, program);
		try {
			var = function.addLocalVariable(var, source);
		}
		catch (DuplicateNameException e) {
			throw new AssertException("Unexpected exception with default name", e);
		}

		Register reg = var.getRegister();
		if (reg != null) {
			program.getReferenceManager()
					.addRegisterReference(pcAddr, -1, reg, RefType.WRITE, source);
		}

		return var;
	}

	private static void clearObsoleteDynamicLocalsFromDatabase(HighFunction highFunction) {
		Function function = highFunction.getFunction();
		Variable[] variables = function.getLocalVariables();
		for (Variable var : variables) {
			if (var.isUniqueVariable() && !isValidUniqueVariable(highFunction, var)) {
				function.removeVariable(var);
			}
		}
	}

	private static boolean isValidUniqueVariable(HighFunction highFunction, Variable var) {
		if (!var.isUniqueVariable()) {
			return false;
		}
		long hash = var.getFirstStorageVarnode().getOffset();
		Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
		while (symbols.hasNext()) {
			HighSymbol symbol = symbols.next();
			SymbolEntry entry = symbol.getFirstWholeMap();
			if (!(entry instanceof DynamicEntry)) {
				continue;
			}
			// Note: assumes there is only one hash method used for unique locals
			if (((DynamicEntry) entry).getHash() == hash) {
				if (symbol.getHighVariable() != null) {
					return true;		// Hash successfully attached to a variable
				}
			}
		}
		return false;
	}

	/**
	 * Given a particular seed Variable, find the set of local Variables that are intended to be
	 * merged containing that seed. The result will be an array with at least the seed variable in it.
	 * @param function is the function containing the local variables
	 * @param seed is the seed local variable
	 * @return an array of all Variables intended to be merged.
	 */
	private static Variable[] gatherMergeSet(Function function, Variable seed) {
		TreeMap<String, Variable> nameMap = new TreeMap<String, Variable>();
		for (Variable var : function.getAllVariables()) {
			nameMap.put(var.getName(), var);
		}
		String baseName = seed.getName();
		int pos = baseName.lastIndexOf('$');
		if (pos >= 0) {
			baseName = baseName.substring(0, pos);
		}
		DataType dataType = seed.getDataType();
		Variable currentVar = nameMap.get(baseName);
		int index = 0;
		boolean sawSeed = false;
		ArrayList<Variable> mergeArray = new ArrayList<Variable>();
		for (;;) {
			if (currentVar == null) {
				break;
			}
			if (!currentVar.getDataType().equals(dataType)) {
				break;
			}
			if (index != 0 && currentVar instanceof Parameter) {
				break;
			}
			if (index != 0 && currentVar.hasStackStorage()) {
				break;
			}
			if (currentVar == seed) {
				sawSeed = true;
			}
			mergeArray.add(currentVar);
			index += 1;
			String newName = baseName + '$' + Integer.toString(index);
			currentVar = nameMap.get(newName);
		}
		Variable[] res;
		if (!sawSeed) {
			res = new Variable[1];
			res[0] = seed;
		}
		else {
			res = new Variable[mergeArray.size()];
			mergeArray.toArray(res);
		}
		return res;
	}

	/**
	 * Low-level routine for clearing any variables in the
	 * database which conflict with this variable and return
	 * one of them for re-use.  The returned variable still
	 * exists within the function at the same first-use-offset.
	 * @param function is the function containing the local variables
	 * @param storage is the storage area to clear
	 * @param pcAddr is the point of use
	 * @return existing variable with identical storage and first-use offset or null
	 */
	private static Variable clearConflictingLocalVariables(Function function,
			VariableStorage storage, Address pcAddr) {

		int firstUseOffset = 0;
		if (pcAddr != null) {
			firstUseOffset = (int) pcAddr.subtract(function.getEntryPoint());
		}
		if (storage.isHashStorage()) {

			long hashVal = storage.getFirstVarnode().getOffset();
			for (Variable ul : function.getLocalVariables(VariableFilter.UNIQUE_VARIABLE_FILTER)) {
				// Note: assumes there is only one hash method used for unique locals
				if (ul.getFirstStorageVarnode().getOffset() == hashVal) {
					return ul;
				}
			}
			return null;
		}

		Variable matchingVariable = null;
		for (Variable otherVar : function.getLocalVariables()) {
			if (otherVar.getFirstUseOffset() != firstUseOffset) {
				// other than parameters we will have a hard time identifying
				// local variable conflicts due to differences in scope (i.e., first-use)
				continue;
			}

			VariableStorage otherStorage = otherVar.getVariableStorage();

			if (otherStorage.intersects(storage)) {
				if (matchingVariable == null && otherStorage.equals(storage)) {
					matchingVariable = otherVar;
					continue;
				}
				function.removeVariable(otherVar);
			}
		}

		return matchingVariable;
	}

	/**
	 * Get database parameter which corresponds to the given symbol, where we anticipate that
	 * the parameter will be modified to match the symbol. The entire prototype is
	 * committed to the database if necessary. An exception is thrown if a modifiable parameter
	 * can't be found/created.
	 * @param param is the HighSymbol describing the desired function parameter
	 * @return the matching parameter that can be modified
	 * @throws InvalidInputException if the desired parameter cannot be modified
	 */
	private static Parameter getDatabaseParameter(HighSymbol param) throws InvalidInputException {

		HighFunction highFunction = param.getHighFunction();
		Function function = highFunction.getFunction();

		int slot = param.getCategoryIndex();
		Parameter[] parameters = function.getParameters();
		if (slot < parameters.length) {
			if (parameters[slot].isAutoParameter()) {
				throw new InvalidInputException(
					"Cannot modify auto-parameter: " + parameters[slot].getName());
			}
		}
		if (slot >= parameters.length ||
			!parameters[slot].getVariableStorage().equals(param.getStorage())) {
			try {
				commitParamsToDatabase(highFunction, true, SourceType.ANALYSIS);
			}
			catch (DuplicateNameException e) {
				throw new AssertException("Unexpected exception", e);
			}
			parameters = function.getParameters();
			if (slot >= parameters.length ||
				!parameters[slot].getVariableStorage().equals(param.getStorage())) {
				throw new InvalidInputException(
					"Parameter commit failed for function at " + function.getEntryPoint());
			}
		}
		return parameters[slot];
	}

	/**
	 * Rename and/or retype the specified variable in the database.  All parameters may be flushed
	 * to the database if typed parameter inconsistency detected.
	 * @param highSymbol is the symbol being updated
	 * @param name new variable name or null to use retain current variable name
	 * @param dataType newly assigned data type or null to retain current variable datatype.
	 * Only a fixed-length data type may be specified.  If size varies from the current size,
	 * an attempt will be made to grow/shrink the storage.
	 * @param source source type
	 * @throws InvalidInputException if suitable data type was not specified, or unable to
	 * resize storage, or invalid name specified
	 * @throws DuplicateNameException if name was specified and conflicts with another
	 * variable/label within the function's namespace
	 * @throws UnsupportedOperationException if unsupported variable type is specified
	 */
	public static void updateDBVariable(HighSymbol highSymbol, String name, DataType dataType,
			SourceType source) throws InvalidInputException, DuplicateNameException {

		HighFunction highFunction = highSymbol.getHighFunction();
		Function function = highFunction.getFunction();
		Program program = function.getProgram();

		boolean resized = false;
		if (dataType != null) {
			dataType = dataType.clone(program.getDataTypeManager());
			if (dataType.getLength() <= 0) {
				throw new InvalidInputException(
					"Data type is not fixed-length: " + dataType.getName());
			}

			resized = (dataType.getLength() != highSymbol.getSize());
		}

		boolean isRename = name != null;

		if (highSymbol.isParameter()) {
			Parameter dbParam = getDatabaseParameter(highSymbol);
			VariableStorage storage = highSymbol.getStorage();
			if (dataType != null) {
				if (resized && function.hasCustomVariableStorage()) {
					VariableStorage newStorage =
						VariableUtilities.resizeStorage(storage, dataType, true, function);
					dbParam.setDataType(dataType, newStorage, false, source);
				}
				else {
					dbParam.setDataType(dataType, source);
				}
			}
			if (name != null && !name.equals(dbParam.getName())) {
				dbParam.setName(name, source);
			}
		}
		else if (!highSymbol.isGlobal()) {
			Variable[] varList = null;
			VariableStorage storage = highSymbol.getStorage();
			Address pcAddr = highSymbol.getPCAddress();
			HighVariable tmpHigh = highSymbol.getHighVariable();
			if (!storage.isHashStorage() && tmpHigh != null && tmpHigh.requiresDynamicStorage()) {
				DynamicEntry entry = DynamicEntry.build(tmpHigh.getRepresentative());
				storage = entry.getStorage();
				pcAddr = entry.getPCAdress();	// The address may change from original Varnode
			}
			else {
				Variable var = clearConflictingLocalVariables(function, storage, pcAddr);
				if (var != null) {
					if (!resized) {
						varList = gatherMergeSet(function, var);	// Cannot resize a whole multi-merge
					}
					else {
						varList = new Variable[1];
						varList[0] = var;
					}
				}
			}
			boolean usesHashStorage = storage.isHashStorage();
			if (dataType == null) {
				if (varList != null) {
					dataType = varList[0].getDataType();	// Use preexisting datatype if it fits in desired storage
				}
				else {
					dataType = Undefined.getUndefinedDataType(highSymbol.getSize());
					dataType = dataType.clone(program.getDataTypeManager());
				}
			}
			if (resized) {
				if (usesHashStorage) {
					throw new InvalidInputException(
						"Variable size (" + highSymbol.getSize() + ") may not be changed: type '" +
							dataType.getName() + "' length is " + dataType.getLength());
				}
				storage = VariableUtilities.resizeStorage(storage, dataType, true, function);
			}

			if (varList == null) {
				Variable var = createLocalVariable(function, dataType, storage, pcAddr, source);
				varList = new Variable[1];
				varList[0] = var;
			}
			else if (resized) {
				// Set resized data-type on existing Variable
				varList[0].setDataType(dataType, storage, true, source);
			}
			else {
				// Set data-type on existing merge set
				for (Variable var : varList) {
					var.setDataType(dataType, source);
				}
			}
			if (name == null) {
				name = highSymbol.getName(); // must update name if not specified
			}
			Variable renameVar = null;
			try {
				int index = 0;
				String curName = name;
				for (Variable var : varList) {
					renameVar = var;
					var.setName(curName, source);
					index += 1;
					curName = name + '$' + Integer.toString(index);
				}
			}
			catch (DuplicateNameException e) {
				if (isRename) {
					throw e;
				}
				// assign default name on conflict
				try {
					Msg.error(HighFunctionDBUtil.class,
						"Name conflict while naming local variable: " + function.getName() + ":" +
							name);
					renameVar.setName(null, SourceType.DEFAULT);
				}
				catch (DuplicateNameException e1) {
					throw new AssertException("Unexpected exception with default name", e);
				}
			}
		}
		else {	// A global symbol

			VariableStorage storage = highSymbol.getStorage();
			if (!storage.isMemoryStorage()) {
				throw new UnsupportedOperationException(
					"Database supports global memory variables only");
			}

			if (name == null) {
				name = highSymbol.getName();
				if (name != null && SymbolUtilities.isDynamicSymbolPattern(name, true)) {
					name = null;
				}
			}

			if (dataType != null) {
				setGlobalDataType(highSymbol, dataType);
			}

			if (name != null) {
				try {
					setGlobalName(highSymbol, name, source);
				}
				catch (DuplicateNameException e) {
					if (isRename) {
						throw e;
					}
				}
			}
		}
	}

	private static void setGlobalName(HighSymbol global, String name, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		Program program = global.getHighFunction().getFunction().getProgram();
		VariableStorage storage = global.getStorage();
		if (!storage.isMemoryStorage()) {
			return; // unsupported global (register?)
		}
		Address addr = storage.getFirstVarnode().getAddress();
		SymbolTable symTable = program.getSymbolTable();
		Symbol sym = symTable.getPrimarySymbol(addr);
		if (sym == null) {
			symTable.createLabel(addr, name, source);
		}
		else if (!sym.getName().equals(name)) {
			sym.setName(name, source);
		}
	}

	private static Data setGlobalDataType(HighSymbol global, DataType dt)
			throws InvalidInputException {
		Program program = global.getHighFunction().getFunction().getProgram();
		VariableStorage storage = global.getStorage();
		if (!storage.isMemoryStorage()) {
			return null;
		}
		Address addr = storage.getFirstVarnode().getAddress();
		if (storage.size() != dt.getLength() && program.getMemory().isBigEndian()) {
			// maintain address of lsb
			long delta = storage.size() - dt.getLength();
			try {
				addr = addr.addNoWrap(delta);
			}
			catch (AddressOverflowException e) {
				throw new InvalidInputException(
					"Unable to resize global storage for " + dt.getName() + " at " + addr);
			}
		}

		Listing listing = program.getListing();
		Data d = listing.getDataAt(addr);
		if (d != null && d.getDataType().isEquivalent(dt)) {
			return d;
		}

		try {
			return DataUtilities.createData(program, addr, dt, -1, false,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
		}
		catch (CodeUnitInsertionException e) {
			// Recast as InvalidInput
			throw new InvalidInputException(e.getMessage());
		}
	}

	/**
	 * Commit an overriding prototype for a particular call site to the database. The override
	 * only applies to the function(s) containing the actual call site. Calls to the same function from
	 * other sites are unaffected.  This is used typically either for indirect calls are for calls to
	 * a function with a variable number of parameters.
	 * @param function is the Function whose call site is being overridden
	 * @param callsite is the address of the calling instruction (the call site)
	 * @param sig is the overriding function signature
	 * @throws InvalidInputException if there are problems committing the override symbol
	 */
	public static void writeOverride(Function function, Address callsite, FunctionSignature sig)
			throws InvalidInputException {

		ParameterDefinition[] params = sig.getArguments();
		FunctionDefinitionDataType fsig = new FunctionDefinitionDataType("tmpname"); // Empty datatype, will get renamed later
		fsig.setGenericCallingConvention(sig.getGenericCallingConvention());
		fsig.setArguments(params);
		fsig.setReturnType(sig.getReturnType());
		fsig.setVarArgs(sig.hasVarArgs());

		DataTypeSymbol datsym = new DataTypeSymbol(fsig, "prt", AUTO_CAT);
		Program program = function.getProgram();
		SymbolTable symtab = program.getSymbolTable();
		DataTypeManager dtmanage = program.getDataTypeManager();
		Namespace space = HighFunction.findCreateOverrideSpace(function);
		if (space == null) {
			throw new InvalidInputException("Could not create \"override\" namespace");
		}
		datsym.writeSymbol(symtab, callsite, space, dtmanage, true);
	}

	/**
	 * Read a call prototype override which corresponds to the specified override code symbol
	 * @param sym special call override code symbol whose address corresponds to a call site
	 * @return call prototype override DataTypeSymbol or null if associated function signature
	 * data-type could not be found
	 */
	public static DataTypeSymbol readOverride(Symbol sym) {
		DataTypeSymbol datsym = DataTypeSymbol.readSymbol(AUTO_CAT, sym);
		if (datsym == null) {
			return null;
		}
		DataType dt = datsym.getDataType();
		if (!(dt instanceof FunctionSignature)) {
			return null;
		}
		return datsym;
	}

	/**
	 * Get the Address referred to by a spacebase reference. Address-of references are encoded in
	 * the p-code syntax tree as: {@code vn = PTRSUB(<spacebase>, #const)}.  This decodes the reference and
	 * returns the Address
	 * @param program is the program containing the Address
	 * @param op is the PTRSUB op encoding the reference
	 * @return the recovered Address (or null if not correct form)
	 */
	public static Address getSpacebaseReferenceAddress(Program program, PcodeOp op) {
		Address storageAddress = null;
		if (op == null) {
			return storageAddress;
		}
		if (op.getOpcode() == PcodeOp.PTRSUB) {
			Varnode vnode = op.getInput(0);
			Varnode cnode = op.getInput(1);
			if (vnode.isRegister()) {
				AddressSpace stackspace = program.getAddressFactory().getStackSpace();
				if (stackspace != null) {
					storageAddress = stackspace.getAddress(cnode.getOffset());
				}
			}
			else {
				AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
				if (space instanceof SegmentedAddressSpace) {
					// Assume this is a "full" encoding of the offset
					int innersize = space.getPointerSize();
					int base = (int) (cnode.getOffset() >>> 8 * innersize);
					int off = (int) cnode.getOffset() & ((1 << 8 * innersize) - 1);
					storageAddress = ((SegmentedAddressSpace) space).getAddress(base, off);
				}
				else {
					storageAddress = space.getAddress(cnode.getOffset());
				}
			}
		}
		return storageAddress;
	}
}
