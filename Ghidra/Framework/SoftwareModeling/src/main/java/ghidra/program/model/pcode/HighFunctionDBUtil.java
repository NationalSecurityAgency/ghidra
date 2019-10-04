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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
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
	 * Commit function return to the underlying database.
	 * @param highFunction
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

		commitParamsToDatabase(function, highFunction.getFunctionPrototype(), params,
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
			HighParam param = symbolMap.getParam(i);
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
	 * Commit the specified parameter list to the specified function.
	 * @param function
	 * @param params
	 * @param renameConflicts if true any name conflicts will be resolved
	 * by renaming the conflicting local variable/label
	 * @param source source type
	 * @throws DuplicateNameException if commit of parameters caused conflict with other
	 * local variable/label.  Should not occur if renameConflicts is true.
	 * @throws InvalidInputException
	 */
	public static void commitParamsToDatabase(Function function, FunctionPrototype prototype,
			List<Parameter> params, boolean hasVarArgs, boolean renameConflicts, SourceType source)
			throws DuplicateNameException, InvalidInputException {

		String modelName = prototype != null ? prototype.getModelName() : null;

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
			}
			catch (InvalidInputException e) {
				break;
			}
		}
	}

	/**
	 * Commit all local variables to the underlying database.
	 * @param highFunction
	 * @param source source type
	 */
	public static void commitLocalsToDatabase(HighFunction highFunction, SourceType source) {

		Function function = highFunction.getFunction();

		clearObsoleteDynamicLocalsFromDatabase(highFunction);

		Iterator<HighSymbol> iter = highFunction.getLocalSymbolMap().getSymbols();
		while (iter.hasNext()) {
			HighSymbol sym = iter.next();
			HighVariable high = sym.getHighVariable();
			if ((high instanceof HighParam) || !(high instanceof HighLocal)) {
				continue;
			}

			HighLocal local = (HighLocal) high;
			String name = local.getName();
			try {
				Variable var = clearConflictingLocalVariables(local);
				if (var == null) {
					var = createLocalVariable(local, null, null, source);
					if (name != null) {
						var.setName(name, source);
					}
				}
				else {
					var.setDataType(local.getDataType(), local.getStorage(), false, source);
					var.setName(name, source);
				}
			}
			catch (UsrException e) {
				Msg.error(HighFunctionDBUtil.class, "Local variable commit failed for " +
					function.getName() + ":" + name + " : " + e.getMessage());
			}
		}
	}

	/**
	 * Create a local DB variable with a default name
	 * @param local
	 * @param dt data type or null to use local data type defined by local high variable
	 * @param storage storage or null to use storage defined by local high variable
	 * @param source
	 * @return
	 * @throws InvalidInputException
	 * @throws DuplicateNameException
	 */
	private static Variable createLocalVariable(HighLocal local, DataType dt,
			VariableStorage storage, SourceType source) throws InvalidInputException {
		Function function = local.getHighFunction().getFunction();
		Program program = function.getProgram();
		if (storage == null || storage.isUniqueStorage()) {
			storage = local.getStorage();
		}
		if (dt == null) {
			dt = local.getDataType();
		}
		Variable var = new LocalVariableImpl(null, local.getFirstUseOffset(), dt, storage, program);
		try {
			var = function.addLocalVariable(var, SourceType.ANALYSIS);
		}
		catch (DuplicateNameException e) {
			throw new AssertException("Unexpected exception with default name", e);
		}

		Register reg = var.getRegister();
		if (reg != null) {
			program.getReferenceManager().addRegisterReference(local.getPCAddress(), -1, reg,
				RefType.WRITE, source);
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
			HighVariable high = symbols.next().getHighVariable();
			if (!(high instanceof HighLocal)) {
				continue;
			}
			// Note: assumes there is only one hash method used for unique locals
			if (((HighLocal) high).buildDynamicHash() == hash) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Low-level routine for clearing any variables in the
	 * database which conflict with this variable and return
	 * one of them for re-use.  The returned variable still
	 * exists within the function at the same first-use-offset.
	 * @throws InvalidInputException
	 * @returns variable with conflicting storage or null, all
	 * aspects of variable returned should be reset (i.e., name, datatype and storage)
	 */
	private static Variable clearConflictingLocalVariables(HighLocal local)
			throws InvalidInputException {

		if (local instanceof HighParam) {
			throw new IllegalArgumentException();
		}

		HighFunction highFunction = local.getHighFunction();
		Function func = highFunction.getFunction();

		HighSymbol symbol = local.getSymbol();
		VariableStorage storage = local.getStorage();
		int firstUseOffset = local.getFirstUseOffset();
		if (symbol instanceof DynamicSymbol || storage.isUniqueStorage()) {

			if (!(symbol instanceof DynamicSymbol)) {
				return null;
			}

			DynamicSymbol dynamicSym = (DynamicSymbol) symbol;
			for (Variable ul : func.getLocalVariables(VariableFilter.UNIQUE_VARIABLE_FILTER)) {
				// Note: assumes there is only one hash method used for unique locals
				if (ul.getFirstStorageVarnode().getOffset() == dynamicSym.getHash()) {
					return ul;
				}
			}
			return null;
		}

		Variable matchingVariable = null;
		for (Variable otherVar : func.getLocalVariables()) {
			if (otherVar.getFirstUseOffset() != firstUseOffset) {
				// other than parameters we will have a hard time identifying
				// local variable conflicts due to differences in scope (i.e., first-use)
				continue;
			}

			VariableStorage otherStorage = otherVar.getVariableStorage();

			if (otherStorage.intersects(storage)) {
				if (matchingVariable == null || otherStorage.equals(storage)) {
					if (matchingVariable != null) {
						func.removeVariable(matchingVariable);
					}
					matchingVariable = otherVar;
					continue;
				}
				func.removeVariable(otherVar);
			}
		}

		return matchingVariable;
	}

	/**
	 * Get database parameter which corresponds to HighParam, where we anticipate that
	 * the parameter will be modified to match the HighParam. The entire prototype is
	 * committed to the database if necessary. An exception is thrown if a modifiable parameter
	 * can't be found/created.
	 * @param param is the HighParam describing the desired function parameter
	 * @return the matching parameter that can be modified
	 * @throws InvalidInputException if the desired parameter cannot be modified
	 */
	private static Parameter getDatabaseParameter(HighParam param) throws InvalidInputException {

		HighFunction highFunction = param.getHighFunction();
		Function function = highFunction.getFunction();

		int slot = param.getSlot();
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
	 * Retype the specified variable in the database.  All parameters may be flushed
	 * to the database if typed parameter inconsistency detected.
	 * Only variable types HighParam, HighLocal and HighGlobal are supported.
	 * @param variable
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
	public static void updateDBVariable(HighVariable variable, String name, DataType dataType,
			SourceType source) throws InvalidInputException, DuplicateNameException {

		HighFunction highFunction = variable.getHighFunction();
		Function function = highFunction.getFunction();
		Program program = function.getProgram();

		boolean resized = false;
		if (dataType != null) {
			dataType = dataType.clone(program.getDataTypeManager());
			if (dataType.getLength() <= 0) {
				throw new InvalidInputException(
					"Data type is not fixed-length: " + dataType.getName());
			}

			resized = (dataType.getLength() != variable.getSize());
		}

		boolean isRename = name != null;

		if (variable instanceof HighParam) {
			HighParam param = (HighParam) variable;
			Parameter dbParam = getDatabaseParameter(param);
			VariableStorage storage = param.getStorage();
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
		else if (variable instanceof HighLocal) {
			HighLocal local = (HighLocal) variable;
			VariableStorage storage = local.getStorage();
			boolean usesHashStorage = storage.isHashStorage();

			Variable var = clearConflictingLocalVariables(local);
			if (dataType == null) {
				if (var != null) {
					dataType = var.getDataType();	// Use preexisting datatype
				}
				else {
					dataType = Undefined.getUndefinedDataType(variable.getSize());
					dataType = dataType.clone(program.getDataTypeManager());
				}
			}
			if (resized) {
				if (usesHashStorage) {
					throw new InvalidInputException(
						"Variable size (" + local.getSize() + ") may not be changed: type '" +
							dataType.getName() + "' length is " + dataType.getLength());
				}
				storage = VariableUtilities.resizeStorage(storage, dataType, true, function);
			}

			if (var == null) {
				var = createLocalVariable(local, dataType, storage, source);
			}
			else {
				// fixup reused variable
				var.setDataType(dataType, storage, true, source);
				if (name == null) {
					name = local.getName(); // must update name if not specified
				}
			}
			try {
				// must set/correct name
				var.setName(name, source);
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
					var.setName(null, SourceType.DEFAULT);
				}
				catch (DuplicateNameException e1) {
					throw new AssertException("Unexpected exception with default name", e);
				}
			}
		}
		else if (variable instanceof HighGlobal) {

			VariableStorage storage = variable.getStorage();
			if (!storage.isMemoryStorage()) {
				throw new UnsupportedOperationException(
					"Database supports global memory variables only");
			}

			HighGlobal global = (HighGlobal) variable;
			if (name == null) {
				name = global.getName();
				if (name != null && SymbolUtilities.isDynamicSymbolPattern(name, true)) {
					name = null;
				}
			}

			if (dataType != null) {
				setGlobalDataType(global, dataType);
			}

			if (name != null) {
				try {
					setGlobalName((HighGlobal) variable, variable.getName(), source);
				}
				catch (DuplicateNameException e) {
					if (isRename) {
						throw e;
					}
				}
			}
		}
		else {
			throw new UnsupportedOperationException(
				"Database support not provided for " + variable.getClass().getSimpleName());
		}
	}

	private static void setGlobalName(HighGlobal global, String name, SourceType source)
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

	private static Data setGlobalDataType(HighGlobal global, DataType dt)
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
	 * Commit an override of a calls prototype to the database
	 * @param func is the Function whose call is being overriden
	 * @param callsite is the address of the call
	 * @param function signature override
	 * @throws InvalidInputException
	 * @throws DuplicateNameException
	 */
	public static void writeOverride(Function function, Address callsite, FunctionSignature sig)
			throws InvalidInputException, DuplicateNameException {

		ParameterDefinition[] params = sig.getArguments();
		FunctionSignatureImpl fsig = new FunctionSignatureImpl("tmpname"); // Empty datatype, will get renamed later
		fsig.setGenericCallingConvention(sig.getGenericCallingConvention());
		fsig.setArguments(params);
		fsig.setReturnType(sig.getReturnType());
		fsig.setVarArgs(sig.hasVarArgs());

		FunctionDefinitionDataType dt = new FunctionDefinitionDataType(fsig);

		DataTypeSymbol datsym = new DataTypeSymbol(dt, "prt", AUTO_CAT);
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
	 * @param sym special call override code symbol whose address corresponds to a callsite
	 * @return call prototype override DataTypeSymbol or null if associated function signature
	 * datatype could not be found
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

}
