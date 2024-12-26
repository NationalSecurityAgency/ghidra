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
package ghidra.program.util;

import java.util.*;

import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.*;
import ghidra.util.HTMLUtilities;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Utility methods for performing function related actions.
 */
public class FunctionUtility {

	// Don't want to be able to create an instance.
	private FunctionUtility() {
	}

	/**
	 * Applies the name and namespace from source function to the target function
	 * @param target the function whose name is being changed.
	 * @param source the source function from which to get name and namespace. The source function
	 * can be from another program.
	 * @throws DuplicateNameException if creating a namespace would create a invalid duplicate name
	 * @throws InvalidInputException if the name or namespace from the source function is invalid
	 * @throws CircularDependencyException if this function is an ancestor of
	 * the target namespace. This probably can't happen
	 */
	public static void applyNameAndNamespace(Function target, Function source)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {
		String name = source.getName();
		Namespace targetNamespace = getOrCreateSourceNamespaceInTarget(target, source);
		Symbol symbol = target.getSymbol();
		symbol.setNameAndNamespace(name, targetNamespace, source.getSymbol().getSource());
	}

	/**
	 * Updates the destination function so its signature will match the source function's signature
	 * as closely as possible. This method will try to create conflict names if necessary for the
	 * function and its parameters.
	 * <br>
	 * All datatypes will be resolved using the 
	 * {@link DataTypeConflictHandler#DEFAULT_HANDLER default conflict handler}.
	 * 
	 * @param destinationFunction the destination function to update
	 * @param sourceFunction the source function to use as a template
	 * @throws InvalidInputException if the function name or a variable name is invalid or if a
	 *                        parameter data type is not a fixed length.
	 * @throws DuplicateNameException This shouldn't happen since it will try to create conflict
	 *                        names for the function and its variables if necessary. Otherwise, 
	 *                        this would be because the function's name or a variable name already exists.
	 * @throws CircularDependencyException if namespaces have circular references
	 */
	public static void updateFunction(Function destinationFunction, Function sourceFunction)
			throws InvalidInputException, DuplicateNameException, CircularDependencyException {

		applySignature(destinationFunction, sourceFunction, false,
			DataTypeConflictHandler.DEFAULT_HANDLER);
	}

	/**
	 * Updates the destination function so its signature will match the source function's signature
	 * as closely as possible. This method will try to create conflict names if necessary for the
	 * function and its parameters.
	 * 
	 * @param destinationFunction the destination function to update
	 * @param sourceFunction  the source function to use as a template
	 * @param applyEmptyComposites If true, applied composites will be resolved without their
	 *                        respective components if the type does not already exist in the 
	 *                        destination datatype manager.  If false, normal type resolution 
	 *                        will occur.
	 * @param conflictHandler conflict handler to be used when applying datatypes to the
	 *                        destination program.  If this value is not null or 
	 *                        {@link DataTypeConflictHandler#DEFAULT_HANDLER} the datatypes will be 
	 *                        resolved prior to updating the destinationFunction.  This handler
	 *                        will provide some control over how applied datatype are handled when 
	 *                        they conflict with existing datatypes. 
	 *                        See {@link DataTypeConflictHandler} which provides some predefined
	 *                        handlers.
	 * @throws InvalidInputException if the function name or a variable name is invalid or if a
	 *                        parameter data type is not a fixed length.
	 * @throws DuplicateNameException This shouldn't happen since it will try to create conflict
	 *                        names for the function and its variables if necessary. Otherwise, 
	 *                        this would be because the function's name or a variable name already exists.
	 * @throws CircularDependencyException if namespaces have circular references
	 */
	public static void applySignature(Function destinationFunction, Function sourceFunction,
			boolean applyEmptyComposites, DataTypeConflictHandler conflictHandler)
			throws InvalidInputException, DuplicateNameException, CircularDependencyException {

		if (conflictHandler == null) {
			conflictHandler = DataTypeConflictHandler.DEFAULT_HANDLER;
		}
		updateFunctionExceptName(destinationFunction, sourceFunction, applyEmptyComposites,
			conflictHandler);
		applyNameAndNamespace(destinationFunction, sourceFunction);
	}

	private static void updateFunctionExceptName(Function destinationFunction,
			Function sourceFunction, boolean applyEmptyComposites,
			DataTypeConflictHandler conflictHandler)
			throws InvalidInputException, DuplicateNameException {

		Program sourceProgram = sourceFunction.getProgram();
		Program destinationProgram = destinationFunction.getProgram();
		boolean sameLanguage = isSameLanguageAndCompilerSpec(destinationProgram, sourceProgram);

		String callingConventionName =
			determineCallingConventionName(destinationFunction, sourceFunction, sameLanguage);
		boolean useCustomStorage =
			determineCustomStorageUse(destinationFunction, sourceFunction, sameLanguage);

		DataTypeManager destinationDtm = destinationFunction.getProgram().getDataTypeManager();
		final DataTypeCleaner dtCleaner =
			applyEmptyComposites ? new DataTypeCleaner(destinationDtm, true) : null;
		try {
			SourceType source = sourceFunction.getSignatureSource();
			Variable returnValue =
				determineReturnValue(destinationFunction, sourceFunction, useCustomStorage,
					dt -> prepareDataType(dt, destinationDtm, dtCleaner, conflictHandler));
			List<Parameter> newParams =
				determineParameters(destinationFunction, sourceFunction, useCustomStorage,
					dt -> prepareDataType(dt, destinationDtm, dtCleaner, conflictHandler));
			setUniqueParameterNames(destinationFunction, newParams);
			destinationFunction.updateFunction(callingConventionName, returnValue, newParams,
				useCustomStorage ? FunctionUpdateType.CUSTOM_STORAGE
						: FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
				true, source);
		}
		finally {
			if (dtCleaner != null) {
				dtCleaner.close();
			}
		}

		applyInline(destinationFunction, sourceFunction);
		applyNoReturn(destinationFunction, sourceFunction);
		applyVarArgs(destinationFunction, sourceFunction);
		applyCallFixup(destinationFunction, sourceFunction, sameLanguage);
	}

	private static DataType prepareDataType(DataType dt, DataTypeManager destinationDtm,
			DataTypeCleaner dtCleaner, DataTypeConflictHandler conflictHandler) {
		if (dtCleaner != null) {
			dt = dtCleaner.clean(dt);
		}
		if (conflictHandler != DataTypeConflictHandler.DEFAULT_HANDLER) {
			dt = destinationDtm.resolve(dt, conflictHandler);
		}
		return dt;
	}

	/**
	 * Changes the names of the parameters in the array to unique names that won't conflict with
	 * any other names in the function's namespace when the parameters are used to replace
	 * the existing parameters in the function. Appends an integer number to
	 * the base name if necessary to create a unique name in the function's namespace.
	 * @param function the function
	 * @param parameters the parameters that need names that won't conflict. These should be
	 * Impl objects and not DB objects since their names will be changed within this method.
	 * @throws InvalidInputException
	 * @throws DuplicateNameException
	 */
	public static void setUniqueParameterNames(Function function, List<Parameter> parameters)
			throws DuplicateNameException, InvalidInputException {
		SymbolTable symbolTable = function.getProgram().getSymbolTable();

		// Create a set containing all the unique parameter names determined so far so they can
		// be avoided as additional parameter names are determined.
		Set<String> namesSoFar = new HashSet<>();
		for (Parameter parameter : parameters) {
			String baseName = parameter.getName();
			String uniqueName =
				getUniqueReplacementParameterName(symbolTable, function, baseName, namesSoFar);
			namesSoFar.add(uniqueName);
			if (!SystemUtilities.isEqual(baseName, uniqueName)) {
				parameter.setName(uniqueName, parameter.getSource());
			}
		}
	}

	/**
	 * Get a unique parameter name for a parameter when all parameter names are being replaced.
	 * If the specified name is  a default parameter name then the original default name passed
	 * in is returned.
	 * @param symbolTable the symbol table containing symbols for the indicated namespace
	 * @param namespace the namespace containing symbol names to check.
	 * @param baseName the base name to append with an integer number if necessary
	 * to create a unique name.
	 * @param namesNotToBeUsed set of names that should not be used when determining a unique name.
	 * @return a unique parameter name
	 */
	private static String getUniqueReplacementParameterName(SymbolTable symbolTable,
			Function function, String name, Set<String> namesNotToBeUsed) {
		if (name == null || SymbolUtilities.isDefaultParameterName(name)) {
			return name;
		}
		return getUniqueNameIgnoringCurrentParameters(symbolTable, function, name,
			namesNotToBeUsed);
	}

	/**
	 * Gets a unique name in the indicated namespace by appending an integer number if necessary
	 * and ignoring any conflicts with existing parameters.
	 * @param symbolTable the symbol table containing symbols for the indicated namespace
	 * @param function the namespace containing symbol names to check.
	 * @param baseName the base name to append with an integer number if necessary to create a
	 * unique name.
	 * @param namesNotToBeUsed set of names that should not be used when determining a unique name.
	 * @return an unused unique name within the namespace ignoring current parameter names and
	 * that doesn't conflict with any in the set of names not to be used.
	 */
	private static String getUniqueNameIgnoringCurrentParameters(SymbolTable symbolTable,
			Function function, String baseName, Set<String> namesNotToBeUsed) {
		String name = baseName;
		if (name != null) {
			// establish unique name
			int cnt = 0;
			Symbol symbol = symbolTable.getVariableSymbol(name, function);
			while (symbol != null) {
				if (namesNotToBeUsed.contains(name)) {
					continue;
				}
				if (symbol.getSymbolType() == SymbolType.PARAMETER) {
					return name;
				}
				name = baseName + (++cnt);
				symbol = symbolTable.getVariableSymbol(name, function);
			}
		}
		return name;
	}

	private static void applyInline(Function destinationFunction, Function sourceFunction) {
		boolean sourceInline = sourceFunction.isInline();
		boolean destInline = destinationFunction.isInline();
		if (destInline != sourceInline) {
			destinationFunction.setInline(sourceInline);
		}
	}

	private static void applyNoReturn(Function destinationFunction, Function sourceFunction) {
		boolean sourceNoReturn = sourceFunction.hasNoReturn();
		boolean destNoReturn = destinationFunction.hasNoReturn();
		if (destNoReturn != sourceNoReturn) {
			destinationFunction.setNoReturn(sourceNoReturn);
		}
	}

	private static void applyVarArgs(Function destinationFunction, Function sourceFunction) {
		boolean sourceVarArgs = sourceFunction.hasVarArgs();
		boolean destVarArgs = destinationFunction.hasVarArgs();
		if (destVarArgs != sourceVarArgs) {
			destinationFunction.setVarArgs(sourceVarArgs);
		}
	}

	private static void applyCallFixup(Function destinationFunction, Function sourceFunction,
			boolean sameLanguage) {
		String sourceCallFixup = sourceFunction.getCallFixup();
		String destCallFixup = destinationFunction.getCallFixup();
		if (SystemUtilities.isEqual(destCallFixup, sourceCallFixup)) {
			return; // they are the same already.
		}
		if (sameLanguage) {
			destinationFunction.setCallFixup(sourceCallFixup);
		}
	}

	/**
	 * Sets the destination function's name to match the source function's name. Otherwise, it
	 * creates a conflict name if the desired name already exists elsewhere in the program.
	 * @param destinationFunction the destination function to update
	 * @param sourceFunction the source function to use as a template
	 * @throws InvalidInputException if the function name is invalid.
	 * @throws DuplicateNameException This shouldn't happen since it will try to create a conflict
	 * name for the function if necessary. Otherwise, this would be because the function's name
	 * already exists.
	 */
	static void setFunctionName(Function destinationFunction, Function sourceFunction)
			throws InvalidInputException, DuplicateNameException {
		String sourceName = sourceFunction.getName();
		Address sourceEntryPoint = sourceFunction.getEntryPoint();
		Namespace sourceNamespace = sourceFunction.getParentNamespace();
		String defaultFunctionName = SymbolUtilities.getDefaultFunctionName(sourceEntryPoint);
		boolean isDefaultFunctionName = defaultFunctionName.equals(sourceName);
		if (isDefaultFunctionName) {
			return; // Do nothing if source was default name.
		}
		String destinationName = destinationFunction.getName();
		if (sourceName.equals(destinationName)) {
			return; // names already the same.
		}
		// Set the destination name to the same as the source or a conflict name if necessary.
		String baseName = getBaseName(sourceFunction);
		SymbolTable symbolTable = sourceFunction.getProgram().getSymbolTable();
		Symbol symbol = symbolTable.getSymbol(sourceName, sourceEntryPoint, sourceNamespace);
		SourceType source = (symbol != null) ? symbol.getSource() : SourceType.USER_DEFINED;
		try {
			destinationFunction.setName(baseName, source);
		}
		catch (DuplicateNameException e) {
			// Create a conflict name.
			baseName = createConflictName(baseName, destinationFunction);
			// Retry with new conflict name.
			destinationFunction.setName(baseName, source);
		}
	}

	/**
	 * Creates a conflict name based on the specified name and when being applied to the
	 * destination function.
	 * @param name the base name to use when creating the conflict name.
	 * @param destinationFunction the function that will use the conflict name.
	 * @return the conflict name.
	 */
	static String createConflictName(String name, Function destinationFunction) {
		Address entryPoint = destinationFunction.getEntryPoint();
		return name + "@" + SymbolUtilities.getAddressString(entryPoint);
	}

	static String getBaseName(Function function) {
		Address entryPoint = function.getEntryPoint();
		String conflictSuffix = "@" + SymbolUtilities.getAddressString(entryPoint);
		String name = function.getName();
		if (name.endsWith(conflictSuffix)) {
			// Strip the conflict suffix from the name and return it.
			return name.substring(0, name.length() - conflictSuffix.length());
		}
		return name;
	}

	/**
	 * Determines whether or not the two programs are considered to have the same processor
	 * language and compiler specification.
	 * @param program1 the first program
	 * @param program2 the second program
	 * @return true if the two programs have the same processor language and compiler spec.
	 */
	public static boolean isSameLanguageAndCompilerSpec(Program program1, Program program2) {
		Language language1 = program1.getLanguage();
		Language language2 = program2.getLanguage();
		if (language1.getLanguageID() != language2.getLanguageID()) {
			return false;
		}
		CompilerSpec compilerSpec1 = program1.getCompilerSpec();
		CompilerSpec compilerSpec2 = program2.getCompilerSpec();
		if (compilerSpec1.getCompilerSpecID() != compilerSpec2.getCompilerSpecID()) {
			return false;
		}
		return true;
	}

	private static String determineCallingConventionName(Function destinationFunction,
			Function sourceFunction, boolean sameLanguageAndCompilerSpec) {
		String sourceConv = sourceFunction.getCallingConventionName();
		if (CompilerSpec.CALLING_CONVENTION_thiscall.equals(sourceConv)) {
			return sourceConv;
		}
		boolean applyConventionName = sameLanguageAndCompilerSpec;
		String callingConvention = sourceFunction.getCallingConventionName();
		if (applyConventionName &&
			!CompilerSpec.CALLING_CONVENTION_default.equals(callingConvention)) {
			DataTypeManager dtMgr = destinationFunction.getProgram().getDataTypeManager();
			if (GenericCallingConvention.getGenericCallingConvention(
				callingConvention) == GenericCallingConvention.unknown &&
				!dtMgr.getKnownCallingConventionNames().contains(callingConvention)) {
				applyConventionName = false;
			}
		}
		return applyConventionName ? callingConvention
				: destinationFunction.getCallingConventionName();
	}

	private static boolean determineCustomStorageUse(Function destinationFunction,
			Function sourceFunction, boolean sameLanguage) {
		boolean useCustomStorage = sourceFunction.hasCustomVariableStorage();
		if (useCustomStorage) {
			return sameLanguage; // only use for same language.
		}
		return false;
	}

	private static Variable determineReturnValue(Function destinationFunction,
			Function sourceFunction, boolean useCustomStorage,
			java.util.function.Function<DataType, DataType> prepareDataType)
			throws InvalidInputException {
		Program destinationProgram = destinationFunction.getProgram();
		Parameter sourceReturn = sourceFunction.getReturn();
		VariableStorage storage =
			(useCustomStorage) ? sourceReturn.getVariableStorage().clone(destinationProgram)
					: VariableStorage.UNASSIGNED_STORAGE;
		DataType dataType = prepareDataType.apply(sourceReturn.getDataType());
		if (dataType.isZeroLength()) {
			storage = VariableStorage.UNASSIGNED_STORAGE;
		}
		Parameter returnValue = new ReturnParameterImpl(dataType, storage, destinationProgram);
		return returnValue;
	}

	private static List<Parameter> determineParameters(Function destinationFunction,
			Function sourceFunction, boolean useCustomStorage,
			java.util.function.Function<DataType, DataType> prepareDataType)
			throws InvalidInputException {
		Program destinationProgram = destinationFunction.getProgram();
		List<Parameter> parameters = new ArrayList<>();
		Parameter[] sourceParameters = sourceFunction.getParameters();
		for (Parameter sourceParameter : sourceParameters) {
			String name = sourceParameter.getName();
			VariableStorage storage =
				(useCustomStorage) ? sourceParameter.getVariableStorage().clone(destinationProgram)
						: VariableStorage.UNASSIGNED_STORAGE;
			DataType dataType = prepareDataType.apply(sourceParameter.getDataType());
			if (dataType.isZeroLength()) {
				storage = VariableStorage.UNASSIGNED_STORAGE;
			}

			SourceType source = sourceParameter.getSource();
			Parameter parameter =
				new ParameterImpl(name, dataType, storage, destinationProgram, source);
			String comment = sourceParameter.getComment();
			if (comment != null) {
				parameter.setComment(comment);
			}
			parameters.add(parameter);
		}
		return parameters;
	}

	/**
	 * Determines if the indicated function has a default name.
	 * @param function the function
	 * @return true if the function has a default name.
	 */
	public static boolean isDefaultFunctionName(Function function) {
		String defaultFunctionName =
			SymbolUtilities.getDefaultFunctionName(function.getEntryPoint());
		return defaultFunctionName.equals(function.getName());
	}

	/**
	 * Gets a title string wrapped as HTML and indicating the function's name and the program
	 * containing it.
	 * @param function the function to be indicated in the title.
	 * @return the title string as HTML.
	 */
	public static String getFunctionTitle(Function function) {
		if (function == null) {
			return HTMLUtilities.wrapAsHTML("No Function");
		}
		StringBuffer buf = new StringBuffer();
		String padStr = HTMLUtilities.spaces(4);
		buf.append(padStr);

		String functionStr = HTMLUtilities.friendlyEncodeHTML(function.getName() + "()");
		String specialFunctionStr = HTMLUtilities.bold(functionStr);
		buf.append(specialFunctionStr);

		Program program = function.getProgram();
		if (program != null) {
			buf.append(" in ");

			String programStr =
				HTMLUtilities.friendlyEncodeHTML(program.getDomainFile().getPathname());
			String specialProgramStr = HTMLUtilities.colorString(Palette.DARK_GRAY, programStr);
			buf.append(specialProgramStr);
			buf.append(padStr);
		}
		return HTMLUtilities.wrapAsHTML(buf.toString());
	}

	private static Namespace getOrCreateSourceNamespaceInTarget(Function target, Function source)
			throws DuplicateNameException, InvalidInputException {

		Namespace targetNamespace = target.getParentNamespace();
		Namespace sourceNamespace = source.getParentNamespace();
		if (targetNamespace.getName(true).equals(sourceNamespace.getName(true))) {
			return targetNamespace;
		}
		return getOrCreateTargetNamespace(target.getProgram(), sourceNamespace);
	}

	private static Namespace getOrCreateTargetNamespace(Program program, Namespace otherNamespace)
			throws DuplicateNameException, InvalidInputException {
		if (otherNamespace.isGlobal()) {
			return program.getGlobalNamespace();
		}
		Namespace otherParent = otherNamespace.getParentNamespace();
		Namespace parent = getOrCreateTargetNamespace(program, otherParent);

		SymbolTable symbolTable = program.getSymbolTable();
		String otherName = otherNamespace.getName();

		Namespace namespace = symbolTable.getNamespace(otherName, parent);
		if (namespace != null) {
			return namespace;
		}

		// not there, we need to create it.
		SourceType source = otherNamespace.getSymbol().getSource();
		if (otherNamespace instanceof GhidraClass) {
			return symbolTable.createClass(parent, otherName, source);
		}
		else if (otherNamespace instanceof Library) {
			return symbolTable.createExternalLibrary(otherName, source);
		}
		return symbolTable.createNameSpace(parent, otherName, source);
	}

}
