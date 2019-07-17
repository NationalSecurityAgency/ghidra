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

import java.awt.Color;
import java.util.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.GenericCallingConvention;
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
	 * Updates the destination function so its signature will match the source function's signature
	 * as closely as possible. This method will try to create conflict names if necessary for the
	 * function and its parameters.
	 * @param destinationFunction the destination function to update
	 * @param sourceFunction the source function to use as a template
	 * @throws InvalidInputException if the function name or a variable name is invalid or if a
	 * parameter data type is not a fixed length.
	 * @throws DuplicateNameException This shouldn't happen since it will try to create conflict
	 * names for the function and its variables if necessary. Otherwise, this would be because
	 * the function's name or a variable name already exists.
	 */
	public static void updateFunction(Function destinationFunction, Function sourceFunction)
			throws InvalidInputException, DuplicateNameException {

		updateFunctionExceptName(destinationFunction, sourceFunction);
		setFunctionName(destinationFunction, sourceFunction);
	}

	private static void updateFunctionExceptName(Function destinationFunction,
			Function sourceFunction) throws InvalidInputException, DuplicateNameException {

		Program sourceProgram = sourceFunction.getProgram();
		Program destinationProgram = destinationFunction.getProgram();
		boolean sameLanguage = isSameLanguage(destinationProgram, sourceProgram);

		String callingConventionName =
			determineCallingConventionName(destinationFunction, sourceFunction, sameLanguage);
		boolean useCustomStorage =
			determineCustomStorageUse(destinationFunction, sourceFunction, sameLanguage);
		boolean force = true;
		SourceType source = sourceFunction.getSignatureSource();
		Variable returnValue =
			determineReturnValue(destinationFunction, sourceFunction, useCustomStorage);
		List<Parameter> newParams =
			determineParameters(destinationFunction, sourceFunction, useCustomStorage);
		setUniqueParameterNames(destinationFunction, newParams);
		destinationFunction.updateFunction(callingConventionName, returnValue, newParams,
			useCustomStorage ? FunctionUpdateType.CUSTOM_STORAGE
					: FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
			force, source);
		applyInline(destinationFunction, sourceFunction);
		applyNoReturn(destinationFunction, sourceFunction);
		applyVarArgs(destinationFunction, sourceFunction);
		applyCallFixup(destinationFunction, sourceFunction, sameLanguage);
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
	public static boolean isSameLanguage(Program program1, Program program2) {
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
			Function sourceFunction, boolean sameLanguage) {
		String sourceCallingConventionName = sourceFunction.getCallingConventionName();
		if (sameLanguage) {
			return sourceCallingConventionName; // Same language, so set to source.
		}
		GenericCallingConvention guessedCallingConvention =
			GenericCallingConvention.guessFromName(sourceCallingConventionName);
		if (guessedCallingConvention == GenericCallingConvention.thiscall) {
			return GenericCallingConvention.thiscall.name(); // this call
		}
		return destinationFunction.getCallingConventionName(); // leave destination unchanged.
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
			Function sourceFunction, boolean useCustomStorage) throws InvalidInputException {
		Program destinationProgram = destinationFunction.getProgram();
		Parameter sourceReturn = sourceFunction.getReturn();
		DataType dataType = sourceReturn.getDataType();
		VariableStorage storage =
			(useCustomStorage) ? sourceReturn.getVariableStorage().clone(destinationProgram)
					: VariableStorage.UNASSIGNED_STORAGE;
		Parameter returnValue = new ReturnParameterImpl(dataType, storage, destinationProgram);
		return returnValue;
	}

	private static List<Parameter> determineParameters(Function destinationFunction,
			Function sourceFunction, boolean useCustomStorage) throws InvalidInputException {
		Program destinationProgram = destinationFunction.getProgram();
		List<Parameter> parameters = new ArrayList<>();
		Parameter[] sourceParameters = sourceFunction.getParameters();
		for (Parameter sourceParameter : sourceParameters) {
			String name = sourceParameter.getName();
			DataType dataType = sourceParameter.getDataType();
			VariableStorage storage =
				(useCustomStorage) ? sourceParameter.getVariableStorage().clone(destinationProgram)
						: VariableStorage.UNASSIGNED_STORAGE;
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
	static boolean isDefaultFunctionName(Function function) {
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
			String specialProgramStr = HTMLUtilities.colorString(Color.DARK_GRAY, programStr);
			buf.append(specialProgramStr);
			buf.append(padStr);
		}
		return HTMLUtilities.wrapAsHTML(buf.toString());
	}
}
