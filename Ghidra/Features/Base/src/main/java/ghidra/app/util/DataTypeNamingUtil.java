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
package ghidra.app.util;

import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.util.InvalidNameException;

public class DataTypeNamingUtil {

	private static final String ANONYMOUS_FUNCTION_DEF_PREFIX = "_func";

	private DataTypeNamingUtil() {
		// no construct
	}

	/**
	 * Generate a simple mangled function definition name and apply it to the specified
	 * functionDefinition.  Generated name will start with {@code _func}.
	 * @param functionDefinition function definition whose name should be set
	 * @return name applied to functionDefinition
	 */
	public static String setMangledAnonymousFunctionName(
			FunctionDefinitionDataType functionDefinition) {
		String name = generateMangledSignature(functionDefinition);
		try {
			functionDefinition.setName(name);
		}
		catch (InvalidNameException e) {
			// Note that we created the name using generateMangledSignature(functionDefinition).
			//  An invalid name is a programming error on our part.
			throw new AssertionError(e);
		}
		return name;
	}

	/**
	 * Generate a simple mangled function signature.  Generated string will start with
	 * {@code _func}.
	 * @param functionDefinition function definition is used for generating the name
	 * @return generated name
	 */
	public static String generateMangledSignature(FunctionDefinitionDataType functionDefinition) {

		DataType returnType = functionDefinition.getReturnType();
		ParameterDefinition[] parameters = functionDefinition.getArguments();

		StringBuilder sb = new StringBuilder(ANONYMOUS_FUNCTION_DEF_PREFIX);

		if (functionDefinition.hasNoReturn()) {
			sb.append("_").append(FunctionSignature.NORETURN_DISPLAY_STRING);
		}

		String convention = functionDefinition.getCallingConventionName();
		if (!Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(convention)) {
			sb.append("_").append(convention);
		}

		sb.append("_");
		sb.append(mangleDTName(returnType));
		for (ParameterDefinition p : parameters) {
			sb.append("_").append(mangleDTName(p.getDataType()));
		}

		if (functionDefinition.hasVarArgs()) {
			sb.append("_").append("varargs");
		}

		String name = sb.toString();
		if (!DataUtilities.isValidDataTypeName(name)) {
			// Note that we created the name.  An invalid name is a programming error on our part.
			throw new AssertionError("Unexpected bad name: " + name);
		}
		return name;
	}

	private static String mangleDTName(DataType dt) {
		String name = DataTypeUtilities.getNameWithoutConflict(dt);
		return name.replaceAll(" ", "_").replaceAll("\\*", "ptr");
	}

}
