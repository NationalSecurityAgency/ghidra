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

import ghidra.program.model.data.*;
import ghidra.util.InvalidNameException;

public class DataTypeNamingUtil {
	
	private DataTypeNamingUtil() {
		// no construct
	}
	
	/**
	 * Generate a simple mangled function definition name and apply it to the specified functionDefinition.
	 * @param functionDefinition function definition whose name should be set
	 * @param namePrefix prefix to be applied to generated name.  An underscore will separate this prefix from the 
	 * remainder of the mangled name.  If null specified a prefix of "_function" will be used.
	 * @return name applied to functionDefinition
	 * @throws IllegalArgumentException if generated name contains unsupported characters
	 */
	public static String setMangledAnonymousFunctionName(
			FunctionDefinitionDataType functionDefinition, String namePrefix)
			throws IllegalArgumentException {

		DataType returnType = functionDefinition.getReturnType();
		ParameterDefinition[] parameters = functionDefinition.getArguments();

		if (namePrefix == null) {
			namePrefix = "_function";
		}
		StringBuilder sb = new StringBuilder(namePrefix);

		GenericCallingConvention convention = functionDefinition.getGenericCallingConvention();
		if (convention != null && convention != GenericCallingConvention.unknown) {
			sb.append(convention.getDeclarationName());
		}
		sb.append("_");

		sb.append(mangleDTName(returnType.getName()));
		for (ParameterDefinition p : parameters) {
			sb.append("_").append(mangleDTName(p.getDataType().getName()));
		}

		if (functionDefinition.hasVarArgs()) {
			sb.append("_").append("varargs");
		}

		String name = sb.toString();
		try {
			functionDefinition.setName(name);
		}
		catch (InvalidNameException e) {
			throw new IllegalArgumentException(e);
		}
		return name;
	}

	private static String mangleDTName(String s) {
		return s.replaceAll(" ", "_").replaceAll("\\*", "ptr");
	}

}
