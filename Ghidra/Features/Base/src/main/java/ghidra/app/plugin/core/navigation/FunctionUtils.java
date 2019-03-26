/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.navigation;

import ghidra.app.util.viewer.field.FieldStringInfo;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;

import java.util.ArrayList;
import java.util.List;

public class FunctionUtils {

	/**
	 * Returns a FieldStringInfo object for the given function's return type.  This info contains
	 * the return type string and its location in the function signature.
	 * 
	 * @param function The function from which to get the return type.
	 * @param functionSignatureString The function signature string from which to get the return
	 * type string.
	 * @return Returns a FieldStringInfo object for the given function's return type.
	 */
	public static FieldStringInfo getFunctionReturnTypeStringInfo(Function function,
			String functionSignatureString) {
		DataType returnType = function.getReturnType();
		return new FieldStringInfo(functionSignatureString, returnType.getName(), 0);
	}

	/**
	 * Returns a FieldStringInfo object for the given function's name.  This info contains
	 * the name string and its location in the function signature.
	 * 
	 * @param function The function from which to get the name.
	 * @param functionSignatureString The function signature string from which to get the name
	 * string.
	 * @return Returns a FieldStringInfo object for the given function's name.
	 */
	public static FieldStringInfo getFunctionNameStringInfo(Function function,
			String functionSignatureString) {
		String functionName = function.getName(true);

		// check for fully-qualified name
		int offset = functionSignatureString.indexOf(functionName);
		if (offset == -1) {
			functionName = function.getName();
			offset = functionSignatureString.indexOf(functionName);
		}

		return new FieldStringInfo(functionSignatureString, functionName, offset);
	}

	public static int getCallingConventionSignatureOffset(Function function) {
		PrototypeModel callingConvention = function.getCallingConvention();
		if (callingConvention == null) {
			return 0;
		}
		String callingConventionName = callingConvention.getName();
		if (callingConventionName == null) {
			return 0;
		}
		if (callingConventionName.equals(Function.UNKNOWN_CALLING_CONVENTION_STRING)) {
			return 0;
		}
		return callingConventionName.length() + 1;

	}

	/**
	 * Returns a FieldStringInfo object for the given function's parameters.  This info contains
	 * the parameter string and their respective locations in the function signature.  Each
	 * returned FieldStringInfo object will contain a single string retrievable from 
	 * {@link FieldStringInfo#getFieldString()} that is a space-separated combination of the 
	 * parameter's datatype and name.
	 * 
	 * @param function The function from which to get the function parameter strings.
	 * @param functionSignatureString The function signature string from which to get the 
	 * parameter strings.
	 * @return Returns a FieldStringInfo object for the given function's parameter strings.
	 */
	public static FieldStringInfo[] getFunctionParameterStringInfos(Function function,
			String functionSignatureString) {
		Parameter[] arguments = function.getParameters();

		int startIndex = functionSignatureString.indexOf('(') + 1;
		List<FieldStringInfo> list = new ArrayList<FieldStringInfo>();
		for (Parameter parameter : arguments) {
			String dataTypeName = parameter.getDataType().getDisplayName();
			String parameterName = parameter.getName();

			startIndex = functionSignatureString.indexOf(dataTypeName, startIndex);
			list.add(new FieldStringInfo(functionSignatureString, dataTypeName + " " +
				parameterName, startIndex));

			// push the starting point past the name of the current parameter            
			startIndex =
				functionSignatureString.indexOf(parameterName, startIndex) + parameterName.length();
		}

		return list.toArray(new FieldStringInfo[list.size()]);
	}
}
