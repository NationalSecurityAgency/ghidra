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
package ghidra.program.model.data;

import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.symbol.SourceType;

/**
 * Defines a function signature for things like function pointers.
 */
public interface FunctionDefinition extends DataType, FunctionSignature {

	/**
	 * Set the arguments to this function.
	 * @param args array of parameter definitions to be used as arguments to this function
	 */
	public void setArguments(ParameterDefinition[] args);

	/**
	 * Set the return data type for this function
	 * @param type the return datatype to be set.
	 * @throws IllegalArgumentException if data type is not a fixed length type
	 */
	public void setReturnType(DataType type) throws IllegalArgumentException;

	/**
	 * Set the function comment
	 * @param comment the comment to set.
	 */
	public void setComment(String comment);

	/**
	 * Set whether parameters can be passed as a VarArg (variable argument list).
	 * 
	 * @param hasVarArgs true if this function has a variable argument list (ie printf(fmt, ...)).
	 */
	public void setVarArgs(boolean hasVarArgs);

	/**
	 * Set the generic calling convention associated with this function definition.
	 * @param genericCallingConvention generic calling convention
	 */
	public void setGenericCallingConvention(GenericCallingConvention genericCallingConvention);

	/**
	 * Replace the given argument with another data type
	 * 
	 * @param ordinal the index of the argument to be replaced, starting from '0'
	 * @param name name of the new argument
	 * @param dt data type of the new argument
	 * @param comment comment for the argument
	 * @param source the source of this function definition argument: 
	 * Symbol.DEFAULT, Symbol.ANALYSIS, Symbol.IMPORTED, or Symbol.USER_DEFINED
	 */
	public void replaceArgument(int ordinal, String name, DataType dt, String comment,
			SourceType source);

}
