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
package ghidra.program.model.listing;

import ghidra.program.model.data.*;

/**
 * Interface describing all the things about a function that are portable
 * from one program to another.
 */

public interface FunctionSignature {
	public static final String VAR_ARGS_DISPLAY_STRING = "...";
	public static final String VOID_PARAM_DISPLAY_STRING = "void";

	/**
	 * Return the name of this function
	 */
	public String getName();

	/**
	 * Return a string representation of the function signature without the
	 * calling convention specified.
	 */
	public String getPrototypeString();

	/**
	 * Return a string representation of the function signature
	 * @param includeCallingConvention if true prototype will include call convention
	 * declaration if known.
	 */
	public String getPrototypeString(boolean includeCallingConvention);

	/**
	 * Return an array of parameters for the function
	 */
	public ParameterDefinition[] getArguments();

	/**
	 * Return the return data type
	 */
	public DataType getReturnType();

	/**
	 * Return the comment string
	 */
	public String getComment();

	/**
	 * Returns true if this function signature has a variable argument list (VarArgs).
	 */
	public boolean hasVarArgs();

	/**
	 * Returns the generic calling convention associated with this function definition.
	 * The "unknown" convention should be returned instead of null.
	 */
	public GenericCallingConvention getGenericCallingConvention();

	/**
	 * Returns true if the given signature is equivalent to this signature.  The
	 * precise meaning of "equivalent" is dependent upon return/parameter dataTypes.
	 * @param signature the function signature being tested for equivalence.
	 * @return true if the if the given signature is equivalent to this signature.
	 */
	public boolean isEquivalentSignature(FunctionSignature signature);
}
