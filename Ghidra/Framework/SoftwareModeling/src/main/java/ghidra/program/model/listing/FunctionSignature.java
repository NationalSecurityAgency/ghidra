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

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.lang.PrototypeModel;

/**
 * Interface describing all the things about a function that are portable
 * from one program to another.
 */

public interface FunctionSignature {
	public static final String NORETURN_DISPLAY_STRING = "noreturn";
	public static final String VAR_ARGS_DISPLAY_STRING = "...";
	public static final String VOID_PARAM_DISPLAY_STRING = "void";

	/**
	 * Return the name of this function
	 */
	public String getName();

	/**
	 * Get string representation of the function signature without the
	 * calling convention specified.
	 * @return function signature string
	 */
	public String getPrototypeString();

	/**
	 * Get string representation of the function signature
	 * @param includeCallingConvention if true prototype will include call convention
	 * declaration if known as well as <code>noreturn</code> indicator if applicable.
	 * @return function signature string
	 */
	public String getPrototypeString(boolean includeCallingConvention);

	/**
	 * Get function signature parameter arguments
	 * @return an array of parameters for the function
	 */
	public ParameterDefinition[] getArguments();

	/**
	 * Get function signature return type
	 * @return the return data type
	 */
	public DataType getReturnType();

	/**
	 * Get descriptive comment for signature
	 * @return the comment string
	 */
	public String getComment();

	/**
	 * @return true if this function signature has a variable argument list (VarArgs).
	 */
	public boolean hasVarArgs();

	/**
	 * @return true if this function signature corresponds to a non-returning function.
	 */
	public boolean hasNoReturn();

	/**
	 * Gets the calling convention prototype model for this function if associated with a 
	 * compiler specificfation.  This method will always return null if signature is not 
	 * associated with a specific program architecture.
	 * 
	 * @return the prototype model of the function's current calling convention or null.
	 */
	public PrototypeModel getCallingConvention();

	/**
	 * Returns the calling convention name associated with this function definition.
	 * Reserved names may also be returned: {@link Function#UNKNOWN_CALLING_CONVENTION_STRING},
	 * {@link Function#DEFAULT_CALLING_CONVENTION_STRING}.
	 * The "unknown" convention must be returned instead of null.
	 * @return calling convention name
	 */
	public String getCallingConventionName();

	/**
	 * Determine if this signature has an unknown or unrecognized calling convention name.
	 * @return true if calling convention is unknown or unrecognized name, else false.
	 */
	public default boolean hasUnknownCallingConventionName() {
		return getCallingConvention() == null;
	}

	/**
	 * Returns true if the given signature is equivalent to this signature.  The
	 * precise meaning of "equivalent" is dependent upon return/parameter dataTypes.
	 * @param signature the function signature being tested for equivalence.
	 * @return true if the if the given signature is equivalent to this signature.
	 */
	public boolean isEquivalentSignature(FunctionSignature signature);
}
