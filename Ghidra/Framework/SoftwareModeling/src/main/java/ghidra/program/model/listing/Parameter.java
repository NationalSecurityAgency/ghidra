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

/**
 * Interface for function parameters
 */
public interface Parameter extends Variable {

	public static final String RETURN_NAME = "<RETURN>";

	public static final int RETURN_ORIDINAL = -1;
	public static final int UNASSIGNED_ORDINAL = -2;

	/**
	 * Returns the ordinal (index) of this parameter within the function signature.
	 */
	public int getOrdinal();

	/**
	 * @return true if this parameter is automatically generated based upon the associated
	 * function calling convention and function signature.  An example of such a parameter 
	 * include the "__return_storage_ptr__" parameter. 
	 */
	public boolean isAutoParameter();

	/**
	 * If this is an auto-parameter this method will indicate its type.
	 * @return auto-parameter type of null if not applicable.
	 */
	public AutoParameterType getAutoParameterType();

	/**
	 * If this parameter which was forced by the associated calling 
	 * convention to be passed as a pointer instead of its original formal type.
	 * @return true if this parameter was forced to be passed as a pointer instead of its 
	 * original formal type
	 */
	public boolean isForcedIndirect();

	/**
	 * Get the original formal signature data type before a possible forced indirect was
	 * possibly imposed by the functions calling convention.  The {@link #getDataType()} method 
	 * will always return the effective data type which corresponds to the allocated 
	 * variable storage.
	 * @return Formal data type.  This type will only differ from the {@link #getDataType()}
	 * value if this parameter isForcedIndirect.
	 */
	public DataType getFormalDataType();
}
