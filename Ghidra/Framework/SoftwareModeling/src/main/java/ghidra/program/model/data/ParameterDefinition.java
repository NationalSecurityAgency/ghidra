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

import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;

/**
 * <code>ParameterDefinition</code> specifies a parameter which can be
 * used to specify a function definition.
 */
public interface ParameterDefinition extends Comparable<ParameterDefinition> {

	/**
	 * Get the parameter ordinal
	 * 
	 * @return the ordinal (index) of this parameter within the function signature.
	 */
	int getOrdinal();

	/**
	 * Get the Data Type of this variable
	 *
	 * @return the data type of the variable
	 */
	public DataType getDataType();

	/**
	 * Set the Data Type of this variable.
	 * @param type dataType the fixed-length datatype of the parameter
	 * @throws IllegalArgumentException if invalid parameter datatype specified
	 */
	public void setDataType(DataType type) throws IllegalArgumentException;

	/**
	 * Get the Name of this variable.
	 *
	 * @return the name of the variable or null if no name has been specified.
	 */
	public String getName();

	/**
	 * Get the length of this variable
	 *
	 * @return the length of the variable
	 */
	public int getLength();

	/**
	 * Set the name of this variable.
	 * @param name the name
	 */
	public void setName(String name);

	/**
	 * Get the Comment for this variable
	 *
	 * @return the comment
	 */
	public String getComment();

	/**
	 * Set the comment for this variable
	 * @param comment the comment
	 */
	public void setComment(String comment);

	/**
	 * Determine if a variable corresponds to a parameter which is equivalent to 
	 * this parameter definition by both ordinal and datatype.  Name is not considered
	 * relevant. 
	 * @param variable variable to be compared with this parameter definition.
	 * @return true if the specified variable represents the same parameter by ordinal
	 * and dataType.  False will always be returned if specified variable is
	 * not a {@link Parameter}.
	 */
	public boolean isEquivalent(Variable variable);

	/**
	 * Determine if parm is equivalent to this parameter definition by both ordinal 
	 * and datatype.  Name is not considered relevant. 
	 * @param parm parameter definition to be compared with this parameter definition.
	 * @return true if the specified parameter definition represents the same parameter 
	 * by ordinal and dataType.
	 */
	public boolean isEquivalent(ParameterDefinition parm);
}
