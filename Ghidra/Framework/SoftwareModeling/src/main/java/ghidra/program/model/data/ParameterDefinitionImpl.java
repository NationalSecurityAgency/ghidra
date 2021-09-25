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

import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.InvalidInputException;

public class ParameterDefinitionImpl implements ParameterDefinition {

	private int ordinal;
	private String name;
	private DataType dataType;
	private String comment;

	/**
	 * Constructs a new ParameterImp with an unassigned ordinal.  The ordinal will be
	 * established by the function definition.
	 * @param name the name of the parameter.
	 * @param dataType the fixed-length datatype of the parameter
	 * @param comment the comment to store about this parameter.
	 * @throws IllegalArgumentException if invalid parameter datatype specified
	 */
	public ParameterDefinitionImpl(String name, DataType dataType, String comment) {
		this(name, dataType, comment, Parameter.UNASSIGNED_ORDINAL);
	}

	/**
	 * Constructs a new ParameterImp
	 * @param name the name of the parameter.
	 * @param dataType the fixed-length datatype of the parameter
	 * @param comment the comment to store about this parameter.
	 * @param ordinal the index of this parameter within the function signature.
	 * @throws IllegalArgumentException if invalid parameter datatype specified
	 */
	protected ParameterDefinitionImpl(String name, DataType dataType, String comment, int ordinal) {
		this.dataType = validateDataType(dataType,
			dataType != null ? dataType.getDataTypeManager() : null, false);
		this.name = name;
		this.comment = comment;
		this.ordinal = ordinal;
	}

	/**
	 * Check the specified datatype for use as a return, parameter or variable type.  It may
	 * not be suitable for other uses.  The following datatypes will be mutated into a default pointer datatype:
	 * <ul>
	 * <li>Function definition datatype</li>
	 * <li>An unsized/zero-element array</li>
	 * </ul>  
	 * @param dataType datatype to be checked.  If null specified the DEFAULT datatype will be returned.
	 * @param dtMgr target datatype manager (null permitted which will adopt default data organization)
	 * @param voidOK true if checking return datatype and void is allow, else false.
	 * @return cloned/mutated datatype suitable for function parameters and variables (including function return data type).
	 * @throws IllegalArgumentException if an unacceptable datatype was specified
	 */
	public static DataType validateDataType(DataType dataType, DataTypeManager dtMgr,
			boolean voidOK) throws IllegalArgumentException {
		try {
			return VariableUtilities.checkDataType(dataType, voidOK, dtMgr);
		}
		catch (InvalidInputException e) {
			throw new IllegalArgumentException(e.getMessage());
		}
	}

	@Override
	public final int compareTo(ParameterDefinition p) {
		return ordinal - p.getOrdinal();
	}

	@Override
	public int getOrdinal() {
		return ordinal;
	}

	@Override
	public String getComment() {
		return comment;
	}

	@Override
	public DataType getDataType() {
		return dataType;
	}

	@Override
	public int getLength() {
		return dataType.getLength();
	}

	@Override
	public String getName() {
		if (name == null) {
			return "";
		}
		return name;
	}

	@Override
	public void setComment(String comment) {
		if (comment != null && comment.endsWith("\n")) {
			comment = comment.substring(0, comment.length() - 1);
		}
		this.comment = comment;
	}

	@Override
	public void setDataType(DataType type) {
		this.dataType = validateDataType(type, dataType.getDataTypeManager(), false);
	}

	@Override
	public void setName(String name) {
		if (SymbolUtilities.isDefaultParameterName(name)) {
			name = null;
		}
		this.name = name;
	}

	@Override
	public boolean isEquivalent(Variable variable) {
		if (variable == null) {
			return false;
		}
		if (!(variable instanceof Parameter)) {
			return false;
		}
		if (ordinal != ((Parameter) variable).getOrdinal()) {
			return false;
		}
		return DataTypeUtilities.isSameOrEquivalentDataType(dataType, variable.getDataType());
	}

	@Override
	public boolean isEquivalent(ParameterDefinition parm) {
		if (parm == null) {
			return false;
		}
		if (ordinal != parm.getOrdinal()) {
			return false;
		}
		return DataTypeUtilities.isSameOrEquivalentDataType(dataType, parm.getDataType());
	}

	@Override
	public String toString() {
		return dataType.getName() + " " + name;
	}

}
