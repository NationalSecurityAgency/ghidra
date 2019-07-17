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

import org.apache.commons.lang3.StringUtils;

import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
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
	 * @param dataType the datatype of the parameter
	 * @param comment the comment to store about this parameter.
	 */
	public ParameterDefinitionImpl(String name, DataType dataType, String comment) {
		this(name, dataType, comment, Parameter.UNASSIGNED_ORDINAL);
	}

	/**
	 * Constructs a new ParameterImp
	 * @param name the name of the parameter.
	 * @param dataType the datatype of the parameter
	 * @param comment the comment to store about this parameter.
	 * @param ordinal the index of this parameter within the function signature.
	 */
	protected ParameterDefinitionImpl(String name, DataType dataType, String comment, int ordinal) {
		this.dataType = checkDataType(dataType, null);
		this.name = name;
		this.comment = comment;
		this.ordinal = ordinal;
	}

	public static DataType checkDataType(DataType dataType, DataTypeManager dtMgr) {
		if (dataType == null) {
			dataType = DataType.DEFAULT;
		}
		else if (dataType instanceof FunctionDefinition || (dataType instanceof TypeDef &&
			((TypeDef) dataType).getBaseDataType() instanceof FunctionDefinition)) {
			dataType = new PointerDataType(dataType, dtMgr);
		}
		else if (dataType instanceof Dynamic || dataType instanceof FactoryDataType) {
			throw new IllegalArgumentException(
				"Parameter may not be defined with Dynamic or Factory data-type: " +
					dataType.getName());
		}
		dataType = dataType.clone(dtMgr != null ? dtMgr : dataType.getDataTypeManager());
		if (!dataType.isDynamicallySized() && dataType.getLength() < 0) {
			throw new IllegalArgumentException(
				"Parameter must be specified with fixed-length data type: " + dataType.getName());
		}
		if (dataType instanceof VoidDataType) {
			throw new IllegalArgumentException(
				"Parameter may not specify the void datatype - empty parameter list should be used");
		}
		if (!(dataType instanceof Composite) && dataType.getLength() == 0) {
			throw new IllegalArgumentException(
				"Parameter must be specified with fixed-length data type: " + dataType.getName());
		}
		return dataType;
	}

	/**
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
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
	public void setDataType(DataType type) throws InvalidInputException {
		this.dataType = checkDataType(type, dataType.getDataTypeManager());
	}

	@Override
	public void setName(String name) {
		if (SymbolUtilities.isDefaultParameterName(name)) {
			name = null;
		}
		this.name = name;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		if (!(obj instanceof ParameterDefinition)) {
			return false;
		}

		ParameterDefinition otherVar = (ParameterDefinition) obj;
		if (ordinal != otherVar.getOrdinal()) {
			return false;
		}
		if (!DataTypeUtilities.isSameOrEquivalentDataType(dataType, otherVar.getDataType())) {
			return false;
		}
		if (!StringUtils.equals(getName(), otherVar.getName())) {
			return false;
		}
		return StringUtils.equals(getComment(), otherVar.getComment());
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
