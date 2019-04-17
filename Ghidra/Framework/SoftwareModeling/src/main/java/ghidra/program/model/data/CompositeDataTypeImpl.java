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

import ghidra.app.plugin.core.datamgr.archive.SourceArchive;
import ghidra.docking.settings.Settings;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.InvalidNameException;
import ghidra.util.UniversalID;
import ghidra.util.exception.NotYetImplementedException;

/**
 *  Common implementation methods for structure and union
 */
public abstract class CompositeDataTypeImpl extends GenericDataType implements Composite {
	private final static long serialVersionUID = 1;
	private String description;

	protected boolean aligned = false;  //WARNING, changing the initial value for this will cause
										// subtle errors - One I know of is in the StructureDataType
										// copyComponent method.  It has built in assumptions about this.

	protected AlignmentType currentAlignment = AlignmentType.DEFAULT_ALIGNED;
	protected int packingValue = NOT_PACKING;
	protected int externalAlignment = DEFAULT_ALIGNMENT_VALUE;

	/**
	 * Creates an empty CompositeDataType with the specified name.
	 * @param path the category path indicating where this data type is located.
	 * @param name the data type's name
	 * @param dataTypeManager the data type manager associated with this data type. This can be null. 
	 * Also, the data type manager may not contain this actual data type.
	 */
	CompositeDataTypeImpl(CategoryPath path, String name, UniversalID universalID,
			SourceArchive sourceArchive, long lastChangeTime, long lastChangeTimeInSourceArchive,
			DataTypeManager dtm) {
		super(path != null ? path : CategoryPath.ROOT, name, universalID, sourceArchive,
			lastChangeTime, lastChangeTimeInSourceArchive, dtm);
		description = "";
	}

	CompositeDataTypeImpl(CategoryPath path, String name, DataTypeManager dtm) {
		super(path != null ? path : CategoryPath.ROOT, name, dtm);
		description = "";
	}

	@Override
	public boolean isDynamicallySized() {
		return isInternallyAligned();
	}

	@Override
	public boolean isPartOf(DataType dataTypeOfInterest) {
		return DataTypeUtilities.isSecondPartOfFirst(this, dataTypeOfInterest);
	}

	/**
	 * This method throws an exception if the indicated data type is an ancestor
	 * of this data type. In other words, the specified data type has a component
	 * or sub-component containing this data type.
	 * @param dataType the data type
	 * @throws IllegalArgumentException if the data type is an ancestor of this 
	 * data type.
	 */
	protected void checkAncestry(DataType dataType) {
		if (this.equals(dataType)) {
			throw new IllegalArgumentException(
				"Data type " + getDisplayName() + " can't contain itself.");
		}
		else if (DataTypeUtilities.isSecondPartOfFirst(dataType, this)) {
			throw new IllegalArgumentException("Data type " + dataType.getDisplayName() + " has " +
				getDisplayName() + " within it.");
		}
	}

	/**
	 * This method throws an exception if the indicated data type is not
	 * a valid data type for a component of this composite data type.
	 * @param dataType the data type to be checked.
	 * @throws IllegalArgumentException if the data type is invalid.
	 */
	protected void validateDataType(DataType dataType) {
		if (dataType instanceof FactoryDataType) {
			throw new IllegalArgumentException("The \"" + dataType.getName() +
				"\" data type is not allowed in a composite data type.");
		}
		else if (dataType instanceof Dynamic) {
			Dynamic dynamicDataType = (Dynamic) dataType;
			if (!dynamicDataType.canSpecifyLength()) {
				throw new IllegalArgumentException("The \"" + dataType.getName() +
					"\" data type is not allowed in a composite data type.");
			}
		}
	}

	@Override
	public DataTypeComponent add(DataType dataType) {
		dataType = dataType.clone(getDataTypeManager());
		return add(dataType, dataType.getLength(), null, null);
	}

	@Override
	public void setDescription(String desc) {
		this.description = desc == null ? "" : desc;
	}

	@Override
	public String getDescription() {
		return description;
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return null;
	}

	public void setValue(MemBuffer buf, Settings settings, int length, Object value) {
		throw new NotYetImplementedException("setValue() not implemented");
	}

	@Override
	public DataTypeComponent add(DataType dataType, int length) {
		return add(dataType, length, null, null);
	}

	@Override
	public DataTypeComponent add(DataType dataType, String fieldName, String comment) {
		return add(dataType, dataType.getLength(), fieldName, comment);
	}

	@Override
	public DataTypeComponent insert(int ordinal, DataType dataType, int length) {
		return insert(ordinal, dataType, length, null, null);
	}

	@Override
	public DataTypeComponent insert(int ordinal, DataType dataType) {
		return insert(ordinal, dataType, dataType.getLength(), null, null);
	}

	@Override
	public String getMnemonic(Settings settings) {
		return getDisplayName();
	}

	@Override
	public void setName(String name) throws InvalidNameException {
		checkValidName(name);
		this.name = name;
	}

	@Override
	public int getPackingValue() {
		return packingValue;
	}

	@Override
	public void setPackingValue(int packingValue) {
		aligned = true;
		this.packingValue = packingValue;
		adjustInternalAlignment();
	}

	@Override
	public int getMinimumAlignment() {
		return externalAlignment;
	}

	@Override
	public void setMinimumAlignment(int externalAlignment) {
		aligned = true;
		if (currentAlignment != AlignmentType.ALIGNED_BY_VALUE) {
			currentAlignment = AlignmentType.ALIGNED_BY_VALUE;
		}
		this.externalAlignment = externalAlignment;
		adjustInternalAlignment();
	}

	@Override
	public boolean isInternallyAligned() {
		return aligned;
	}

	@Override
	public boolean isDefaultAligned() {
		return currentAlignment == AlignmentType.DEFAULT_ALIGNED;
	}

	@Override
	public boolean isMachineAligned() {
		return currentAlignment == AlignmentType.MACHINE_ALIGNED;
	}

	@Override
	public void setInternallyAligned(boolean aligned) {
		if (this.aligned != aligned) {
			this.aligned = aligned;
			if (!aligned) {
				currentAlignment = AlignmentType.DEFAULT_ALIGNED;
				packingValue = Composite.NOT_PACKING;
			}
		}
		adjustInternalAlignment();
	}

	@Override
	public void setToDefaultAlignment() {
		aligned = true;
		currentAlignment = AlignmentType.DEFAULT_ALIGNED;
		adjustInternalAlignment();
	}

	@Override
	public void setToMachineAlignment() {
		aligned = true;
		currentAlignment = AlignmentType.MACHINE_ALIGNED;
		adjustInternalAlignment();
	}

	/**
	 * Notify any parent data types that this composite data type's alignment has changed.
	 */
	protected void notifyAlignmentChanged() {
		DataType[] parents = getParents();
		for (DataType dataType : parents) {
			if (dataType instanceof Composite) {
				Composite composite = (Composite) dataType;
				composite.dataTypeAlignmentChanged(this);
			}
		}
	}

	/**
	 * Adjusts the internal alignment of components within this composite based on the current
	 * settings of the internal alignment, packing, alignment type and minimum alignment value.
	 * This method should be called whenever any of the above settings are changed or whenever
	 * a components data type is changed or a component is added or removed.
	 */
	protected abstract void adjustInternalAlignment();

	@Override
	public int getAlignment() {
		return getDataOrganization().getAlignment(this, getLength());
	}

	// set my alignment info to the same as the given composite
	protected void setDataAlignmentInfo(Composite composite) {

		aligned = composite.isInternallyAligned();

		if (composite.isDefaultAligned()) {
			currentAlignment = AlignmentType.DEFAULT_ALIGNED;
		}
		else if (composite.isMachineAligned()) {
			currentAlignment = AlignmentType.MACHINE_ALIGNED;
		}
		else {
			if (currentAlignment != AlignmentType.ALIGNED_BY_VALUE) {
				currentAlignment = AlignmentType.ALIGNED_BY_VALUE;
			}
			externalAlignment = composite.getMinimumAlignment();
		}

		packingValue = composite.getPackingValue();

		adjustInternalAlignment();
	}

	/**
	 * Dump all components for use in {@link #toString()} representation.
	 * @param buffer string buffer
	 * @param pad padding to be used with each component output line
	 */
	protected void dumpComponents(StringBuilder buffer, String pad) {
		for (DataTypeComponent dtc : getComponents()) {
			DataType dataType = dtc.getDataType();
			buffer.append(pad + dataType.getDisplayName());
			buffer.append(pad + dtc.getLength());
			buffer.append(pad + dtc.getFieldName());
			String comment = dtc.getComment();
			if (comment == null) {
				comment = "";
			}
			buffer.append(pad + "\"" + comment + "\"");
			buffer.append("\n");
		}
	}

	@Override
	public String toString() {
		StringBuilder stringBuffer = new StringBuilder();
		stringBuffer.append(getPathName() + "\n");
		stringBuffer.append(getAlignmentSettingsString() + "\n");
		stringBuffer.append(getTypeName() + " " + getDisplayName() + " {\n");
		dumpComponents(stringBuffer, "   ");
		stringBuffer.append("}\n");
		stringBuffer.append(
			"Size = " + getLength() + "   Actual Alignment = " + getAlignment() + "\n");
		return stringBuffer.toString();
	}

	private String getTypeName() {
		if (this instanceof Structure) {
			return "Structure";
		}
		else if (this instanceof Union) {
			return "Union";
		}
		return "";
	}

	private String getAlignmentSettingsString() {
		StringBuffer stringBuffer = new StringBuffer();
		if (!isInternallyAligned()) {
			stringBuffer.append("Unaligned");
		}
		else if (isDefaultAligned()) {
			stringBuffer.append("Aligned");
		}
		else if (isMachineAligned()) {
			stringBuffer.append("Machine aligned");
		}
		else {
			long alignment = getMinimumAlignment();
			stringBuffer.append("align(" + alignment + ")");
		}
		stringBuffer.append(getPackingString());
		return stringBuffer.toString();
	}

	private String getPackingString() {
		if (!isInternallyAligned()) {
			return "";
		}
		if (packingValue == Composite.NOT_PACKING) {
			return "";
		}
		return " pack(" + packingValue + ")";
	}
}
