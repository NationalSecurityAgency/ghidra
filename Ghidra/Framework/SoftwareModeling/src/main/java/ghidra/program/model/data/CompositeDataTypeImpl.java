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

import ghidra.docking.settings.Settings;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.InvalidNameException;
import ghidra.util.UniversalID;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.NotYetImplementedException;

/**
 * Common implementation methods for structure and union
 */
public abstract class CompositeDataTypeImpl extends GenericDataType implements Composite {
	private final static long serialVersionUID = 1;
	private String description;

	protected boolean aligned = false; // WARNING, changing the initial value for this will cause
										// subtle errors - One I know of is in the StructureDataType
										// copyComponent method. It has built in assumptions about this.

	protected AlignmentType alignmentType = AlignmentType.DEFAULT_ALIGNED;
	protected int packingValue = NOT_PACKING;
	protected int externalAlignment = DEFAULT_ALIGNMENT_VALUE;

	/**
	 * Construct a new composite with the given name
	 * 
	 * @param path                          the category path indicating where this
	 *                                      data type is located.
	 * @param name                          the name of the new structure
	 * @param universalID                   the id for the data type
	 * @param sourceArchive                 the source archive for this data type
	 * @param lastChangeTime                the last time this data type was changed
	 * @param lastChangeTimeInSourceArchive the last time this data type was changed
	 *                                      in its source archive.
	 * @param dtm                           the data type manager associated with
	 *                                      this data type. This can be null. Also,
	 *                                      the data type manager may not yet
	 *                                      contain this actual data type.
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

	/**
	 * Get the preferred length for a new component. For Unions and internally
	 * aligned structures the preferred component length for a fixed-length dataType
	 * will be the length of that dataType. Otherwise the length returned will be no
	 * larger than the specified length.
	 * 
	 * @param dataType new component datatype
	 * @param length   constrained length or -1 to force use of dataType size.
	 *                 Dynamic types such as string must have a positive length
	 *                 specified.
	 * @return preferred component length
	 */
	protected int getPreferredComponentLength(DataType dataType, int length) {
		if ((isInternallyAligned() || (this instanceof Union)) && !(dataType instanceof Dynamic)) {
			length = -1; // force use of datatype size
		}
		int dtLength = dataType.getLength();
		if (length <= 0) {
			length = dtLength;
		}
		else if (dtLength > 0 && dtLength < length) {
			length = dtLength;
		}
		if (length <= 0) {
			throw new IllegalArgumentException("Positive length must be specified for " +
				dataType.getDisplayName() + " component");
		}
		return length;
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
	 * This method throws an exception if the indicated data type is an ancestor of
	 * this data type. In other words, the specified data type has a component or
	 * sub-component containing this data type.
	 * 
	 * @param dataType the data type
	 * @throws IllegalArgumentException if the data type is an ancestor of this data
	 *                                  type.
	 */
	protected void checkAncestry(DataType dataType) throws IllegalArgumentException {
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
	 * This method throws an exception if the indicated data type is not a valid
	 * data type for a component of this composite data type.
	 * 
	 * @param dataType the data type to be checked.
	 * @throws IllegalArgumentException if the data type is invalid.
	 */
	protected void validateDataType(DataType dataType) {
		if (isInternallyAligned() && dataType == DataType.DEFAULT) {
			throw new IllegalArgumentException(
				"The DEFAULT data type is not allowed in an aligned composite data type.");
		}
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

	/**
	 * Handle replacement of datatype which may impact bitfield datatype.
	 * 
	 * @param bitfieldComponent bitfield component
	 * @param oldDt             affected datatype which has been removed or replaced
	 * @param newDt             replacement datatype
	 * @return true if bitfield component was modified
	 * @throws InvalidDataTypeException if new datatype is not
	 */
	protected boolean updateBitFieldDataType(DataTypeComponentImpl bitfieldComponent,
			DataType oldDt, DataType newDt) throws InvalidDataTypeException {
		if (!bitfieldComponent.isBitFieldComponent()) {
			throw new AssertException("expected bitfield component");
		}

		BitFieldDataType bitfieldDt = (BitFieldDataType) bitfieldComponent.getDataType();
		if (bitfieldDt.getBaseDataType() != oldDt) {
			return false;
		}

		if (newDt != null) {
			BitFieldDataType.checkBaseDataType(newDt);
			int maxBitSize = 8 * newDt.getLength();
			if (bitfieldDt.getBitSize() > maxBitSize) {
				throw new InvalidDataTypeException("Replacement datatype too small for bitfield");
			}
		}

		try {
			BitFieldDataType newBitfieldDt = new BitFieldDataType(newDt,
				bitfieldDt.getDeclaredBitSize(), bitfieldDt.getBitOffset());
			bitfieldComponent.setDataType(newBitfieldDt);
			oldDt.removeParent(this);
			newDt.addParent(this);
		}
		catch (InvalidDataTypeException e) {
			throw new AssertException("unexpected");
		}

		return true;
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
	public final DataTypeComponent add(DataType dataType) {
		return add(dataType, -1, null, null);
	}

	@Override
	public final DataTypeComponent add(DataType dataType, int length) {
		return add(dataType, length, null, null);
	}

	@Override
	public final DataTypeComponent add(DataType dataType, String fieldName, String comment) {
		return add(dataType, -1, fieldName, comment);
	}

	@Override
	public final DataTypeComponent insert(int ordinal, DataType dataType, int length) {
		return insert(ordinal, dataType, length, null, null);
	}

	@Override
	public final DataTypeComponent insert(int ordinal, DataType dataType) {
		return insert(ordinal, dataType, -1, null, null);
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
		if (packingValue < 0) {
			packingValue = NOT_PACKING;
		}
		aligned = true;
		this.packingValue = packingValue;
		adjustInternalAlignment();
	}

	@Override
	public int getMinimumAlignment() {
		if (alignmentType == AlignmentType.MACHINE_ALIGNED) {
			return getMachineAlignment();
		}
		if (alignmentType == AlignmentType.DEFAULT_ALIGNED) {
			return Composite.DEFAULT_ALIGNMENT_VALUE;
		}
		return externalAlignment;
	}

	@Override
	public void setMinimumAlignment(int externalAlignment) {
		if (externalAlignment < 1) {
			this.externalAlignment = DEFAULT_ALIGNMENT_VALUE;
			alignmentType = AlignmentType.DEFAULT_ALIGNED;
		}
		else {
			this.externalAlignment = externalAlignment;
			alignmentType = AlignmentType.ALIGNED_BY_VALUE;
		}
		aligned = true;
		adjustInternalAlignment();
	}

	private int getMachineAlignment() {
		return getDataOrganization().getMachineAlignment();
	}

	@Override
	public boolean isInternallyAligned() {
		return aligned;
	}

	@Override
	public boolean isDefaultAligned() {
		return alignmentType == AlignmentType.DEFAULT_ALIGNED;
	}

	@Override
	public boolean isMachineAligned() {
		return alignmentType == AlignmentType.MACHINE_ALIGNED;
	}

	@Override
	public void setInternallyAligned(boolean aligned) {
		if (this.aligned != aligned) {
			this.aligned = aligned;
			if (!aligned) {
				alignmentType = AlignmentType.DEFAULT_ALIGNED;
				packingValue = Composite.NOT_PACKING;
			}
		}
		adjustInternalAlignment();
	}

	@Override
	public void setToDefaultAlignment() {
		aligned = true;
		alignmentType = AlignmentType.DEFAULT_ALIGNED;
		adjustInternalAlignment();
	}

	@Override
	public void setToMachineAlignment() {
		aligned = true;
		alignmentType = AlignmentType.MACHINE_ALIGNED;
		adjustInternalAlignment();
	}

	/**
	 * Notify any parent data types that this composite data type's alignment has
	 * changed.
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
	 * Adjusts the internal alignment of components within this composite based on
	 * the current settings of the internal alignment, packing, alignment type and
	 * minimum alignment value. This method should be called whenever any of the
	 * above settings are changed or whenever a components data type is changed or a
	 * component is added or removed.
	 */
	protected abstract void adjustInternalAlignment();

	@Override
	public int getAlignment() {
		return CompositeAlignmentHelper.getAlignment(getDataOrganization(), this);
	}

	// set my alignment info to the same as the given composite
	protected void setAlignment(Composite composite) {

		aligned = composite.isInternallyAligned();

		if (composite.isDefaultAligned()) {
			alignmentType = AlignmentType.DEFAULT_ALIGNED;
		}
		else if (composite.isMachineAligned()) {
			alignmentType = AlignmentType.MACHINE_ALIGNED;
		}
		else {
			if (alignmentType != AlignmentType.ALIGNED_BY_VALUE) {
				alignmentType = AlignmentType.ALIGNED_BY_VALUE;
			}
			externalAlignment = composite.getMinimumAlignment();
		}

		packingValue = composite.getPackingValue();

		adjustInternalAlignment();
	}

	/**
	 * Dump all components for use in {@link #toString()} representation.
	 * 
	 * @param buffer string buffer
	 * @param pad    padding to be used with each component output line
	 */
	protected void dumpComponents(StringBuilder buffer, String pad) {
		// limit output of filler components for unaligned structures
		DataTypeComponent[] components = getDefinedComponents();
		for (DataTypeComponent dtc : components) {
			DataType dataType = dtc.getDataType();
			buffer.append(pad + dtc.getOffset());
			buffer.append(pad + dataType.getName());
			if (dataType instanceof BitFieldDataType) {
				BitFieldDataType bfDt = (BitFieldDataType) dataType;
				buffer.append("(");
				buffer.append(Integer.toString(bfDt.getBitOffset()));
				buffer.append(")");
			}
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
