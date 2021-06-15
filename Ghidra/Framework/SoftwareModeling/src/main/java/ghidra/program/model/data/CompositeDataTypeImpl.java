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
public abstract class CompositeDataTypeImpl extends GenericDataType implements CompositeInternal {

	// Strings used for toString formatting
	private static final String ALIGN_NAME = "aligned";
	private static final String PACKING_NAME = "pack";
	private static final String DISABLED_PACKING_NAME = "disabled";
	private static final String DEFAULT_PACKING_NAME = "";

	private String description;

	protected int minimumAlignment = DEFAULT_ALIGNMENT;
	protected int packing = NO_PACKING;

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

	@Override
	public int getStoredPackingValue() {
		return packing;
	}

	@Override
	public int getStoredMinimumAlignment() {
		return minimumAlignment;
	}

	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
		// ignored
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
	public abstract boolean hasLanguageDependantLength();

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
	 * data type for a component of this composite data type.  If the DEFAULT 
	 * datatype is specified when unsupported an Undefined1 will be returned 
	 * in its place (e.g., packing enabled, Union).
	 * 
	 * @param dataType the data type to be checked.
	 * @return datatype to be used for insert/add
	 * @throws IllegalArgumentException if the data type is invalid.
	 */
	protected DataType validateDataType(DataType dataType) {
		if (dataType == DataType.DEFAULT) {
			if (isPackingEnabled() || (this instanceof Union)) {
				return Undefined1DataType.dataType;
			}
			return dataType;
		}
		if (dataType instanceof Dynamic) {
			Dynamic dynamicDataType = (Dynamic) dataType;
			if (!dynamicDataType.canSpecifyLength()) {
				throw new IllegalArgumentException("The \"" + dataType.getName() +
					"\" data type is not allowed in a composite data type.");
			}
		}
		else if (dataType instanceof FactoryDataType || dataType.getLength() <= 0) {
			throw new IllegalArgumentException("The \"" + dataType.getName() +
				"\" data type is not allowed in a composite data type.");
		}
		return dataType;
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
	public final void repack() {
		repack(true);
	}

	/**
	 * Repack components within this composite based on the current packing, alignment 
	 * and {@link DataOrganization} settings.  Non-packed Structures: change detection
	 * is limited to component count and length is assumed to already be correct.
	 * <p>
	 * NOTE: If modifications to stored length are made prior to invoking this method, 
	 * detection of a size change may not be possible.  
	 * <p>
	 * NOTE: Currently a change in calculated alignment can not be provided since
	 * this value is not stored.
	 * 
	 * @param notify if true notification will be sent to parents if a size change
	 * or component placement change is detected.
	 * @return true if a layout change was detected.
	 */
	public abstract boolean repack(boolean notify);

	@Override
	public void setPackingEnabled(boolean enabled) {
		if (enabled == isPackingEnabled()) {
			return;
		}
		setStoredPackingValue(enabled ? DEFAULT_PACKING : NO_PACKING);
	}

	@Override
	public PackingType getPackingType() {
		if (packing < DEFAULT_PACKING) {
			return PackingType.DISABLED;
		}
		if (packing == DEFAULT_PACKING) {
			return PackingType.DEFAULT;
		}
		return PackingType.EXPLICIT;
	}

	@Override
	public void setToDefaultPacking() {
		setStoredPackingValue(DEFAULT_PACKING);
	}

	@Override
	public int getExplicitPackingValue() {
		return packing;
	}

	@Override
	public void setExplicitPackingValue(int packingValue) {
		if (packingValue <= 0) {
			throw new IllegalArgumentException(
				"explicit packing value must be positive: " + packingValue);
		}
		setStoredPackingValue(packingValue);
	}

	private void setStoredPackingValue(int packingValue) {
		if (minimumAlignment < NO_PACKING) {
			throw new IllegalArgumentException("invalid packing value: " + packingValue);
		}
		if (packingValue == this.packing) {
			return;
		}
		if (this.packing == NO_PACKING || packingValue == NO_PACKING) {
			// force default alignment when transitioning to or from disabled packing
			this.minimumAlignment = DEFAULT_ALIGNMENT;
		}
		this.packing = packingValue;
		repack(true);
	}

	@Override
	public AlignmentType getAlignmentType() {
		if (minimumAlignment < DEFAULT_ALIGNMENT) {
			return AlignmentType.MACHINE;
		}
		if (minimumAlignment == DEFAULT_ALIGNMENT) {
			return AlignmentType.DEFAULT;
		}
		return AlignmentType.EXPLICIT;
	}

	@Override
	public void setToDefaultAligned() {
		setStoredMinimumAlignment(DEFAULT_ALIGNMENT);
	}

	@Override
	public void setToMachineAligned() {
		setStoredMinimumAlignment(MACHINE_ALIGNMENT);
	}

	@Override
	public int getExplicitMinimumAlignment() {
		return minimumAlignment;
	}

	@Override
	public void setExplicitMinimumAlignment(int minimumAlignment) {
		if (minimumAlignment <= 0) {
			throw new IllegalArgumentException(
				"explicit minimum alignment must be positive: " + minimumAlignment);
		}
		setStoredMinimumAlignment(minimumAlignment);
	}

	private void setStoredMinimumAlignment(int minimumAlignment) {
		if (minimumAlignment < MACHINE_ALIGNMENT) {
			throw new IllegalArgumentException(
				"invalid minimum alignment value: " + minimumAlignment);
		}
		if (this.minimumAlignment == minimumAlignment) {
			return;
		}
		this.minimumAlignment = minimumAlignment;
		repack(true);
	}

	protected final int getNonPackedAlignment() {
		int alignment;
		if (minimumAlignment == DEFAULT_ALIGNMENT) {
			alignment = 1;
		}
		else if (minimumAlignment == MACHINE_ALIGNMENT) {
			alignment = getDataOrganization().getMachineAlignment();
		}
		else {
			alignment = minimumAlignment;
		}
		return alignment;
	}

	@Override
	public abstract int getAlignment();

	@Override
	public String toString() {
		return toString(this);
	}

	public static String toString(Composite composite) {

		StringBuilder stringBuffer = new StringBuilder();
		stringBuffer.append(composite.getPathName() + "\n");
		stringBuffer.append(getAlignmentAndPackingString(composite) + "\n");
		stringBuffer.append(getTypeName(composite) + " " + composite.getDisplayName() + " {\n");
		dumpComponents(composite, stringBuffer, "   ");
		stringBuffer.append("}\n");
		stringBuffer.append("Size = " + composite.getLength() + "   Actual Alignment = " +
			composite.getAlignment() + "\n");
		return stringBuffer.toString();

	}

	/**
	 * Dump all components for use in {@link #toString()} representation.
	 * 
	 * @param buffer string buffer
	 * @param pad    padding to be used with each component output line
	 */
	private static void dumpComponents(Composite composite, StringBuilder buffer, String pad) {
		// limit output of filler components for non-packed structures
		DataTypeComponent[] components = composite.getDefinedComponents();
		for (DataTypeComponent dtc : components) {
			DataType dataType = dtc.getDataType();
//			buffer.append(pad + dtc.getOrdinal());
//			buffer.append(") ");
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
		if (composite instanceof Structure) {
			DataTypeComponent dtc = ((Structure) composite).getFlexibleArrayComponent();
			if (dtc != null) {
				DataType dataType = dtc.getDataType();
				buffer.append(pad + dataType.getDisplayName() + "[0]");
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
	}

	private static String getTypeName(Composite composite) {
		if (composite instanceof Structure) {
			return "Structure";
		}
		else if (composite instanceof Union) {
			return "Union";
		}
		return "";
	}

	public static String getAlignmentAndPackingString(Composite composite) {
		StringBuilder buf =
			new StringBuilder(getMinAlignmentString(composite));
		if (buf.length() != 0) {
			buf.append(" ");
		}
		buf.append(getPackingString(composite));
		return buf.toString();
	}

	public static String getMinAlignmentString(Composite composite) {
		if (composite.isDefaultAligned()) {
			return "";
		}
		StringBuilder buf = new StringBuilder(ALIGN_NAME);
		buf.append("(");
		if (composite.isMachineAligned()) {
			buf.append("machine:");
			buf.append(composite.getDataOrganization().getMachineAlignment());
		}
		else {
			buf.append(composite.getExplicitMinimumAlignment());
		}
		buf.append(")");
		return buf.toString();
	}

	public static String getPackingString(Composite composite) {
		StringBuilder buf = new StringBuilder(PACKING_NAME);
		buf.append("(");
		if (composite.isPackingEnabled()) {
			if (composite.hasExplicitPackingValue()) {
				buf.append(composite.getExplicitPackingValue());
			}
			else {
				buf.append(DEFAULT_PACKING_NAME);
			}
		}
		else {
			buf.append(DISABLED_PACKING_NAME); // NO_PACKING
		}
		buf.append(")");
		return buf.toString();
	}

}
