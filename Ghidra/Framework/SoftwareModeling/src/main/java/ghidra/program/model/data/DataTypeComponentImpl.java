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

import java.io.Serializable;

import org.apache.commons.lang3.StringUtils;

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsImpl;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.DuplicateNameException;

/**
 * Basic implementation of a DataTypeComponent
 */
public class DataTypeComponentImpl implements InternalDataTypeComponent, Serializable {
	private final static long serialVersionUID = 1;

	private DataType dataType;
	private CompositeDataTypeImpl parent; // parent prototype containing us
	private int offset; // offset in parent
	private int ordinal; // position in parent
	private SettingsImpl defaultSettings;

	private String fieldName; // name of this prototype in the component
	private String comment; // comment about this component.
	private int length; // my length

	/**
	 * Create a new DataTypeComponent
	 * @param dataType the dataType for this component
	 * @param parent the dataType that this component belongs to
	 * @param length the length of the dataType in this component.
	 * @param ordinal the index within its parent.
	 * @param offset the byte offset within the parent
	 * @param fieldName the name associated with this component
	 * @param comment the comment associated with this component
	 */
	public DataTypeComponentImpl(DataType dataType, CompositeDataTypeImpl parent, int length,
			int ordinal, int offset, String fieldName, String comment) {

		this.parent = parent;
		this.ordinal = ordinal;
		this.offset = offset;
		this.length = length;
		this.fieldName = fieldName;
		setDataType(dataType);
		setComment(comment);
	}

	/**
	 * Create a new DataTypeComponent
	 * @param dataType the dataType for this component
	 * @param parent the dataType that this component belongs to
	 * @param length the length of the dataType in this component.
	 * @param ordinal the index of this component within its parent.
	 * @param offset the byte offset within the parent
	 */
	public DataTypeComponentImpl(DataType dataType, CompositeDataTypeImpl parent, int length,
			int ordinal, int offset) {
		this(dataType, parent, length, ordinal, offset, null, null);
	}

	@Override
	public boolean isBitFieldComponent() {
		return dataType instanceof BitFieldDataType;
	}

	@Override
	public boolean isZeroBitFieldComponent() {
		if (isBitFieldComponent()) {
			BitFieldDataType bitField = (BitFieldDataType) getDataType();
			return bitField.getBitSize() == 0;
		}
		return false;
	}

	@Override
	public int getOffset() {
		return offset;
	}

	boolean containsOffset(int off) {
		if (off == offset) { // separate check required to handle zero-length case
			return true;
		}
		return off > offset && off < (offset + length);
	}

	@Override
	public int getEndOffset() {
		if (length == 0) { // separate check required to handle zero-length case
			return offset;
		}
		return offset + length - 1;
	}

	@Override
	public String getComment() {
		return comment;
	}

	@Override
	public void setComment(String comment) {
		this.comment = StringUtils.isBlank(comment) ? null : comment;
	}

	@Override
	public String getFieldName() {
		if (isZeroBitFieldComponent()) {
			return null;
		}
		return fieldName;
	}

	@Override
	public void setFieldName(String name) throws DuplicateNameException {
		this.fieldName = checkFieldName(name);
	}

	private void checkDuplicateName(String name) throws DuplicateNameException {
		checkDefaultFieldName(name);
		if (parent == null) {
			return; // Bad situation
		}
		for (DataTypeComponent comp : parent.getDefinedComponents()) {
			if (comp != this && name.equals(comp.getFieldName())) {
				throw new DuplicateNameException("Duplicate field name: " + name);
			}
		}
	}

	private String checkFieldName(String name) throws DuplicateNameException {
		if (name != null) {
			name = name.trim();
			if (name.length() == 0 || name.equals(getDefaultFieldName())) {
				name = null;
			}
			else {
				checkDuplicateName(name);
			}
		}
		return name;
	}

	public static void checkDefaultFieldName(String fieldName) throws DuplicateNameException {
		if (fieldName.startsWith(DataTypeComponent.DEFAULT_FIELD_NAME_PREFIX)) {
			String subname =
				fieldName.substring(DataTypeComponent.DEFAULT_FIELD_NAME_PREFIX.length());
			int base = 10;
			if (subname.length() > 3 && subname.startsWith("_0x")) {
				subname = subname.substring(3);
				base = 16;
			}
			if (subname.length() != 0) {
				try {
					Integer.parseInt(subname, base);
					throw new DuplicateNameException("Reserved field name: " + fieldName);
				}
				catch (NumberFormatException e) {
					// ignore
				}
			}
		}
	}

	@Override
	public DataType getDataType() {
		return dataType;
	}

	@Override
	public DataType getParent() {
		return parent;
	}

	/**
	 * Perform special-case component update that does not result in size or alignment changes. 
	 * @param name new component name
	 * @param dt new resolved datatype
	 * @param cmt new comment
	 */
	void update(String name, DataType dt, String cmt) {
		// TODO: Need to check field name and throw DuplicateNameException
		// this.fieldName =  = checkFieldName(name);
		this.fieldName = name;
		this.dataType = dt;
		this.comment = StringUtils.isBlank(cmt) ? null : cmt;
	}

	@Override
	public void update(int ordinal, int offset, int length) {
		this.ordinal = ordinal;
		this.offset = offset;
		this.length = length;
	}

	/**
	 * Set the byte offset of where this component begins in its immediate parent
	 * data type.
	 * @param offset the offset
	 */
	void setOffset(int offset) {
		this.offset = offset;
	}

	@Override
	public int getLength() {
		return length;
	}

	void setLength(int length) {
		this.length = length;
	}

	@Override
	public int getOrdinal() {
		return ordinal;
	}

	/**
	 * Set the component ordinal of this component within its parent
	 * data type.
	 * @param ordinal component ordinal
	 */
	void setOrdinal(int ordinal) {
		this.ordinal = ordinal;
	}

	@Override
	public Settings getDefaultSettings() {
		if (defaultSettings == null) {
			DataTypeManager dataMgr = parent.getDataTypeManager();
			boolean immutableSettings =
				dataMgr == null || !dataMgr.allowsDefaultComponentSettings();
			defaultSettings = new SettingsImpl(immutableSettings);
			defaultSettings.setDefaultSettings(getDataType().getDefaultSettings());
		}
		return defaultSettings;
	}

	void invalidateSettings() {
		defaultSettings = null;
	}

	@Override
	public int hashCode() {
		// It is not expected that these objects ever be put in a hash map
		return super.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof DataTypeComponent)) {
			return false;
		}
		DataTypeComponent dtc = (DataTypeComponent) obj;
		DataType myDt = getDataType();
		DataType otherDt = dtc.getDataType();

		if (offset != dtc.getOffset() || getLength() != dtc.getLength() ||
			ordinal != dtc.getOrdinal() ||
			!SystemUtilities.isEqual(getFieldName(), dtc.getFieldName()) ||
			!SystemUtilities.isEqual(getComment(), dtc.getComment())) {
			return false;
		}
		if (!(myDt instanceof Pointer)) {
			String myRelPath = myDt.getPathName();
			String otherRelPath = otherDt.getPathName();
			if (!myRelPath.equals(otherRelPath)) {
				return false;
			}
		}

		if (myDt instanceof Structure) {
			return otherDt instanceof Structure;
		}
		else if (myDt instanceof Union) {
			return otherDt instanceof Union;
		}
		else if (myDt instanceof Array) {
			return otherDt instanceof Array;
		}
		else if (myDt instanceof Pointer) {
			return otherDt instanceof Pointer;
		}
		else if (myDt instanceof TypeDef) {
			return otherDt instanceof TypeDef;
		}
		return myDt.getClass() == otherDt.getClass();

	}

	@Override
	public boolean isEquivalent(DataTypeComponent dtc) {
		DataType myDt = getDataType();
		DataType otherDt = dtc.getDataType();
		DataType myParent = getParent();
		boolean aligned =
			(myParent instanceof Composite) ? ((Composite) myParent).isPackingEnabled() : false;
		// Components don't need to have matching offset when they are aligned
		if ((!aligned && (offset != dtc.getOffset())) ||
			!SystemUtilities.isEqual(getFieldName(), dtc.getFieldName()) ||
			!SystemUtilities.isEqual(getComment(), dtc.getComment())) {
			return false;
		}

		// Component lengths need only be checked for dynamic types
		if (getLength() != dtc.getLength() && (myDt instanceof Dynamic)) {
			return false;
		}

		return DataTypeUtilities.isSameOrEquivalentDataType(myDt, otherDt);
	}

	@Override
	public void setDataType(DataType dt) {
		// intended for internal use only - note exsiting settings should be preserved
		dataType = dt;
	}

	/**
	 * Determine if component is an undefined filler component
	 * @return true if undefined filler component, else false
	 */
	boolean isUndefined() {
		return dataType == DataType.DEFAULT;
	}

	@Override
	public String toString() {
		return InternalDataTypeComponent.toString(this);
	}

	/**
	 * Get the preferred length for a new component. The length returned will be no
	 * larger than the specified length.
	 * 
	 * @param dataType new component datatype
	 * @param length   constrained length or -1 to force use of dataType size.
	 *                 Dynamic types such as string must have a positive length
	 *                 specified.
	 * @return preferred component length
	 */
	public static int getPreferredComponentLength(DataType dataType, int length) {
		if (DataTypeComponent.usesZeroLengthComponent(dataType)) {
			return 0;
		}
		int dtLength = dataType.getAlignedLength();
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

}
