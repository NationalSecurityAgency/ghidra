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

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsImpl;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.util.exception.DuplicateNameException;

/**
 * DataTypeComponents from dataTypes that can not be modified.
 */
public class ReadOnlyDataTypeComponent implements DataTypeComponent, Serializable {
	private final static long serialVersionUID = 1;

	private DataType dataType;
	private DynamicDataType parent; // parent prototype containing us
	private int offset; // offset in parent
	private int ordinal; // position in parent
	private Settings settings;

	private String fieldName; // name of this prototype in the component
	private String comment; // comment about this component.
	private int length; // my length

	/**
	 * Create a new DataTypeComponent
	 * @param dataType the dataType for this component
	 * @param parent the dataType that this component belongs to
	 * @param length the length of the dataType in this component.
	 * @param offset the byte offset within the parent
	 * @param ordinal the index of this component in the parent.
	 * @param fieldName the name associated with this component
	 * @param comment the comment associated with ths component
	 */
	public ReadOnlyDataTypeComponent(DataType dataType, DynamicDataType parent, int length,
			int ordinal, int offset, String fieldName, String comment) {

		this.dataType = dataType;
		this.parent = parent;
		this.ordinal = ordinal;
		this.offset = offset;
		this.length = length;
		this.fieldName = fieldName;
		this.comment = comment;
	}

	/**
	 * Create a new DataTypeComponent
	 * @param dataType the dataType for this component
	 * @param parent the dataType that this component belongs to
	 * @param length the length of the dataType in this component.
	 * @param ordinal the index of this component in the parent.
	 * @param offset the byte offset within the parent
	 */
	public ReadOnlyDataTypeComponent(DataType dataType, DynamicDataType parent, int length,
			int ordinal, int offset) {
		this(dataType, parent, length, ordinal, offset, null, null);
	}

	@Override
	public boolean isFlexibleArrayComponent() {
		return false; // Unsupported use
	}

	@Override
	public boolean isBitFieldComponent() {
		return dataType instanceof BitFieldDataType;
	}

	@Override
	public boolean isZeroBitFieldComponent() {
		if (dataType instanceof BitFieldDataType) {
			return ((BitFieldDataType) dataType).getBitSize() == 0;
		}
		return false;
	}

	/**
	 * @see ghidra.program.model.data.DataTypeComponent#getOffset()
	 */
	@Override
	public int getOffset() {
		return offset;
	}

	/**
	 * @see ghidra.program.model.data.DataTypeComponent#getEndOffset()
	 */
	@Override
	public int getEndOffset() {
		return offset + length - 1;
	}

	/**
	 * @see ghidra.program.model.data.DataTypeComponent#getComment()
	 */
	@Override
	public String getComment() {
		return comment;
	}

	/**
	 * @see ghidra.program.model.data.DataTypeComponent#setComment(java.lang.String)
	 */
	@Override
	public void setComment(String comment) {
	}

	/**
	 * @see ghidra.program.model.data.DataTypeComponent#getFieldName()
	 */
	@Override
	public String getFieldName() {
		if (fieldName == null) {
			fieldName = getDefaultFieldName();
		}
		return fieldName;
	}

	/**
	 * @see ghidra.program.model.data.DataTypeComponent#getDefaultFieldName()
	 */
	@Override
	public String getDefaultFieldName() {
		return "field_" + getOrdinal();
	}

	/**
	 * @see ghidra.program.model.data.DataTypeComponent#setFieldName(java.lang.String)
	 */
	@Override
	public void setFieldName(String fieldName) throws DuplicateNameException {
	}

	/**
	 * @see ghidra.program.model.data.DataTypeComponent#getDataType()
	 */
	@Override
	public DataType getDataType() {
		return dataType;
	}

	/**
	 * @see ghidra.program.model.data.DataTypeComponent#getParent()
	 */
	@Override
	public DataType getParent() {
		return parent;
	}

	/**
	 * Set the byte offset of where this component begins in its immediate parent
	 * data type.
	 * @param offset the offset
	 */
	void setOffset(int offset) {
		this.offset = offset;
	}

	/**
	 * @see ghidra.program.model.data.DataTypeComponent#getLength()
	 */
	@Override
	public int getLength() {
		return length;
	}

	void setLength(int length) {
		this.length = length;
	}

	/**
	 * @see ghidra.program.model.data.DataTypeComponent#getOrdinal()
	 */
	@Override
	public int getOrdinal() {
		return ordinal;
	}

	/**
	 * @param ordinal
	 */
	void setOrdinal(int ordinal) {
		this.ordinal = ordinal;
	}

	/**
	 * @see ghidra.program.model.data.DataTypeComponent#getDefaultSettings()
	 */
	@Override
	public Settings getDefaultSettings() {
		if (settings == null) {
			settings = new SettingsImpl();
		}
		return settings;
	}

	/**
	 * @see ghidra.program.model.data.DataTypeComponent#setDefaultSettings(ghidra.docking.settings.Settings)
	 */
	@Override
	public void setDefaultSettings(Settings settings) {
		this.settings = settings;
	}

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof DataTypeComponent)) {
			return false;
		}
		DataTypeComponent dtc = (DataTypeComponent) obj;

		if (offset != dtc.getOffset() || length != dtc.getLength() || ordinal != dtc.getOrdinal() ||
			!dataType.isEquivalent(dtc.getDataType())) {

			return false;
		}
		return isSameString(fieldName, dtc.getFieldName()) &&
			isSameString(comment, dtc.getComment());
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataTypeComponent#isEquivalent(ghidra.program.model.data.DataTypeComponent)
	 */
	@Override
	public boolean isEquivalent(DataTypeComponent dtc) {
		DataType myDt = getDataType();
		DataType otherDt = dtc.getDataType();
		int otherLength = dtc.getLength();
		DataType myParent = getParent();
		boolean aligned =
			(myParent instanceof Composite) ? ((Composite) myParent).isPackingEnabled() : false;
		// Components don't need to have matching offset when they are aligned, only matching ordinal.
		if ((!aligned && (offset != dtc.getOffset())) ||
			// Components don't need to have matching length when they are aligned. Is this correct?
			(!aligned && (length != otherLength)) || ordinal != dtc.getOrdinal() ||
			!isSameString(getFieldName(), dtc.getFieldName()) ||
			!isSameString(getComment(), dtc.getComment())) {

			return false;
		}
		// if they contain datatypes that have same ids, then we are essentially equivalent.
		return DataTypeUtilities.isSameOrEquivalentDataType(myDt, otherDt);
	}

	private boolean isSameString(String s1, String s2) {
		if (s1 == null) {
			return s2 == null;
		}
		return s1.equals(s2);
	}

}
