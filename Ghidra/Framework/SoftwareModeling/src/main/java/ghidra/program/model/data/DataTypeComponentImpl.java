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
	private Settings settings;

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
		this.comment = comment;
		setDataType(dataType);
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
		this.comment = comment;
	}

	@Override
	public String getFieldName() {
		if (isZeroBitFieldComponent()) {
			return "";
		}
		return fieldName;
	}

	@Override
	public void setFieldName(String name) throws DuplicateNameException {
		if (name != null) {
			name = name.trim();
			if (name.length() == 0 || name.equals(getDefaultFieldName())) {
				name = null;
			}
			else {
				if (name.equals(this.fieldName)) {
					return;
				}
				checkDuplicateName(name);
			}
		}
		this.fieldName = name;
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
	 * @param ordinal
	 */
	void setOrdinal(int ordinal) {
		this.ordinal = ordinal;
	}

	@Override
	public Settings getDefaultSettings() {
		if (settings == null) {
			settings = new SettingsImpl();
		}
		return settings;
	}

	@Override
	public void setDefaultSettings(Settings settings) {
		this.settings = settings;
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
		// intended for internal use only
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

}
