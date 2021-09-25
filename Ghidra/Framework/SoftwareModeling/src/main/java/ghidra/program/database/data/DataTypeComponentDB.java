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
package ghidra.program.database.data;

import java.io.IOException;

import db.DBRecord;
import ghidra.docking.settings.Settings;
import ghidra.program.model.data.*;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.DuplicateNameException;

/**
 * Database implementation for a DataTypeComponent. If this
 * component is for an undefined data type, then the record object is
 * null.
 */
class DataTypeComponentDB implements InternalDataTypeComponent {

	private final DataTypeManagerDB dataMgr;
	private final ComponentDBAdapter adapter;
	private final DBRecord record; // null record -> immutable component
	private final CompositeDB parent;

	private DataType cachedDataType; // required for bit-fields during packing process

	private int ordinal;
	private int offset;
	private int length;
	private SettingsDBManager defaultSettings;

	/**
	 * Construct an immutable component not backed by a record with a specified datatype and length.
	 * No comment or field name is provided.
	 * @param dataMgr
	 * @param parent
	 * @param ordinal
	 * @param offset
	 * @param datatype
	 * @param length
	 */
	DataTypeComponentDB(DataTypeManagerDB dataMgr, CompositeDB parent, int ordinal, int offset,
			DataType datatype, int length) {
		this(dataMgr, parent, ordinal, offset);
		this.cachedDataType = datatype;
		this.length = length;
	}

	/**
	 * Construct an immutable undefined 1-byte component not backed by a record.
	 * No comment or field name is provided.
	 * @param dataMgr
	 * @param parent
	 * @param ordinal
	 * @param offset
	 */
	DataTypeComponentDB(DataTypeManagerDB dataMgr, CompositeDB parent, int ordinal, int offset) {
		this.dataMgr = dataMgr;
		this.parent = parent;
		this.ordinal = ordinal;
		this.offset = offset;
		this.length = 1;
		this.record = null;
		this.adapter = null;
	}

	/**
	 * Construct a component backed by a record.
	 * @param dataMgr
	 * @param adapter
	 * @param parent
	 * @param record
	 */
	DataTypeComponentDB(DataTypeManagerDB dataMgr, ComponentDBAdapter adapter, CompositeDB parent,
			DBRecord record) {
		this.dataMgr = dataMgr;
		this.adapter = adapter;
		this.record = record;
		this.parent = parent;
		ordinal = record.getIntValue(ComponentDBAdapter.COMPONENT_ORDINAL_COL);
		offset = record.getIntValue(ComponentDBAdapter.COMPONENT_OFFSET_COL);
		length = record.getIntValue(ComponentDBAdapter.COMPONENT_SIZE_COL);
		if (isZeroBitFieldComponent()) {
			length = 0; // previously stored as 1, force to 0
		}
	}

	@Override
	public boolean isBitFieldComponent() {
		if (record == null) {
			return false;
		}
		long id = record.getLongValue(ComponentDBAdapter.COMPONENT_DT_ID_COL);
		return DataTypeManagerDB.getTableID(id) == DataTypeManagerDB.BITFIELD;
	}

	@Override
	public boolean isZeroBitFieldComponent() {
		if (isBitFieldComponent()) {
			BitFieldDataType bitField = (BitFieldDataType) getDataType();
			return bitField.getBitSize() == 0;
		}
		return false;
	}

	/**
	 * Get record key
	 * @return record key or -1 for undefined component without a record
	 */
	public long getKey() {
		return record != null ? record.getKey() : -1;
	}

	@Override
	public DataType getDataType() {
		if (cachedDataType != null) {
			return cachedDataType;
		}
		if (record == null) {
			return DataType.DEFAULT;
		}
		long id = record.getLongValue(ComponentDBAdapter.COMPONENT_DT_ID_COL);
		if (id == -1) {
			return DataType.DEFAULT;
		}
		return dataMgr.getDataType(id);
	}

	@Override
	public Composite getParent() {
		return parent;
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
	public int getOrdinal() {
		return ordinal;
	}

	@Override
	public int getEndOffset() {
		if (length == 0) { // separate check required to handle zero-length case
			return offset;
		}
		return offset + length - 1;
	}

	@Override
	public int getLength() {
		return length;
	}

	@Override
	public String getComment() {
		if (record != null) {
			return record.getString(ComponentDBAdapter.COMPONENT_COMMENT_COL);
		}
		return null;
	}

	@Override
	public Settings getDefaultSettings() {
		if (defaultSettings == null) {
			if (record != null) {
				defaultSettings = new SettingsDBManager(dataMgr, this, record.getKey());
			}
			else {
				return getDataType().getDefaultSettings();
			}
		}
		return defaultSettings;

	}

	@Override
	public void setDefaultSettings(Settings settings) {
		if (record != null) {
			if (defaultSettings == null) {
				defaultSettings = new SettingsDBManager(dataMgr, this, record.getKey());
			}
			defaultSettings.update(settings);
		}
	}

	@Override
	public void setComment(String comment) {
		try {
			if (record != null) {
				record.setString(ComponentDBAdapter.COMPONENT_COMMENT_COL, comment);
				adapter.updateRecord(record);
				dataMgr.dataTypeChanged(getParent(), false);
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
	}

	@Override
	public String getFieldName() {
		if (isZeroBitFieldComponent()) {
			return "";
		}
		if (record != null) {
			return record.getString(ComponentDBAdapter.COMPONENT_FIELD_NAME_COL);
		}
		return null;
	}

	@Override
	public void setFieldName(String name) throws DuplicateNameException {
		try {
			if (record != null) {
				if (name != null) {
					name = name.trim();
					if (name.length() == 0 || name.equals(getDefaultFieldName())) {
						name = null;
					}
					else {
						checkDuplicateName(name);
					}
				}
				record.setString(ComponentDBAdapter.COMPONENT_FIELD_NAME_COL, name);
				adapter.updateRecord(record);
				dataMgr.dataTypeChanged(getParent(), false);
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}

	}

	private void checkDuplicateName(String name) throws DuplicateNameException {
		DataTypeComponentImpl.checkDefaultFieldName(name);
		for (DataTypeComponent comp : parent.getDefinedComponents()) {
			if (comp == this) {
				continue;
			}
			if (name.equals(comp.getFieldName())) {
				throw new DuplicateNameException("Duplicate field name: " + name);
			}
		}
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
		if (!(myDt instanceof Pointer) && !myDt.getPathName().equals(otherDt.getPathName())) {
			return false;
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
		// SCR #11220 - this may fix the null pointer exception  - not sure as it is hard
		// to reproduce.
		if (myDt == null || otherDt == null) {
			return false;
		}
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
	public void update(int newOrdinal, int newOffset, int newLength) {
		if (length < 0) {
			throw new IllegalArgumentException(
				"Cannot set data type component length to " + length + ".");
		}

		ordinal = newOrdinal;
		offset = newOffset;
		length = newLength;

		if (record != null) {
			record.setIntValue(ComponentDBAdapter.COMPONENT_ORDINAL_COL, ordinal);
			record.setIntValue(ComponentDBAdapter.COMPONENT_OFFSET_COL, offset);
			record.setIntValue(ComponentDBAdapter.COMPONENT_SIZE_COL, length);
			updateRecord();
		}
	}

	void setOffset(int newOffset, boolean updateRecord) {
		offset = newOffset;
		if (record != null) {
			record.setIntValue(ComponentDBAdapter.COMPONENT_OFFSET_COL, offset);
		}
		if (updateRecord) {
			updateRecord();
		}
	}

	void setOrdinal(int ordinal, boolean updateRecord) {
		this.ordinal = ordinal;
		if (record != null) {
			record.setIntValue(ComponentDBAdapter.COMPONENT_ORDINAL_COL, ordinal);
		}
		if (updateRecord) {
			updateRecord();
		}
	}

	void setLength(int length, boolean updateRecord) {
		this.length = length;
		if (length < 0) {
			throw new IllegalArgumentException(
				"Cannot set data type component length to " + length + ".");
		}
		if (record != null) {
			record.setIntValue(ComponentDBAdapter.COMPONENT_SIZE_COL, length);
		}
		if (updateRecord) {
			updateRecord();
		}
	}

	void updateRecord() {
		if (record != null) {
			try {
				adapter.updateRecord(record);
			}
			catch (IOException e) {
				dataMgr.dbError(e);
			}
		}
	}

	DBRecord getRecord() {
		return record;
	}

	@Override
	public void setDataType(DataType newDt) {
		// intended for internal use only
		if (record != null) {
			record.setLongValue(ComponentDBAdapter.COMPONENT_DT_ID_COL,
				dataMgr.getResolvedID(newDt));
			updateRecord();
		}
	}

	@Override
	public String toString() {
		return InternalDataTypeComponent.toString(this);
	}

	/**
	 * Determine if component is an undefined filler component
	 * @return true if undefined filler component, else false
	 */
	boolean isUndefined() {
		return record == null && cachedDataType == null;
	}
}
