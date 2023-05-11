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

import org.apache.commons.lang3.StringUtils;

import db.DBRecord;
import ghidra.docking.settings.*;
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
	private Settings defaultSettings;

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

	private boolean hasSettings() {
		return record != null && dataMgr.allowsDefaultComponentSettings() &&
			getDataType().getSettingsDefinitions().length != 0;
	}

	@Override
	public Settings getDefaultSettings() {
		if (!hasSettings()) {
			return SettingsImpl.NO_SETTINGS;
		}
		if (defaultSettings == null) {
			defaultSettings = new ComponentDBSettings();
		}
		return defaultSettings;
	}

	@Override
	public void setComment(String comment) {
		if (record != null) {
			if (StringUtils.isBlank(comment)) {
				comment = null;
			}
			record.setString(ComponentDBAdapter.COMPONENT_COMMENT_COL, comment);
			updateRecord(true);
		}
	}

	@Override
	public String getFieldName() {
		if (record != null && !isZeroBitFieldComponent()) {
			return record.getString(ComponentDBAdapter.COMPONENT_FIELD_NAME_COL);
		}
		return null;
	}

	@Override
	public void setFieldName(String name) throws DuplicateNameException {
		if (record != null) {
			name = checkFieldName(name);
			record.setString(ComponentDBAdapter.COMPONENT_FIELD_NAME_COL, name);
			updateRecord(true);
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
		boolean isPacked =
			(myParent instanceof Composite) ? ((Composite) myParent).isPackingEnabled() : false;
		// Components don't need to have matching offset when structure has packing enabled
		if ((!isPacked && (offset != dtc.getOffset())) ||
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
			updateRecord(false);
		}
	}

	void setOffset(int newOffset, boolean updateRecord) {
		offset = newOffset;
		if (record != null) {
			record.setIntValue(ComponentDBAdapter.COMPONENT_OFFSET_COL, offset);
		}
		if (updateRecord) {
			updateRecord(false);
		}
	}

	void setOrdinal(int ordinal, boolean updateRecord) {
		this.ordinal = ordinal;
		if (record != null) {
			record.setIntValue(ComponentDBAdapter.COMPONENT_ORDINAL_COL, ordinal);
		}
		if (updateRecord) {
			updateRecord(false);
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
			updateRecord(false);
		}
	}

	/**
	 * Update component record and option update composite last modified time.
	 * @param setLastChangeTime if true update composite last modified time and
	 * invoke dataTypeChanged for composite, else update component record only.
	 */
	void updateRecord(boolean setLastChangeTime) {
		if (record != null) {
			try {
				adapter.updateRecord(record);
				if (setLastChangeTime) {
					long timeNow = System.currentTimeMillis();
					parent.setLastChangeTime(timeNow);
				}
			}
			catch (IOException e) {
				dataMgr.dbError(e);
			}
		}
	}

	DBRecord getRecord() {
		return record;
	}

	/**
	 * Perform special-case component update that does not result in size or alignment changes. 
	 * @param name new component name
	 * @param dt new resolved datatype
	 * @param comment new comment
	 */
	void update(String name, DataType dt, String comment) {
		if (record != null) {
			if (StringUtils.isBlank(comment)) {
				comment = null;
			}
			// TODO: Need to check field name and throw DuplicateNameException
			// name = checkFieldName(name);
			record.setString(ComponentDBAdapter.COMPONENT_FIELD_NAME_COL, name);
			record.setLongValue(ComponentDBAdapter.COMPONENT_DT_ID_COL,
				dataMgr.getResolvedID(dt));
			record.setString(ComponentDBAdapter.COMPONENT_COMMENT_COL, comment);
			updateRecord(false);
		}
	}

	@Override
	public void setDataType(DataType newDt) {
		// intended for internal use only - note exsiting settings should be preserved
		if (record != null) {
			record.setLongValue(ComponentDBAdapter.COMPONENT_DT_ID_COL,
				dataMgr.getResolvedID(newDt));
			updateRecord(false);
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

	private class ComponentDBSettings implements Settings {
		//
		// Settings
		//
		// NOTE: Since this is not a DatabaseObject there is the possibility that
		// a setting could be made on a stale component if a concurrent modification 
		// occurs.  Component objects must be discarded anytime the parent composite
		// is modified.
		//

		private void settingsChanged() {
			// NOTE: Merge currently only supports TypeDefDB default settings changes which correspond
			// to TypeDefSettingsDefinition established by the base datatype
			// and does not consider DataTypeComponent default settings changes or other setting types.
			dataMgr.dataTypeChanged(getParent(), false);
		}

		@Override
		public boolean isChangeAllowed(SettingsDefinition settingsDefinition) {
			if (settingsDefinition instanceof TypeDefSettingsDefinition) {
				return false;
			}
			for (SettingsDefinition def : getDataType().getSettingsDefinitions()) {
				if (def.equals(settingsDefinition)) {
					return true;
				}
			}
			return false;
		}

		@Override
		public Long getLong(String name) {
			SettingDB settingDB = dataMgr.getSetting(record.getKey(), name);
			if (settingDB != null) {
				return settingDB.getLongValue();
			}
			return getDataType().getDefaultSettings().getLong(name);
		}

		@Override
		public String getString(String name) {
			SettingDB settingDB = dataMgr.getSetting(record.getKey(), name);
			if (settingDB != null) {
				return settingDB.getStringValue();
			}
			return getDataType().getDefaultSettings().getString(name);
		}

		@Override
		public Object getValue(String name) {
			SettingDB settingDB = dataMgr.getSetting(record.getKey(), name);
			if (settingDB != null) {
				return settingDB.getValue();
			}
			return getDataType().getDefaultSettings().getValue(name);
		}

		@Override
		public void setLong(String name, long value) {
			if (dataMgr.updateSettingsRecord(record.getKey(), name, null, value)) {
				settingsChanged();
			}
		}

		@Override
		public void setString(String name, String value) {
			if (dataMgr.updateSettingsRecord(record.getKey(), name, value, -1)) {
				settingsChanged();
			}
		}

		@Override
		public void setValue(String name, Object value) {
			if (value instanceof Long) {
				setLong(name, ((Long) value).longValue());
			}
			else if (value instanceof String) {
				setString(name, (String) value);
			}
			else {
				throw new IllegalArgumentException("Value is not a known settings type: " + name);
			}
		}

		@Override
		public void clearSetting(String name) {
			if (dataMgr.clearSetting(record.getKey(), name)) {
				settingsChanged();
			}
		}

		@Override
		public void clearAllSettings() {
			if (dataMgr.clearAllSettings(record.getKey())) {
				settingsChanged();
			}
		}

		@Override
		public String[] getNames() {
			return dataMgr.getSettingsNames(record.getKey());
		}

		@Override
		public boolean isEmpty() {
			return getNames().length == 0;
		}

		@Override
		public Settings getDefaultSettings() {
			return getDataType().getDefaultSettings();
		}
	}
}
