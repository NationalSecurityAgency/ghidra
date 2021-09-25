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
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.database.DBObjectCache;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.UniversalID;

/**
 * Database implementation for a Typedef data type.
 *
 *
 */
class TypedefDB extends DataTypeDB implements TypeDef {

	private TypedefDBAdapter adapter;
	private SettingsDefinition[] settingsDef;

	/**
	 * Constructor
	 * @param key
	 */
	public TypedefDB(DataTypeManagerDB dataMgr, DBObjectCache<DataTypeDB> cache,
			TypedefDBAdapter adapter, DBRecord record) {
		super(dataMgr, cache, record);
		this.adapter = adapter;
	}

	@Override
	protected long doGetCategoryID() {
		return record.getLongValue(TypedefDBAdapter.TYPEDEF_CAT_COL);
	}

	@Override
	protected String doGetName() {
		return record.getString(TypedefDBAdapter.TYPEDEF_NAME_COL);
	}

	@Override
	public boolean hasLanguageDependantLength() {
		return getDataType().hasLanguageDependantLength();
	}

	@Override
	protected void doSetNameRecord(String name) throws IOException {
		record.setString(TypedefDBAdapter.TYPEDEF_NAME_COL, name);
		adapter.updateRecord(record, true);
	}

	@Override
	public String getMnemonic(Settings settings) {
		return getDisplayName();
	}

	@Override
	public boolean isZeroLength() {
		return getDataType().isZeroLength();
	}

	@Override
	public int getLength() {
		return getDataType().getLength();
	}

	@Override
	public String getDescription() {
		return getDataType().getDescription();
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return getDataType().getValue(buf, settings, length);
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return getDataType().getValueClass(settings);
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		checkIsValid();
		TypedefSettings ts = new TypedefSettings(super.getDefaultSettings(), settings);
		return getDataType().getRepresentation(buf, ts, length);
	}

	@Override
	public void dataTypeSizeChanged(DataType dt) {
		lock.acquire();
		try {
			if (checkIsValid() && dt == getDataType()) {
				notifySizeChanged(true);
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void dataTypeAlignmentChanged(DataType dt) {
		lock.acquire();
		try {
			if (checkIsValid() && dt == getDataType()) {
				notifyAlignmentChanged(true);
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public DataType getBaseDataType() {
		lock.acquire();
		try {
			checkIsValid();
			DataType dataType = getDataType();
			if (dataType instanceof TypeDef) {
				return ((TypeDef) dataType).getBaseDataType();
			}
			return dataType;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public DataType getDataType() {
		lock.acquire();
		try {
			checkIsValid();
			long dataTypeID = record.getLongValue(TypedefDBAdapter.TYPEDEF_DT_ID_COL);
			DataType dt = dataMgr.getDataType(dataTypeID);
			if (dt == null) {
				dt = DataType.DEFAULT;
			}
			return dt;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		return new TypedefDataType(getCategoryPath(), getName(), getDataType(), getUniversalID(),
			getSourceArchive(), getLastChangeTime(), getLastChangeTimeInSourceArchive(), dtm);

	}

	@Override
	public DataType copy(DataTypeManager dtm) {
		return new TypedefDataType(getCategoryPath(), getName(), getDataType(), dtm);
	}

	@Override
	public boolean isEquivalent(DataType obj) {
		if (obj == this) {
			return true;
		}
		if (obj == null || !(obj instanceof TypeDef)) {
			return false;
		}
		TypeDef td = (TypeDef) obj;
		checkIsValid();
		if (!DataTypeUtilities.equalsIgnoreConflict(getName(), td.getName())) {
			return false;
		}
		return DataTypeUtilities.isSameOrEquivalentDataType(getDataType(), td.getDataType());
	}

	@Override
	protected void doSetCategoryPathRecord(long categoryID) throws IOException {
		record.setLongValue(TypedefDBAdapter.TYPEDEF_CAT_COL, categoryID);
		adapter.updateRecord(record, false);
	}

	@Override
	public void dataTypeReplaced(DataType oldDt, DataType newDt) {
		if (newDt == this || (newDt instanceof Dynamic) || (newDt instanceof FactoryDataType)) {
			newDt = DataType.DEFAULT;
		}
		lock.acquire();
		try {
			if (checkIsValid() && getDataType() == oldDt) {
				oldDt.removeParent(this);
				newDt = resolve(newDt);
				newDt.addParent(this);
				record.setLongValue(TypedefDBAdapter.TYPEDEF_DT_ID_COL,
					dataMgr.getResolvedID(newDt));
				try {
					adapter.updateRecord(record, true);
				}
				catch (IOException e) {
					dataMgr.dbError(e);
				}
				if (oldDt.getLength() != newDt.getLength()) {
					notifySizeChanged(false);
				}
				else if (oldDt.getAlignment() != newDt.getAlignment()) {
					notifyAlignmentChanged(false);
				}
				else {
					dataMgr.dataTypeChanged(this, false);
				}
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void dataTypeDeleted(DataType dt) {
		if (getDataType() == dt) {
			dataMgr.addDataTypeToDelete(key);
		}
	}

	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
	}

	@Override
	public boolean dependsOn(DataType dt) {
		DataType myDt = getDataType();
		return (myDt == dt || myDt.dependsOn(dt));
	}

	@Override
	protected boolean refresh() {
		try {
			DBRecord rec = adapter.getRecord(key);
			if (rec != null) {
				record = rec;
//				super.getDefaultSettings();  // not sure why it was doing this - no one else does.
				return super.refresh();
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		return false;
	}

	@Override
	public SettingsDefinition[] getSettingsDefinitions() {
		lock.acquire();
		try {
			checkIsValid();
			if (settingsDef == null) {
				DataType dt = getDataType();
				settingsDef = dt.getSettingsDefinitions();
			}
			return settingsDef;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public String toString() {
		return "typedef " + this.getName() + " " + getDataType().getName();
	}

	@Override
	public String getDefaultLabelPrefix() {
		return getName();
	}

	@Override
	public long getLastChangeTime() {
		return record.getLongValue(TypedefDBAdapter.TYPEDEF_LAST_CHANGE_TIME_COL);
	}

	@Override
	public long getLastChangeTimeInSourceArchive() {
		return record.getLongValue(TypedefDBAdapter.TYPEDEF_SOURCE_SYNC_TIME_COL);
	}

	@Override
	public UniversalID getUniversalID() {
		return new UniversalID(record.getLongValue(TypedefDBAdapter.TYPEDEF_UNIVERSAL_DT_ID_COL));
	}

	@Override
	protected void setUniversalID(UniversalID id) {
		lock.acquire();
		try {
			checkDeleted();
			record.setLongValue(TypedefDBAdapter.TYPEDEF_UNIVERSAL_DT_ID_COL, id.getValue());
			adapter.updateRecord(record, false);
			dataMgr.dataTypeChanged(this, false);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	protected UniversalID getSourceArchiveID() {
		return new UniversalID(record.getLongValue(TypedefDBAdapter.TYPEDEF_SOURCE_ARCHIVE_ID_COL));
	}

	@Override
	protected void setSourceArchiveID(UniversalID id) {
		lock.acquire();
		try {
			checkDeleted();
			record.setLongValue(TypedefDBAdapter.TYPEDEF_SOURCE_ARCHIVE_ID_COL, id.getValue());
			adapter.updateRecord(record, false);
			dataMgr.dataTypeChanged(this, false);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void setLastChangeTime(long lastChangeTime) {
		lock.acquire();
		try {
			checkDeleted();
			record.setLongValue(TypedefDBAdapter.TYPEDEF_LAST_CHANGE_TIME_COL, lastChangeTime);
			adapter.updateRecord(record, false);
			dataMgr.dataTypeChanged(this, false);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void setLastChangeTimeInSourceArchive(long lastChangeTimeInSourceArchive) {
		lock.acquire();
		try {
			checkDeleted();
			record.setLongValue(TypedefDBAdapter.TYPEDEF_SOURCE_SYNC_TIME_COL,
				lastChangeTimeInSourceArchive);
			adapter.updateRecord(record, false);
			dataMgr.dataTypeChanged(this, false);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void replaceWith(DataType dataType) {
		if (!(dataType instanceof TypeDef)) {
			throw new UnsupportedOperationException();
		}
		if (dataType != this) {
			dataTypeReplaced(getDataType(), ((TypeDef) dataType).getDataType());
		}
	}

}
