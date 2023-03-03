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
import ghidra.util.exception.DuplicateNameException;

/**
 * Database implementation for a Typedef data type.
 *
 *
 */
class TypedefDB extends DataTypeDB implements TypeDef {

	private TypedefDBAdapter adapter;
	private SettingsDefinition[] settingsDef;

	/**
	 * Construct TypeDefDB instance
	 * @param dataMgr datatype manager
	 * @param cache DataTypeDB cache
	 * @param adapter TypeDef record adapter
	 * @param record TypeDefDB record
	 */
	public TypedefDB(DataTypeManagerDB dataMgr, DBObjectCache<DataTypeDB> cache,
			TypedefDBAdapter adapter, DBRecord record) {
		super(dataMgr, cache, record);
		this.adapter = adapter;
		this.defaultSettings = null; // ensure lazy initialization
	}

	private void setFlags(int flags) {
		record.setShortValue(TypedefDBAdapter.TYPEDEF_FLAGS_COL, (short) flags);
	}

	private int getFlags() {
		return record.getShortValue(TypedefDBAdapter.TYPEDEF_FLAGS_COL);
	}

	@Override
	public void enableAutoNaming() {
		if (isAutoNamed()) {
			return;
		}
		lock.acquire();
		try {
			checkDeleted();

			String oldName = getName();

			setFlags(getFlags() | TypedefDBAdapter.TYPEDEF_FLAG_AUTONAME);
			adapter.updateRecord(record, true);

			// auto-named typedef follows category of associated datatype 
			CategoryPath oldPath = getCategoryPath();
			CategoryPath currentPath = getDataType().getCategoryPath();

			String newName = generateTypedefName(currentPath);
			record.setString(TypedefDBAdapter.TYPEDEF_NAME_COL, newName);
			adapter.updateRecord(record, true);
			refreshName();

			if (!currentPath.equals(oldPath)) {
				// update category for typedef
				try {
					super.setCategoryPath(currentPath);
				}
				catch (DuplicateNameException e) {
					// should not happen
				}
			}

			notifyNameChanged(oldName);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean isAutoNamed() {
		int flags = getFlags();
		if (isInvalid()) {
			lock.acquire();
			try {
				checkIsValid();
				flags = getFlags();
			}
			finally {
				lock.release();
			}
		}
		return (flags & TypedefDBAdapter.TYPEDEF_FLAG_AUTONAME) != 0;
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
		setFlags(getFlags() & ~TypedefDBAdapter.TYPEDEF_FLAG_AUTONAME); // clear auto-name flag if name is set
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
	public int getAlignedLength() {
		return getDataType().getAlignedLength();
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
		return getDataType().getRepresentation(buf, settings, length);
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
	public TypeDef clone(DataTypeManager dtm) {
		return TypedefDataType.clone(this, dtm);
	}

	@Override
	public TypedefDataType copy(DataTypeManager dtm) {
		return TypedefDataType.copy(this, dtm);
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
		validate(lock);

		boolean autoNamed = isAutoNamed();
		if (autoNamed != td.isAutoNamed()) {
			return false;
		}
		if (!autoNamed && !DataTypeUtilities.equalsIgnoreConflict(getName(), td.getName())) {
			return false;
		}
		if (!hasSameTypeDefSettings(td)) {
			return false;
		}
		return DataTypeUtilities.isSameOrEquivalentDataType(getDataType(), td.getDataType());
	}

	public void setCategoryPath(CategoryPath path) throws DuplicateNameException {
		if (isAutoNamed()) {
			return; // ignore category change if auto-naming enabled
		}
		super.setCategoryPath(path);
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
				settingsDef = null;
				defaultSettings = null;
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
		if (getDataType() == dt) {
			updateAutoName(true);
		}
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
				settingsDef = null;
				record = rec;
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
				SettingsDefinition[] settingsDefinitions = dt.getSettingsDefinitions();
				TypeDefSettingsDefinition[] typeDefSettingsDefinitions =
					dt.getTypeDefSettingsDefinitions();
				settingsDef = new SettingsDefinition[settingsDefinitions.length +
					typeDefSettingsDefinitions.length];
				System.arraycopy(settingsDefinitions, 0, settingsDef, 0,
					settingsDefinitions.length);
				System.arraycopy(typeDefSettingsDefinitions, 0, settingsDef,
					settingsDefinitions.length, typeDefSettingsDefinitions.length);
			}
			return settingsDef;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public TypeDefSettingsDefinition[] getTypeDefSettingsDefinitions() {
		return getDataType().getTypeDefSettingsDefinitions();
	}

	protected Settings doGetDefaultSettings() {
		DataTypeSettingsDB settings = new DataTypeSettingsDB(dataMgr, this, key);
		settings.setLock(dataMgr instanceof BuiltInDataTypeManager);
		settings.setAllowedSettingPredicate(n -> isAllowedSetting(n));
		settings.setDefaultSettings(getDataType().getDefaultSettings());
		return settings;
	}

	private boolean isAllowedSetting(String settingName) {
		if (dataMgr instanceof ProgramBasedDataTypeManager) {
			// any setting permitted within a program DTM
			return true;
		}
		// non-TypeDefSettingsDefinition settings are not permitted in non-program DTM
		// since they will be discarded during resolve and ignored for equivalence checks
		for (TypeDefSettingsDefinition def : getTypeDefSettingsDefinitions()) {
			if (def.getStorageKey().equals(settingName)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public String toString() {
		if (isAutoNamed()) {
			return getName();
		}
		return "typedef " + this.getName() + " " + getDataType().getName();
	}

	@Override
	public String getDefaultLabelPrefix() {
		if (isAutoNamed()) {
			return getDataType().getDefaultLabelPrefix();
		}
		return getName();
	}

	@Override
	public String getDefaultLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options) {
		if (isAutoNamed()) {
			return getDataType().getDefaultLabelPrefix(buf, settings, len, options);
		}
		return super.getDefaultLabelPrefix(buf, settings, len, options);
	}

	@Override
	public String getDefaultAbbreviatedLabelPrefix() {
		if (isAutoNamed()) {
			return getDataType().getDefaultAbbreviatedLabelPrefix();
		}
		return super.getDefaultAbbreviatedLabelPrefix();
	}

	@Override
	public String getDefaultOffcutLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options, int offcutLength) {
		if (isAutoNamed()) {
			return getDataType().getDefaultOffcutLabelPrefix(buf, settings, len, options,
				offcutLength);
		}
		return super.getDefaultOffcutLabelPrefix(buf, settings, len, options, offcutLength);
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
		if (dataType == this) {
			return;
		}
		lock.acquire();
		try {
			TypeDef td = (TypeDef) dataType;
			dataTypeReplaced(getDataType(), td.getDataType());
			TypedefDataType.copyTypeDefSettings(td, this, true);
			// NOTE: as with the name, auto-name setting is left unchanged
		}
		finally {
			lock.release();
		}
	}

	@Override
	protected void updatePath(DataTypeDB dt) {
		if (isAutoNamed() && dt == getDataType()) {
			// auto-named typedef follows category of associated datatype 
			CategoryPath oldPath = getCategoryPath();
			CategoryPath currentPath = dt.getCategoryPath();
			if (!currentPath.equals(oldPath)) {
				try {
					boolean nameChanged = false;
					String oldName = getName();
					String newName = generateTypedefName(currentPath);
					if (!newName.equals(oldName)) {
						nameChanged = true;
						record.setString(TypedefDBAdapter.TYPEDEF_NAME_COL, newName);
						refreshName();
					}
					super.setCategoryPath(currentPath);
					if (nameChanged) {
						notifyNameChanged(oldName);
					}
				}
				catch (DuplicateNameException e) {
					// should not happen
				}
			}
		}
	}

	private String generateTypedefName(CategoryPath path) {
		String newName = TypedefDataType.generateTypedefName(this);
		DataType dt = dataMgr.getDataType(path, newName);
		if (dt == null || dt == this) {
			return newName;
		}

		String baseName = newName + DataType.CONFLICT_SUFFIX;
		newName = baseName;
		int count = 0;
		while (true) {
			dt = dataMgr.getDataType(path, newName);
			if (dt == null || dt == this) {
				break;
			}
			count++;
			newName = baseName + count;
		}
		return newName;
	}

	boolean updateAutoName(boolean notify) {
		lock.acquire();
		try {
			checkIsValid();

			if (!isAutoNamed()) {
				return false;
			}

			String oldName = getName();
			String newName = generateTypedefName(getCategoryPath());
			if (oldName.equals(newName)) {
				return false;
			}

			record.setString(TypedefDBAdapter.TYPEDEF_NAME_COL, newName);
			adapter.updateRecord(record, false);
			refreshName();

			if (notify) {
				notifyNameChanged(oldName);
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
		return true;
	}

}
