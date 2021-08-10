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
import ghidra.util.InvalidNameException;
import ghidra.util.UniversalID;
import ghidra.util.exception.DuplicateNameException;

/**
 * Database implementation of an Array data type.
 *
 *
 */
class ArrayDB extends DataTypeDB implements Array {

	private volatile String displayName;
	private ArrayDBAdapter adapter;

	/**
	 * Constructor
	 * @param dataMgr
	 * @param cache
	 * @param adapter
	 * @param record
	 */
	public ArrayDB(DataTypeManagerDB dataMgr, DBObjectCache<DataTypeDB> cache,
			ArrayDBAdapter adapter, DBRecord record) {
		super(dataMgr, cache, record);
		this.adapter = adapter;
	}

	@Override
	protected String doGetName() {
		return DataTypeUtilities.getName(this, true);
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return getArrayValueClass(settings);
	}

	@Override
	protected long doGetCategoryID() {
		return record.getLongValue(ArrayDBAdapter.ARRAY_CAT_COL);
	}

	@Override
	protected void refreshName() {
		super.refreshName();
		displayName = null;
	}

	@Override
	protected boolean refresh() {
		try {
			DBRecord rec = adapter.getRecord(key);
			if (rec != null) {
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
	public String getDisplayName() {
		String localDisplayName = displayName;
		if (localDisplayName != null && !isInvalid()) {
			return localDisplayName;
		}
		lock.acquire();
		try {
			checkIsValid();
			if ( displayName == null ) {
				displayName = DataTypeUtilities.getDisplayName(this, false);
			}
			return displayName;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public String getMnemonic(Settings settings) {
		return DataTypeUtilities.getMnemonic(this, false, settings);
	}

	@Override
	public boolean hasLanguageDependantLength() {
		return getDataType().hasLanguageDependantLength();
	}

	@Override
	public boolean isZeroLength() {
		return getNumElements() == 0;
	}

	@Override
	public int getLength() {
		validate(lock);
		if (getNumElements() == 0) {
			return 1; // 0-length datatype instance not supported
		}
		return getNumElements() * getElementLength();
	}

	@Override
	public String getDescription() {
		checkIsValid();
		return "Array of " + getDataType().getDescription();
	}

	@Override
	public DataType getDataType() {
		lock.acquire();
		try {
			checkIsValid();
			long dataTypeID = record.getLongValue(ArrayDBAdapter.ARRAY_DT_ID_COL);
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
	public SettingsDefinition[] getSettingsDefinitions() {
		return getDataType().getSettingsDefinitions();
	}

	@Override
	public int getElementLength() {
		DataType dt = getDataType();
		int elementLen;
		if (dt instanceof Dynamic) {
			elementLen = record.getIntValue(ArrayDBAdapter.ARRAY_ELEMENT_LENGTH_COL);
		}
		else {
			elementLen = dt.getLength();
		}
		return elementLen;
	}

	@Override
	public int getNumElements() {
		validate(lock);
		return record.getIntValue(ArrayDBAdapter.ARRAY_DIM_COL);
	}

	@Override
	public DataType copy(DataTypeManager dtm) {
		return new ArrayDataType(getDataType().clone(dtm), getNumElements(), getElementLength(),
			dtm);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new ArrayDataType(getDataType().clone(dtm), getNumElements(), getElementLength(),
			dtm);
	}

	@Override
	public DataTypeManager getDataTypeManager() {
		return dataMgr;
	}

	@Override
	public boolean isEquivalent(DataType dt) {
		if (dt == this) {
			return true;
		}
		if (!(dt instanceof Array)) {
			return false;
		}
		Array array = (Array) dt;
		if (getNumElements() != array.getNumElements()) {
			return false;
		}
		DataType dataType = getDataType();
		if (!dataType.isEquivalent(array.getDataType())) {
			return false;
		}
		if (dataType instanceof Dynamic && getElementLength() != array.getElementLength()) {
			return false;
		}
		return true;
	}

	@Override
	public void dataTypeReplaced(DataType oldDt, DataType newDt) {
		lock.acquire();
		try {
			checkIsValid();
			if (newDt == this || newDt.getLength() < 0) {
				newDt = DataType.DEFAULT;
			}

			if (oldDt == getDataType()) {

				oldDt.removeParent(this);
				newDt.addParent(this);

				String myOldName = getOldName();
				int oldLength = getLength();
				int oldAlignment = getAlignment();
				int oldElementLength = getElementLength();

				record.setLongValue(ArrayDBAdapter.ARRAY_DT_ID_COL, dataMgr.getResolvedID(newDt));
				if (newDt instanceof Dynamic || newDt instanceof FactoryDataType) {
					newDt = DataType.DEFAULT;
				}
				int elementLength = newDt.getLength() < 0 ? oldElementLength : -1;
				record.setIntValue(ArrayDBAdapter.ARRAY_ELEMENT_LENGTH_COL, elementLength);
				try {
					adapter.updateRecord(record);
				}
				catch (IOException e) {
					dataMgr.dbError(e);
				}
				refreshName();
				if (!getName().equals(myOldName)) {
					notifyNameChanged(myOldName);
				}
				if (getLength() != oldLength || oldElementLength != getElementLength()) {
					notifySizeChanged(false);
				}
				else if (getAlignment() != oldAlignment) {
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
	public void setName(String name) throws InvalidNameException, DuplicateNameException {
		// do nothing - can't change the name of an array
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

	/**
	 * @see ghidra.program.model.data.DataType#setCategoryPath(ghidra.program.model.data.CategoryPath)
	 *
	 * Note: this does get called, but in a tricky way.  If externally, someone calls
	 * setCategoryPath, nothing happens because it is overridden in this class to do nothing.
	 * However, if updatePath is called, then this method calls super.setCategoryPath which
	 * bypasses the overriddenness of setCategoryPath, resulting in this method getting called.
	 */
	@Override
	protected void doSetCategoryPathRecord(long categoryID) throws IOException {
		record.setLongValue(ArrayDBAdapter.ARRAY_CAT_COL, categoryID);
		adapter.updateRecord(record);
	}

	@Override
	protected void doSetNameRecord(String newName) throws InvalidNameException {
		throw new InvalidNameException("Can't set the name of an array!");
		// can't change the name of an array
	}

	@Override
	public void dataTypeDeleted(DataType dt) {
		if (getDataType() == dt) {
			dataMgr.addDataTypeToDelete(key);
		}
	}

	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
		lock.acquire();
		try {
			String myOldName = getOldName();
			if (checkIsValid() && dt == getDataType()) {
				refreshName();
				if (!getName().equals(myOldName)) {
					notifyNameChanged(myOldName);
				}
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	protected void updatePath(DataTypeDB dt) {
		if (dt == DataTypeUtilities.getBaseDataType(this)) {
			CategoryPath oldPath = getCategoryPath();
			CategoryPath currentPath = dt.getCategoryPath();
			if (!currentPath.equals(oldPath)) {
				try {
					super.setCategoryPath(currentPath);
				}
				catch (DuplicateNameException e) {
					// should not happen
				}
			}
		}
	}

	@Override
	public void setCategoryPath(CategoryPath path) throws DuplicateNameException {
		// not permitted to move - follows base type (see updatePath)
	}

	@Override
	public boolean dependsOn(DataType dt) {
		DataType myDt = getDataType();
		return (myDt == dt || myDt.dependsOn(dt));
	}

	@Override
	public String getDefaultLabelPrefix() {
		DataType dt = getDataType();
		if (dt == DataType.DEFAULT) {
			return ARRAY_LABEL_PREFIX;
		}
		return dt.getDefaultLabelPrefix() + "_" + ARRAY_LABEL_PREFIX;
	}

	@Override
	public String getDefaultLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options) {
		return getArrayDefaultLabelPrefix(buf, settings, len, options);
	}

	@Override
	public String getDefaultOffcutLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options, int offcutLength) {
		return getArrayDefaultOffcutLabelPrefix(buf, settings, len, options, offcutLength);
	}

	@Override
	public long getLastChangeTime() {
		return NO_LAST_CHANGE_TIME;
	}

	@Override
	public long getLastChangeTimeInSourceArchive() {
		return DataType.NO_SOURCE_SYNC_TIME;
	}

	@Override
	public void setLastChangeTime(long lastChangeTime) {
		// do nothing
	}

	@Override
	public void setLastChangeTimeInSourceArchive(long lastChangeTimeInSourceArchive) {
		// do nothing
	}

	@Override
	public UniversalID getUniversalID() {
		// For now, arrays and pointers don't have UniversalIDs
		return null;
	}

	@Override
	protected void setUniversalID(UniversalID id) {
		// do nothing
	}

	@Override
	protected UniversalID getSourceArchiveID() {
		return DataTypeManager.LOCAL_ARCHIVE_UNIVERSAL_ID;
	}

	@Override
	protected void setSourceArchiveID(UniversalID id) {
		// do nothing
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return getArrayValue(buf, settings, length);
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return getArrayRepresentation(buf, settings, length);
	}
}
