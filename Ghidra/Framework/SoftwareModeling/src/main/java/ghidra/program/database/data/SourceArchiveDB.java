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
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;
import ghidra.program.model.data.*;
import ghidra.util.Lock;
import ghidra.util.UniversalID;

public class SourceArchiveDB extends DatabaseObject implements SourceArchive {
	private UniversalID sourceID;
	private DBRecord record;
	private final SourceArchiveAdapter adapter;
	private final DataTypeManagerDB dtMgr;
	private Lock lock;

	public SourceArchiveDB(DataTypeManagerDB dtMgr, DBObjectCache<SourceArchiveDB> cache,
			SourceArchiveAdapter adapter, DBRecord record) {
		super(cache, record.getKey());
		this.dtMgr = dtMgr;
		this.adapter = adapter;
		this.record = record;
		sourceID = new UniversalID(record.getKey());
		this.lock = dtMgr.lock;

	}

	/**
	 * Gets the ID that the program has associated with the data type archive.
	 * @return the data type archive ID
	 */
	public UniversalID getSourceArchiveID() {
		if (isLocal()) {
			// if this sourceArchive represents the local archive (id == LOCAL_ARCHIVE_KEY)
			// the sourceArchiveID is this dataTypeManager's universal ID;
			UniversalID universalID = dtMgr.getUniversalID();
			// if the universalID == null, then this is from an non-upgraded archve, return the sourceID
			if (universalID != null) {
				return universalID;
			}
		}
		return sourceID;
	}

	private boolean isLocal() {
		return record.getKey() == DataTypeManager.LOCAL_ARCHIVE_KEY;
	}

	/**
	 * Gets the ID used to uniquely identify the domain file for the data type archive.
	 * @return the domain file identifier
	 */
	public String getDomainFileID() {
		if (isLocal()) {
			return dtMgr.getDomainFileID();
		}
		return record.getString(SourceArchiveAdapter.ARCHIVE_ID_DOMAIN_FILE_ID_COL);
	}

	/**
	 * Gets an indicator for the type of data type archive.
	 * (PROGRAM_TYPE, PROJECT_TYPE, FILE_TYPE)
	 * @return the type
	 */
	public ArchiveType getArchiveType() {
		if (isLocal()) {
			return dtMgr.getType();
		}
		byte byteValue = record.getByteValue(SourceArchiveAdapter.ARCHIVE_ID_TYPE_COL);
		return ArchiveType.values()[byteValue];
	}

	public String getName() {
		if (isLocal()) {
			return dtMgr.getName();
		}
		return record.getString(SourceArchiveAdapter.ARCHIVE_ID_NAME_COL);
	}

	@Override
	protected boolean refresh() {
		try {
			DBRecord rec = adapter.getRecord(key);
			if (rec != null) {
				record = rec;
				return true;
			}
		}
		catch (IOException e) {
			dtMgr.dbError(e);
		}
		return false;
	}

	public long getLastSyncTime() {
		return record.getLongValue(SourceArchiveAdapter.ARCHIVE_ID_LAST_SYNC_TIME_COL);
	}

	public boolean isDirty() {
		return record.getBooleanValue(SourceArchiveAdapter.ARCHIVE_ID_DIRTY_FLAG_COL);
	}

	public void setLastSyncTime(long syncTime) {
		lock.acquire();
		try {
			checkIsValid();
			record.setLongValue(SourceArchiveAdapter.ARCHIVE_ID_LAST_SYNC_TIME_COL, syncTime);
			adapter.updateRecord(record);
			dtMgr.sourceArchiveChanged(getSourceArchiveID());
		}
		catch (IOException e) {
			dtMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	public void setDirtyFlag(boolean isDirty) {
		lock.acquire();
		try {
			checkIsValid();
			record.setBooleanValue(SourceArchiveAdapter.ARCHIVE_ID_DIRTY_FLAG_COL, isDirty);
			adapter.updateRecord(record);
			dtMgr.sourceArchiveChanged(getSourceArchiveID());
		}
		catch (IOException e) {
			dtMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	public void setName(String newName) {
		if (getName().equals(newName)) {
			return;
		}
		lock.acquire();
		try {
			checkIsValid();
			record.setString(SourceArchiveAdapter.ARCHIVE_ID_NAME_COL, newName);
			adapter.updateRecord(record);
			dtMgr.sourceArchiveChanged(getSourceArchiveID());
		}
		catch (IOException e) {
			dtMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public String toString() {
		return getName();
	}
}
