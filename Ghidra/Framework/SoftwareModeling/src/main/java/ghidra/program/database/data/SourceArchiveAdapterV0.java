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
import java.util.*;

import db.*;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.SourceArchive;
import ghidra.util.UniversalID;
import ghidra.util.exception.VersionException;

/**
 * Version 0 implementation for accessing the Data Type Archive ID database table. 
 */
class SourceArchiveAdapterV0 extends SourceArchiveAdapter {
	static final int VERSION = 0;
	static final int V0_ARCHIVE_ID_DOMAIN_FILE_ID_COL = 0;
	static final int V0_ARCHIVE_ID_NAME_COL = 1;
	static final int V0_ARCHIVE_ID_TYPE_COL = 2;
	static final int V0_ARCHIVE_ID_LAST_SYNC_TIME_COL = 3;
	static final int V0_ARCHIVE_ID_DIRTY_FLAG_COL = 4;

	static final Schema V0_SCHEMA = new Schema(VERSION, "Archive ID",
		new Field[] { StringField.INSTANCE, StringField.INSTANCE, ByteField.INSTANCE,
			LongField.INSTANCE, BooleanField.INSTANCE },
		new String[] { "Domain File ID", "Name", "Type", "Last Sync Time", "Dirty Flag" });

	private Table table;

	/**
	 * Gets a version 1 adapter for the Data Type Archive ID table.
	 * @param handle handle to the database containing the table.
	 * @param create true if this constructor should create the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 */
	public SourceArchiveAdapterV0(DBHandle handle, boolean create)
			throws VersionException, IOException {

		if (create) {
			table = handle.createTable(TABLE_NAME, V0_SCHEMA);

			createRecordForLocalManager();
		}
		else {
			table = handle.getTable(TABLE_NAME);
			if (table == null) {
				throw new VersionException(true);
			}
			int version = table.getSchema().getVersion();
			if (version != VERSION) {
				String msg = "Expected version " + VERSION + " for table " + TABLE_NAME +
					" but got " + table.getSchema().getVersion();
				if (version < VERSION) {
					throw new VersionException(msg, VersionException.OLDER_VERSION, true);
				}
				throw new VersionException(msg, VersionException.NEWER_VERSION, false);
			}
		}
	}

	/**
	 * 
	 * @throws IOException
	 */
	private void createRecordForLocalManager() throws IOException {
		DBRecord record = V0_SCHEMA.createRecord(DataTypeManager.LOCAL_ARCHIVE_KEY);
		record.setLongValue(V0_ARCHIVE_ID_LAST_SYNC_TIME_COL, (new Date()).getTime());
		table.putRecord(record);
	}

	@Override
	public DBRecord createRecord(SourceArchive archive) throws IOException {
		DBRecord record = V0_SCHEMA.createRecord(archive.getSourceArchiveID().getValue());
		record.setString(V0_ARCHIVE_ID_DOMAIN_FILE_ID_COL, archive.getDomainFileID());
		record.setString(V0_ARCHIVE_ID_NAME_COL, archive.getName());
		record.setByteValue(V0_ARCHIVE_ID_TYPE_COL, (byte) archive.getArchiveType().ordinal());
		// this should be the local archive record so the getLastSyncTime is really the lastChangeTime
		record.setLongValue(V0_ARCHIVE_ID_LAST_SYNC_TIME_COL, archive.getLastSyncTime()); // this should be the local archive record
		record.setBooleanValue(V0_ARCHIVE_ID_DIRTY_FLAG_COL, false);
		table.putRecord(record);
		return record;
	}

	@Override
	void deleteRecord(UniversalID sourceArchiveID) throws IOException {
		table.deleteRecord(sourceArchiveID.getValue());
	}

	@Override
	public DBRecord getRecord(long key) throws IOException {
		return table.getRecord(key);
	}

	@Override
	public List<DBRecord> getRecords() throws IOException {
		List<DBRecord> records = new ArrayList<>();
		RecordIterator iterator = table.iterator();
		while (iterator.hasNext()) {
			records.add(iterator.next());
		}
		return records;
	}

	@Override
	public void updateRecord(DBRecord record) throws IOException {
		table.putRecord(record);
	}

	@Override
	public boolean removeRecord(long dataTypeArchiveID) throws IOException {
		return table.deleteRecord(dataTypeArchiveID);
	}

	@Override
	protected void deleteTable(DBHandle handle) throws IOException {
	}

}
