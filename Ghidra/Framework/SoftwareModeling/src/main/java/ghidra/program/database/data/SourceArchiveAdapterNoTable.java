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

import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.SourceArchive;
import ghidra.util.UniversalID;
import ghidra.util.exception.VersionException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import db.DBHandle;
import db.DBRecord;

/**
 * Adapter needed for a read-only version of data type manager that is not going
 * to be upgraded, and there is no Data Type Archive ID table in the data type manager.
 */
class SourceArchiveAdapterNoTable extends SourceArchiveAdapter {
	private static DBRecord LOCAL_RECORD;
	static {

		LOCAL_RECORD = SCHEMA.createRecord(DataTypeManager.LOCAL_ARCHIVE_KEY);
		LOCAL_RECORD.setString(ARCHIVE_ID_DOMAIN_FILE_ID_COL, null);
		LOCAL_RECORD.setString(ARCHIVE_ID_NAME_COL, "");
		LOCAL_RECORD.setByteValue(ARCHIVE_ID_TYPE_COL, (byte) 0);
		LOCAL_RECORD.setLongValue(ARCHIVE_ID_LAST_SYNC_TIME_COL, System.currentTimeMillis());
		LOCAL_RECORD.setBooleanValue(ARCHIVE_ID_DIRTY_FLAG_COL, false);
	}

	/**
	 * Gets a pre-table version of the adapter for the data type archive ID database table.
	 * @param handle handle to the database which doesn't contain the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 */
	public SourceArchiveAdapterNoTable(DBHandle handle) {
	}

	@Override
	DBRecord createRecord(SourceArchive sourceArchive) throws IOException {
		throw new UnsupportedOperationException(
			"Not allowed to update version prior to existence of the Data Type Archive ID table.");
	}

	@Override
	protected void deleteTable(DBHandle handle) throws IOException {
	}

	@Override
	DBRecord getRecord(long key) throws IOException {
		if (key == DataTypeManager.LOCAL_ARCHIVE_KEY) {
			return LOCAL_RECORD;
		}
		return null;
	}

	@Override
	List<DBRecord> getRecords() {
		List<DBRecord> records = new ArrayList<DBRecord>();
		records.add(LOCAL_RECORD);
		return records;
	}

	@Override
	boolean removeRecord(long key) throws IOException {
		throw new UnsupportedOperationException("removeRecord not supported");
	}

	@Override
	void updateRecord(DBRecord record) throws IOException {
		throw new UnsupportedOperationException("updateRecord not supported");
	}

	@Override
	void deleteRecord(UniversalID sourceArchiveID) throws IOException {
		throw new UnsupportedOperationException("updateRecord not supported");
	}
}
