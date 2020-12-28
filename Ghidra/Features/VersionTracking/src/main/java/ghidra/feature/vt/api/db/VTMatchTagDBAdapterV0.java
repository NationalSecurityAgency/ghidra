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
package ghidra.feature.vt.api.db;

import static ghidra.feature.vt.api.db.VTMatchTagDBAdapter.ColumnDescription.TAG_NAME_COL;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;

import db.*;

/**
 * Initial adapter for the database table that holds tags for version tracking matches.
 */
public class VTMatchTagDBAdapterV0 extends VTMatchTagDBAdapter {

	private Table table;

	public VTMatchTagDBAdapterV0(DBHandle handle) throws IOException {
		table = handle.createTable(TABLE_NAME, TABLE_SCHEMA, new int[] {});
	}

	public VTMatchTagDBAdapterV0(DBHandle dbHandle, OpenMode openMode, TaskMonitor monitor)
			throws VersionException {
		table = dbHandle.getTable(TABLE_NAME);
		if (table == null) {
			throw new VersionException("Missing Table: " + TABLE_NAME);
		}
		else if (table.getSchema().getVersion() != 0) {
			throw new VersionException("Expected version 0 for table " + TABLE_NAME + " but got " +
				table.getSchema().getVersion());
		}
	}

	@Override
	public DBRecord insertRecord(String tagName) throws IOException {

		if (tagName == null) {
			throw new IllegalArgumentException(
				"Cannot insert a null name into the match tag table.");
		}

		if (tagName.trim().isEmpty()) {
			throw new IllegalArgumentException("Cannot create an empty string tag");
		}

		DBRecord record = TABLE_SCHEMA.createRecord(table.getKey());
		record.setString(TAG_NAME_COL.column(), tagName);

		table.putRecord(record);
		return record;
	}

	@Override
	DBRecord getRecord(long tagRecordKey) throws IOException {
		return table.getRecord(tagRecordKey);
	}

	@Override
	int getRecordCount() {
		return table.getRecordCount();
	}

	@Override
	public RecordIterator getRecords() throws IOException {
		return table.iterator();
	}

	@Override
	void updateRecord(DBRecord record) throws IOException {
		table.putRecord(record);
	}

	@Override
	boolean deleteRecord(long matchRecordKey) throws IOException {
		return table.deleteRecord(matchRecordKey);
	}
}
