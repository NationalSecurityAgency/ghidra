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

import static ghidra.feature.vt.api.db.VTMatchTableDBAdapter.ColumnDescription.*;
import ghidra.feature.vt.api.main.VTMatchInfo;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;

import db.*;

public class VTMatchTableDBAdapterV0 extends VTMatchTableDBAdapter {

	private Table table;
	private final DBHandle dbHandle;

	public VTMatchTableDBAdapterV0(DBHandle dbHandle, long tableID) throws IOException {
		this.dbHandle = dbHandle;
		table =
			dbHandle.createTable(TABLE_NAME + tableID, TABLE_SCHEMA,
				new int[] { ASSOCIATION_COL.column() });
	}

	public VTMatchTableDBAdapterV0(DBHandle dbHandle, long tableID, OpenMode openMode,
			TaskMonitor monitor) throws VersionException {
		this.dbHandle = dbHandle;
		table = dbHandle.getTable(TABLE_NAME + tableID);
		if (table == null) {
			throw new VersionException("Missing Table: " + TABLE_NAME);
		}
		else if (table.getSchema().getVersion() != 0) {
			throw new VersionException("Expected version 0 for table " + TABLE_NAME + " but got " +
				table.getSchema().getVersion());
		}
	}

	@Override
	public DBRecord insertMatchRecord(VTMatchInfo info, VTMatchSetDB matchSet,
			VTAssociationDB association, VTMatchTagDB tag) throws IOException {

		DBRecord record = TABLE_SCHEMA.createRecord(table.getKey());

		record.setLongValue(TAG_KEY_COL.column(), (tag == null) ? -1 : tag.getKey());
		record.setString(SIMILARITY_SCORE_COL.column(), info.getSimilarityScore().toStorageString());
		record.setString(CONFIDENCE_SCORE_COL.column(), info.getConfidenceScore().toStorageString());
		record.setLongValue(ASSOCIATION_COL.column(), association.getKey());
		record.setIntValue(SOURCE_LENGTH_COL.column(), info.getSourceLength());
		record.setIntValue(DESTINATION_LENGTH_COL.column(), info.getDestinationLength());

		table.putRecord(record);
		return record;
	}

	@Override
	DBRecord getMatchRecord(long matchRecordKey) throws IOException {
		return table.getRecord(matchRecordKey);
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

	@Override
	RecordIterator getRecords(long associationID) throws IOException {
		Field field = new LongField(associationID);
		return table.indexIterator(ASSOCIATION_COL.column(), field, field, true);
	}
}
