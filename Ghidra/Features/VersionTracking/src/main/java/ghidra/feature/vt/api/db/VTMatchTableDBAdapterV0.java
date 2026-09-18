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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import db.*;
import ghidra.feature.vt.api.main.VTMatchInfo;
import ghidra.feature.vt.api.main.VTScore;
import ghidra.framework.data.OpenMode;
import ghidra.util.exception.VersionException;

public class VTMatchTableDBAdapterV0 extends VTMatchTableDBAdapter {

	private Table table;

	public VTMatchTableDBAdapterV0(DBHandle dbHandle, long tableID) throws IOException {
		table = dbHandle.createTable(TABLE_NAME + tableID, TABLE_SCHEMA,
			new int[] { ASSOCIATION_COL.column() });
	}

	/**
	 * Opens an existing match table. If the table is schema v0 (pre-PDiff column),
	 * it is automatically upgraded to v1 by recreating the table with the new schema
	 * and copying all records. The new PDIFF_SIMILARITY_SCORE_COL is initialized to
	 * empty; actual scores are backfilled later by {@code VTSessionDB.backfillPdiffScores()}
	 * once source/destination programs are available.
	 *
	 * <p>Requires an active DB transaction (provided by VTSessionDB constructor).</p>
	 */
	public VTMatchTableDBAdapterV0(DBHandle dbHandle, long tableID, OpenMode openMode)
			throws VersionException {
		table = dbHandle.getTable(TABLE_NAME + tableID);
		if (table == null) {
			throw new VersionException("Missing Table: " + TABLE_NAME);
		}
		int version = table.getSchema().getVersion();
		if (version == 0) {
			// Auto-upgrade: v0 tables lack the PDIFF column — migrate to v1
			upgradeFromV0(dbHandle, tableID);
		}
		else if (version != 1) {
			throw new VersionException("Expected version 0 or 1 for table " + TABLE_NAME +
				" but got " + version);
		}
	}

	/**
	 * Upgrades a v0 match table to v1 by:
	 * 1. Reading all existing records into memory
	 * 2. Deleting the old v0 table
	 * 3. Creating a new v1 table (with PDIFF_SIMILARITY_SCORE_COL)
	 * 4. Re-inserting all records with the new column set to empty string
	 *
	 * <p>Column indices 0-7 are identical between v0 and v1, so field values
	 * are copied directly by column ordinal. The new column 8 (PDIFF) is set
	 * to empty, meaning "not yet computed".</p>
	 */
	private void upgradeFromV0(DBHandle dbHandle, long tableID) throws VersionException {
		try {
			// Step 1: Snapshot all existing v0 records before we destroy the table
			List<DBRecord> oldRecords = new ArrayList<>();
			RecordIterator iter = table.iterator();
			while (iter.hasNext()) {
				oldRecords.add(iter.next());
			}

			// Step 2: Delete old v0 table and recreate with v1 schema
			String tableName = TABLE_NAME + tableID;
			dbHandle.deleteTable(tableName);
			table = dbHandle.createTable(tableName, TABLE_SCHEMA,
				new int[] { ASSOCIATION_COL.column() });

			// Step 3: Copy each record into the new table, preserving keys and all
			// existing fields. The new PDIFF column is initialized to empty string.
			for (DBRecord oldRecord : oldRecords) {
				DBRecord newRecord = TABLE_SCHEMA.createRecord(oldRecord.getKey());
				newRecord.setLongValue(TAG_KEY_COL.column(),
					oldRecord.getLongValue(TAG_KEY_COL.column()));
				newRecord.setLongValue(MATCH_SET_COL.column(),
					oldRecord.getLongValue(MATCH_SET_COL.column()));
				newRecord.setString(SIMILARITY_SCORE_COL.column(),
					oldRecord.getString(SIMILARITY_SCORE_COL.column()));
				newRecord.setString(CONFIDENCE_SCORE_COL.column(),
					oldRecord.getString(CONFIDENCE_SCORE_COL.column()));
				newRecord.setString(LENGTH_TYPE.column(),
					oldRecord.getString(LENGTH_TYPE.column()));
				newRecord.setIntValue(SOURCE_LENGTH_COL.column(),
					oldRecord.getIntValue(SOURCE_LENGTH_COL.column()));
				newRecord.setIntValue(DESTINATION_LENGTH_COL.column(),
					oldRecord.getIntValue(DESTINATION_LENGTH_COL.column()));
				newRecord.setLongValue(ASSOCIATION_COL.column(),
					oldRecord.getLongValue(ASSOCIATION_COL.column()));
				newRecord.setString(PDIFF_SIMILARITY_SCORE_COL.column(), "");
				table.putRecord(newRecord);
			}
		}
		catch (IOException e) {
			throw new VersionException(
				"Failed to upgrade " + TABLE_NAME + tableID + ": " + e.getMessage());
		}
	}

	@Override
	public DBRecord insertMatchRecord(VTMatchInfo info, VTMatchSetDB matchSet,
			VTAssociationDB association, VTMatchTagDB tag) throws IOException {

		DBRecord record = TABLE_SCHEMA.createRecord(table.getKey());

		record.setLongValue(TAG_KEY_COL.column(), (tag == null) ? -1 : tag.getKey());
		record.setString(SIMILARITY_SCORE_COL.column(),
			info.getSimilarityScore().toStorageString());
		record.setString(CONFIDENCE_SCORE_COL.column(),
			info.getConfidenceScore().toStorageString());
		record.setLongValue(ASSOCIATION_COL.column(), association.getKey());
		record.setIntValue(SOURCE_LENGTH_COL.column(), info.getSourceLength());
		record.setIntValue(DESTINATION_LENGTH_COL.column(), info.getDestinationLength());

		// Write PDiff score: the combined mnemonic + stack-frame similarity computed in
		// VTMatchSetDB.addMatch(). Null for DATA matches or if computation was skipped.
		VTScore pdiffScore = info.getPdiffSimilarityScore();
		record.setString(PDIFF_SIMILARITY_SCORE_COL.column(),
			pdiffScore != null ? pdiffScore.toStorageString() : "");

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
