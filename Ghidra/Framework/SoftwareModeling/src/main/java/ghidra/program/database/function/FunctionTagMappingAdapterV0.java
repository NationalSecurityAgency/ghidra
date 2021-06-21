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
package ghidra.program.database.function;

import java.io.IOException;

import db.*;
import ghidra.program.database.util.EmptyRecordIterator;
import ghidra.util.exception.VersionException;

/**
 * Initial version of the {@link FunctionTagMappingAdapter}. 
 * 
 */
class FunctionTagMappingAdapterV0 extends FunctionTagMappingAdapter implements DBListener {

	final static int SCHEMA_VERSION = 0;

	// The two columns for this table, one for the function ID, one for the
	// tag ID.
	public static final int V0_FUNCTION_ID_COL = 0;
	public static final int V0_TAG_ID_COL = 1;

	final static Schema SCHEMA =
		new Schema(CURRENT_VERSION, "ID", new Field[] { LongField.INSTANCE, LongField.INSTANCE },
			new String[] { "Function ID", "Tag ID" });

	private Table table; // lazy creation, null if empty
	private final DBHandle dbHandle;

	FunctionTagMappingAdapterV0(DBHandle dbHandle, boolean create) throws VersionException {

		this.dbHandle = dbHandle;

		// This deserves an explanation:
		//
		// Both function tag tables are transient, meaning they're created only when necessary,
		// and destroyed when possible. Because of this, the Table object maintained by this
		// class will at times be invalid and generate an exception if accessed. To protect
		// against this, we listen for db updates and refresh that Table object when the 
		// database is restored. 
		dbHandle.addListener(this);

		if (!create) {
			table = dbHandle.getTable(TABLE_NAME);
			if (table == null) {
				return; // lazy creation
			}
			int version = table.getSchema().getVersion();
			if (version != SCHEMA_VERSION) {
				throw new VersionException(VersionException.NEWER_VERSION, false);
			}
		}
	}

	/******************************************************************************
	 * PUBLIC METHODS
	 ******************************************************************************/

	@Override
	DBRecord getRecord(long functionID, long tagID) throws IOException {

		if (table == null) {
			return null;
		}

		// Use an index iterator so we only look at rows that contain the given function ID.
		LongField value = new LongField(functionID);
		RecordIterator iter = table.indexIterator(V0_FUNCTION_ID_COL, value, value, true);

		while (iter.hasNext()) {
			DBRecord rec = iter.next();
			if ((rec.getLongValue(V0_FUNCTION_ID_COL) == functionID) &&
				(rec.getLongValue(V0_TAG_ID_COL) == tagID)) {
				return rec;
			}
		}

		return null;
	}

	@Override
	DBRecord createFunctionTagRecord(long functionID, long tagID) throws IOException {

		Table t = getTable();
		DBRecord rec = SCHEMA.createRecord(t.getKey());
		rec.setLongValue(V0_FUNCTION_ID_COL, functionID);
		rec.setLongValue(V0_TAG_ID_COL, tagID);
		t.putRecord(rec);

		return rec;
	}

	@Override
	boolean removeFunctionTagRecord(long functionID, long tagID) throws IOException {

		DBRecord record = getRecord(functionID, tagID);
		if (record != null) {
			return table.deleteRecord(record.getKey());
		}

		return false;
	}

	@Override
	void removeFunctionTagRecord(long tagID) throws IOException {

		if (table == null) {
			return;
		}

		// Tag ID is not an indexed column in the mapping table, so we just have to iterate
		// over all records. This operation is only done when deleting a tag (ie: not often)
		// so it won't be indexed.
		RecordIterator iter = table.iterator();
		while (iter.hasNext()) {
			DBRecord rec = iter.next();
			Long tID = rec.getLongValue(V0_TAG_ID_COL);
			if (tID == tagID) {
				iter.delete();
			}
		}
	}

	@Override
	RecordIterator getRecordsByFunctionID(long functionID) throws IOException {
		if (table == null) {
			return new EmptyRecordIterator();
		}
		// Use an index iterator so we only look at rows that have the given functionID.
		LongField value = new LongField(functionID);
		return table.indexIterator(V0_FUNCTION_ID_COL, value, value, true);
	}

	@Override
	protected RecordIterator getRecords() throws IOException {
		if (table == null) {
			return new EmptyRecordIterator();
		}
		return table.iterator();
	}

	@Override
	boolean isTagAssigned(long tagID) throws IOException {
		if (table == null) {
			return false;
		}
		RecordIterator iter = table.iterator();
		while (iter.hasNext()) {
			DBRecord rec = iter.next();
			if ((rec.getLongValue(V0_TAG_ID_COL) == tagID)) {
				return true;
			}
		}
		return false;
	}

	private Table getTable() throws IOException {
		if (table == null) {
			table = dbHandle.createTable(TABLE_NAME, SCHEMA, new int[] { V0_FUNCTION_ID_COL });
		}
		return table;
	}

	@Override
	public void dbRestored(DBHandle dbh) {
		table = dbh.getTable(TABLE_NAME);
	}

	@Override
	public void dbClosed(DBHandle dbh) {
	}

	@Override
	public void tableDeleted(DBHandle dbh, Table table) {
	}

	@Override
	public void tableAdded(DBHandle dbh, Table table) {
		// do nothing
	}

}
