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

import db.*;
import ghidra.util.exception.VersionException;

/**
 *
 */
class ArrayDBAdapterV0 extends ArrayDBAdapter {
	private static final String ARRAY_TABLE_NAME = "Arrays";
	private static final int V0_ARRAY_DT_ID_COL = 0;
	private static final int V0_ARRAY_DIM_COL = 1;
	private static final int V0_ARRAY_LENGTH_COL = 2;

	private Table table;

// DO NOT REMOVE - this documents the schema used in version 0.
//	public static final Schema SCHEMA = new Schema(0, "Array ID",
//									new Class[] {LongField.class, IntField.class,
//											 IntField.class},
//									new String[] {"Data Type ID", "Dimension",
//											"Length"});

	/**
	 * Constructor
	 * 
	 */
	public ArrayDBAdapterV0(DBHandle handle) throws VersionException {

		table = handle.getTable(ARRAY_TABLE_NAME);
		if (table == null) {
			throw new VersionException("Missing Table: " + ARRAY_TABLE_NAME);
		}
		else if (table.getSchema().getVersion() != 0) {
			throw new VersionException("Expected version 0 for table " + ARRAY_TABLE_NAME +
				" but got " + table.getSchema().getVersion());
		}

	}

	@Override
	public DBRecord createRecord(long dataTypeID, int numberOfElements, int length, long catID)
			throws IOException {
		return null;
	}

	@Override
	public DBRecord getRecord(long arrayID) throws IOException {
		return translateRecord(table.getRecord(arrayID));
	}

	@Override
	public RecordIterator getRecords() throws IOException {
		return new TranslatedRecordIterator(table.iterator());
	}

	@Override
	public boolean removeRecord(long dataID) throws IOException {
		return false;
	}

	@Override
	public void updateRecord(DBRecord record) throws IOException {
	}

	private DBRecord translateRecord(DBRecord oldRec) {
		if (oldRec == null) {
			return null;
		}
		DBRecord rec = ArrayDBAdapter.SCHEMA.createRecord(oldRec.getKey());
		rec.setLongValue(ArrayDBAdapter.ARRAY_DT_ID_COL, oldRec.getLongValue(V0_ARRAY_DT_ID_COL));
		rec.setIntValue(ArrayDBAdapter.ARRAY_DIM_COL, oldRec.getIntValue(V0_ARRAY_DIM_COL));
		rec.setIntValue(ArrayDBAdapter.ARRAY_LENGTH_COL, oldRec.getIntValue(V0_ARRAY_LENGTH_COL));
		rec.setLongValue(ArrayDBAdapter.ARRAY_CAT_COL, 0);
		return rec;
	}

	private class TranslatedRecordIterator implements RecordIterator {
		private RecordIterator it;

		TranslatedRecordIterator(RecordIterator it) {
			this.it = it;
		}

		@Override
		public boolean delete() throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean hasNext() throws IOException {
			return it.hasNext();
		}

		@Override
		public boolean hasPrevious() throws IOException {
			return it.hasPrevious();
		}

		@Override
		public DBRecord next() throws IOException {
			DBRecord rec = it.next();
			return translateRecord(rec);
		}

		@Override
		public DBRecord previous() throws IOException {
			DBRecord rec = it.previous();
			return translateRecord(rec);
		}
	}

	@Override
	void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(ARRAY_TABLE_NAME);
	}

	@Override
	Field[] getRecordIdsInCategory(long categoryID) throws IOException {
		return Field.EMPTY_ARRAY;
	}

}
