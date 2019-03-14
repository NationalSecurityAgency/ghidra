/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.util.exception.VersionException;

import java.io.IOException;

import db.*;

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

	/**
	 * @see ghidra.program.database.data.ArrayDBAdapter#createRecord(long, int)
	 */
	@Override
	public Record createRecord(long dataTypeID, int numberOfElements, int length, long catID)
			throws IOException {
		return null;
	}

	/**
	 * @see ghidra.program.database.data.ArrayDBAdapter#getRecord(long)
	 */
	@Override
	public Record getRecord(long arrayID) throws IOException {
		return translateRecord(table.getRecord(arrayID));
	}

	/**
	 * @see ghidra.program.database.data.ArrayDBAdapter#getRecords()
	 */
	@Override
	public RecordIterator getRecords() throws IOException {
		return new TranslatedRecordIterator(table.iterator());
	}

	/**
	 * @see ghidra.program.database.data.ArrayDBAdapter#removeRecord(long)
	 */
	@Override
	public boolean removeRecord(long dataID) throws IOException {
		return false;
	}

	/**
	 * @see ghidra.program.database.data.ArrayDBAdapter#updateRecord(ghidra.framework.store.db.Record)
	 */
	@Override
	public void updateRecord(Record record) throws IOException {
	}

	private Record translateRecord(Record oldRec) {
		if (oldRec == null) {
			return null;
		}
		Record rec = ArrayDBAdapter.SCHEMA.createRecord(oldRec.getKey());
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

		public boolean delete() throws IOException {
			throw new UnsupportedOperationException();
		}

		public boolean hasNext() throws IOException {
			return it.hasNext();
		}

		public boolean hasPrevious() throws IOException {
			return it.hasPrevious();
		}

		public Record next() throws IOException {
			Record rec = it.next();
			return translateRecord(rec);
		}

		public Record previous() throws IOException {
			Record rec = it.previous();
			return translateRecord(rec);
		}
	}

	/**
	 * @see ghidra.program.database.data.ArrayDBAdapter#deleteTable(ghidra.framework.store.db.DBHandle)
	 */
	@Override
	void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(ARRAY_TABLE_NAME);
	}

	/* (non-Javadoc)
	 * @see ghidra.program.database.data.ArrayDBAdapter#getRecordIdsInCategory(long)
	 */
	@Override
	long[] getRecordIdsInCategory(long categoryID) throws IOException {
		return new long[0];
	}

}
