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
 * Version 0 implementation for the accessing the pointer database table.
 * 
 */
class PointerDBAdapterV0 extends PointerDBAdapter {
	final static int VERSION = 0;

	static final int OLD_PTR_DTD_COL = 0;
	static final int OLD_PTR_SIZE_COL = 1;

//	static final Schema SCHEMA = new Schema(VERSION, "Pointer ID",
//								new Class[] {LongField.class, IntField.class},
//								new String[] {"Data Type ID", "Size"});

	private Table table;

	/** 
	 * Constructor
	 * 
	 */
	PointerDBAdapterV0(DBHandle handle) throws VersionException {

		table = handle.getTable(POINTER_TABLE_NAME);
		if (table == null) {
			throw new VersionException("Missing Table: " + POINTER_TABLE_NAME);
		}
		else if (table.getSchema().getVersion() != 0) {
			throw new VersionException("Expected version 0 for table " + POINTER_TABLE_NAME +
				" but got " + table.getSchema().getVersion());
		}
	}

	/*
	 *  (non-Javadoc)
	 * @see ghidra.program.database.data.PointerDBAdapter#createRecord(long, long)
	 */
	@Override
	Record createRecord(long dataTypeID, long categoryID, int length) throws IOException {
		throw new UnsupportedOperationException("Cannot update Version 0");
	}

	/**
	 * @see ghidra.program.database.data.PointerDBAdapter#getRecord(long)
	 */
	@Override
	Record getRecord(long pointerID) throws IOException {
		return translateRecord(table.getRecord(pointerID));
	}

	/**
	 * @see ghidra.program.database.data.PointerDBAdapter#getRecords()
	 */
	@Override
	RecordIterator getRecords() throws IOException {
		return new TranslatedRecordIterator(table.iterator());
	}

	/**
	 * @see ghidra.program.database.data.PointerDBAdapter#removeRecord(long)
	 */
	@Override
	boolean removeRecord(long pointerID) throws IOException {
		throw new UnsupportedOperationException("Cannot update Version 0");
	}

	/**
	 * @see ghidra.program.database.data.PointerDBAdapter#updateRecord(ghidra.framework.store.db.Record)
	 */
	@Override
	void updateRecord(Record record) throws IOException {
		throw new UnsupportedOperationException("Cannot update Version 0");
	}

	/* (non-Javadoc)
	 * @see ghidra.program.database.data.PointerDBAdapter#getRecordIdsInCategory(long)
	 */
	@Override
	long[] getRecordIdsInCategory(long categoryID) throws IOException {
		return new long[0];
	}

	@Override
	Record translateRecord(Record oldRec) {
		if (oldRec == null) {
			return null;
		}
		Record rec = PointerDBAdapter.SCHEMA.createRecord(oldRec.getKey());
		rec.setLongValue(PTR_DT_ID_COL, oldRec.getLongValue(OLD_PTR_DTD_COL));
		rec.setLongValue(PTR_CATEGORY_COL, 0);
		return rec;
	}

	/**
	 * @see ghidra.program.database.data.PointerDBAdapter#deleteTable()
	 */
	@Override
	void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(POINTER_TABLE_NAME);

	}
}
