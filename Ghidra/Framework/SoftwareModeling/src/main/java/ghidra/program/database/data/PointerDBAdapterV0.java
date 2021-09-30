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
 * Version 0 implementation for the accessing the pointer database table.
 *
 */
class PointerDBAdapterV0 extends PointerDBAdapter {
	final static int VERSION = 0;

	static final int V0_PTR_DTD_COL_ = 0;
	static final int V0_PTR_SIZE_COL = 1;

//  Keep for reference
//	static final Schema SCHEMA = new Schema(VERSION, "Pointer ID",
//								new Class[] {LongField.class, IntField.class},
//								new String[] {"Data Type ID", "Size"});

	private Table table;

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

	@Override
	DBRecord createRecord(long dataTypeID, long categoryID, int length) throws IOException {
		throw new UnsupportedOperationException("Cannot update Version 0");
	}

	@Override
	DBRecord getRecord(long pointerID) throws IOException {
		return translateRecord(table.getRecord(pointerID));
	}

	@Override
	RecordIterator getRecords() throws IOException {
		return new TranslatedRecordIterator(table.iterator(), this);
	}

	@Override
	boolean removeRecord(long pointerID) throws IOException {
		throw new UnsupportedOperationException("Cannot update Version 0");
	}

	@Override
	void updateRecord(DBRecord record) throws IOException {
		throw new UnsupportedOperationException("Cannot update Version 0");
	}

	@Override
	Field[] getRecordIdsInCategory(long categoryID) throws IOException {
		return Field.EMPTY_ARRAY;
	}

	@Override
	public DBRecord translateRecord(DBRecord oldRec) {
		if (oldRec == null) {
			return null;
		}
		DBRecord rec = PointerDBAdapter.SCHEMA.createRecord(oldRec.getKey());
		rec.setLongValue(PTR_DT_ID_COL, oldRec.getLongValue(V0_PTR_DTD_COL_));
		rec.setLongValue(PTR_CATEGORY_COL, 0);
		rec.setByteValue(PTR_LENGTH_COL, (byte) -1);
		return rec;
	}

	@Override
	void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(POINTER_TABLE_NAME);

	}
}
