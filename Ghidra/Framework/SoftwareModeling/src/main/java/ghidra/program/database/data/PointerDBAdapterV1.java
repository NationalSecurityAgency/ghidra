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
 * Version 1 adapter for the Pointer table.
 */
class PointerDBAdapterV1 extends PointerDBAdapter {
	final static int VERSION = 1;

	static final int OLD_PTR_DT_ID_COL = 0;
	static final int OLD_PTR_CATEGORY_COL = 1;
	static final Schema V1_SCHEMA =
		new Schema(VERSION, "Pointer ID", new Field[] { LongField.INSTANCE, LongField.INSTANCE },
			new String[] { "Data Type ID", "Category ID" });

	private Table table;

	PointerDBAdapterV1(DBHandle handle) throws VersionException {

		table = handle.getTable(POINTER_TABLE_NAME);
		if (table == null) {
			throw new VersionException("Missing Table: " + POINTER_TABLE_NAME);
		}
		int versionNumber = table.getSchema().getVersion();
		if (versionNumber != VERSION) {
			throw new VersionException("Expected version " + VERSION + " for table " +
				POINTER_TABLE_NAME + " but got " + versionNumber);
		}

	}

	@Override
	DBRecord translateRecord(DBRecord oldRec) {
		if (oldRec == null) {
			return null;
		}
		DBRecord rec = PointerDBAdapter.SCHEMA.createRecord(oldRec.getKey());
		rec.setLongValue(PTR_DT_ID_COL, oldRec.getLongValue(OLD_PTR_DT_ID_COL));
		rec.setLongValue(PTR_CATEGORY_COL, oldRec.getLongValue(OLD_PTR_CATEGORY_COL));
		rec.setByteValue(PTR_LENGTH_COL, (byte) -1);
		return rec;
	}

	@Override
	DBRecord createRecord(long dataTypeID, long categoryID, int length) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	DBRecord getRecord(long pointerID) throws IOException {
		return translateRecord(table.getRecord(pointerID));
	}

	@Override
	RecordIterator getRecords() throws IOException {
		return new TranslatedRecordIterator(table.iterator());
	}

	@Override
	boolean removeRecord(long pointerID) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	void updateRecord(DBRecord record) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	Field[] getRecordIdsInCategory(long categoryID) throws IOException {
		return table.findRecords(new LongField(categoryID), OLD_PTR_CATEGORY_COL);
	}

	@Override
	void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(POINTER_TABLE_NAME);
	}

}
