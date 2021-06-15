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
package ghidra.program.database.symbol;

import java.io.IOException;

import db.*;
import ghidra.util.exception.*;

/**
 * Implementation for Version 0 of the adapter that accesses the 
 * equate record that has the equate name and value.
 * 
 * 
 */
class EquateDBAdapterV0 extends EquateDBAdapter {

	private Table equateTable;

	/**
	 * Constructor
	 * @param handle the database handle.
	 * @param create if true, create the tables.
	 */
	EquateDBAdapterV0(DBHandle handle, boolean create) throws IOException, VersionException {
		if (create) {
			equateTable =
				handle.createTable(EQUATES_TABLE_NAME, EQUATES_SCHEMA, new int[] { NAME_COL });
		}
		else {
			equateTable = handle.getTable(EQUATES_TABLE_NAME);
			if (equateTable == null) {
				throw new VersionException("Missing Table: " + EQUATES_TABLE_NAME);
			}
			else if (equateTable.getSchema().getVersion() != 0) {
				throw new VersionException(VersionException.NEWER_VERSION, false);
			}
		}
	}

	/**
	 * @see ghidra.program.database.symbol.EquateDBAdapter#updateRecord(ghidra.framework.store.db.DBRecord)
	 */
	@Override
	void updateRecord(DBRecord record) throws IOException {
		equateTable.putRecord(record);
	}

	/**
	 * @see ghidra.program.database.symbol.EquateDBAdapter#removeRecord(long)
	 */
	@Override
	void removeRecord(long key) throws IOException {
		equateTable.deleteRecord(key);
	}

	/**
	 * @see ghidra.program.database.symbol.EquateDBAdapter#getRecord(java.lang.String)
	 */
	@Override
	long getRecordKey(String name) throws IOException, NotFoundException {
		Field[] keys = equateTable.findRecords(new StringField(name), NAME_COL);
		if (keys.length == 0) {
			throw new NotFoundException("Equate named " + name + " was not found");
		}
		if (keys.length > 1) {
			throw new AssertException(
				"Expected one record for " + name + " but found " + keys.length);
		}
		return keys[0].getLongValue();
	}

	@Override
	boolean hasRecord(String name) throws IOException {
		Field[] keys = equateTable.findRecords(new StringField(name), NAME_COL);
		return keys.length > 0;
	}

	/**
	 * @see ghidra.program.database.symbol.EquateDBAdapter#createEquate(java.lang.String, long)
	 */
	@Override
	DBRecord createEquate(String name, long value) throws IOException {
		DBRecord rec = equateTable.getSchema().createRecord(equateTable.getKey());
		rec.setString(NAME_COL, name);
		rec.setLongValue(VALUE_COL, value);
		equateTable.putRecord(rec);
		return rec;
	}

	/**
	 * @see ghidra.program.database.symbol.EquateDBAdapter#getRecord(long)
	 */
	@Override
	DBRecord getRecord(long key) throws IOException {
		return equateTable.getRecord(key);
	}

	/**
	 * @see ghidra.program.database.symbol.EquateDBAdapter#getRecords()
	 */
	@Override
	RecordIterator getRecords() throws IOException {
		return equateTable.iterator();
	}
}
