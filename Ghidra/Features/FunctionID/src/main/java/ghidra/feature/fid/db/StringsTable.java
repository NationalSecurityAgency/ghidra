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
package ghidra.feature.fid.db;

import java.io.IOException;

import db.*;
import ghidra.program.database.DBObjectCache;
import ghidra.util.UniversalIdGenerator;

/**
 * The table of strings in the FID database.  Due to the high rate of repetition of string
 * values in function and relation records, all strings are "interned" as iconic values
 * in this table, and the primary key is used instead of the value.  Since most strings
 * are much longer than 8 bytes, this leads to a substantial space savings.
 */
public class StringsTable {
	static final String STRINGS_TABLE = "Strings Table";

	static final int STRING_VALUE_COL = 0;

	static final int CACHE_SIZE = 10000;

	// @formatter:off
	static final Schema SCHEMA = new Schema(LibrariesTable.VERSION, "String ID", 
			new Field[] { StringField.INSTANCE }, 
			new String[] { "String Value" });
	// @formatter:on

	static int[] INDEXED_COLUMNS = new int[] { STRING_VALUE_COL };

	Table table;
	DBObjectCache<StringRecord> stringCache;

	/**
	 * Creates or attaches the string table.
	 * @param handle the database handle
	 * @param create whether to create or attach
	 * @throws IOException if the database has a problem
	 */
	public StringsTable(DBHandle handle) throws IOException {
		table = handle.getTable(STRINGS_TABLE);
		stringCache = new DBObjectCache<>(CACHE_SIZE);
	}

	public static void createTable(DBHandle handle) throws IOException {
		handle.createTable(STRINGS_TABLE, SCHEMA, INDEXED_COLUMNS);
	}

	/**
	 * Lookup existing ID or create new ID (if not present) for String value.
	 * @param value the string value
	 * @return the interned string primary key
	 * @throws IOException if the database has a problem
	 */
	long obtainStringID(String value) throws IOException {
		Field[] records = table.findRecords(new StringField(value), STRING_VALUE_COL);
		if (records == null || records.length == 0) {
			// create
			long key = UniversalIdGenerator.nextID().getValue();
			DBRecord record = SCHEMA.createRecord(key);
			record.setString(STRING_VALUE_COL, value);
			table.putRecord(record);
			return key;
		}
		return records[0].getLongValue();
	}

	/**
	 * Lookup existing ID or return null for String value.
	 * @param value the string value
	 * @return the existing interned string primary key as LongField, or null if nonexistent
	 * @throws IOException if the database has a problem
	 */
	Long lookupStringID(String value) throws IOException {
		Field[] records = table.findRecords(new StringField(value), STRING_VALUE_COL);
		if (records == null || records.length == 0) {
			return null;
		}
		return records[0].getLongValue();
	}

	/**
	 * Return existing String or null for long key stringID.
	 * @param stringID the interned string primary key
	 * @return the string record, or null if no such key
	 */
	StringRecord lookupString(long stringID) {
		StringRecord stringRecord = stringCache.get(stringID);
		if (stringRecord == null) {
			DBRecord record;
			try {
				record = table.getRecord(stringID);
				if (record != null) {
					stringRecord =
						new StringRecord(stringCache, stringID, record.getString(STRING_VALUE_COL));
				}
			}
			catch (IOException e) {
				throw new RuntimeException("serious delayed database access error", e);
			}
		}
		return stringRecord;
	}
}
