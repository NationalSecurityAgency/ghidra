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
 * Version 1 implementation for the enumeration tables adapter.
 * 
 * NOTE: Use of tablePrefix introduced with this adapter version.
 */
class EnumValueDBAdapterV1 extends EnumValueDBAdapter {

	static final int VERSION = 1;

	static final Schema SCHEMA = new Schema(VERSION, "Enum Value ID",
		new Class[] { StringField.class, LongField.class, LongField.class, StringField.class },
		new String[] { "Name", "Value", "Enum ID", "Comment" });

	private Table table;

	/**
	 * Gets a version 1 adapter for the Enumeration Data Type Values database table.
	 * @param handle handle to the database containing the table.
	 * @param tablePrefix prefix to be used with default table name
	 * @param create true if this constructor should create the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 * @throws IOException if IO error occurs
	 */
	EnumValueDBAdapterV1(DBHandle handle, String tablePrefix, boolean create)
			throws VersionException, IOException {
		String tableName = tablePrefix + ENUM_VALUE_TABLE_NAME;
		if (create) {
			table = handle.createTable(tableName, SCHEMA, new int[] { ENUMVAL_ID_COL });
		}
		else {
			table = handle.getTable(tableName);
			if (table == null) {
				throw new VersionException(true);
			}
			int version = table.getSchema().getVersion();
			if (version != VERSION) {
				throw new VersionException(version < VERSION);
			}
		}
	}

	@Override
	void createRecord(long enumID, String name, long value, String comment)
			throws IOException {
		DBRecord record = SCHEMA.createRecord(table.getKey());
		record.setLongValue(ENUMVAL_ID_COL, enumID);
		record.setString(ENUMVAL_NAME_COL, name);
		record.setLongValue(ENUMVAL_VALUE_COL, value);
		record.setString(ENUMVAL_COMMENT_COL, comment);
		table.putRecord(record);
	}

	@Override
	DBRecord getRecord(long valueID) throws IOException {
		return table.getRecord(valueID);
	}

	@Override
	void removeRecord(long valueID) throws IOException {
		table.deleteRecord(valueID);
	}

	@Override
	void updateRecord(DBRecord record) throws IOException {
		table.putRecord(record);
	}

	@Override
	Field[] getValueIdsInEnum(long enumID) throws IOException {
		return table.findRecords(new LongField(enumID), ENUMVAL_ID_COL);
	}

	@Override
	RecordIterator getRecords() throws IOException {
		return table.iterator();
	}

	void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(table.getName());
	}

	@Override
	public DBRecord translateRecord(DBRecord r) {
		return r;
	}
}
