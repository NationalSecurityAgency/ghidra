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
 * Version 0 implementation for the enumeration tables adapter.
 * 
 */
class EnumValueDBAdapterV0 extends EnumValueDBAdapter {
	static final int VERSION = 0;

	// Enum Value Columns
	static final int V0_ENUMVAL_NAME_COL = 0;
	static final int V0_ENUMVAL_VALUE_COL = 1;
	static final int V0_ENUMVAL_ID_COL = 2;

	static final Schema V0_ENUM_VALUE_SCHEMA = new Schema(0, "Enum Value ID",
		new Field[] { StringField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE },
		new String[] { "Name", "Value", "Enum ID" });

	private Table valueTable;

	/**
	 * Gets a version 0 adapter for the Enumeration Data Type Values database table.
	 * @param handle handle to the database containing the table.
	 * @param create true if this constructor should create the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 * @throws IOException if IO error occurs
	 */
	public EnumValueDBAdapterV0(DBHandle handle, boolean create)
			throws VersionException, IOException {

		if (create) {
			valueTable = handle.createTable(ENUM_VALUE_TABLE_NAME, V0_ENUM_VALUE_SCHEMA,
				new int[] { V0_ENUMVAL_ID_COL });
		}
		else {
			valueTable = handle.getTable(ENUM_VALUE_TABLE_NAME);
			if (valueTable == null) {
				throw new VersionException("Missing Table: " + ENUM_VALUE_TABLE_NAME);
			}
			int version = valueTable.getSchema().getVersion();
			if (version != VERSION) {
				String msg = "Expected version " + VERSION + " for table " + ENUM_VALUE_TABLE_NAME +
					" but got " + valueTable.getSchema().getVersion();
				if (version < VERSION) {
					throw new VersionException(msg, VersionException.OLDER_VERSION, true);
				}
				throw new VersionException(msg, VersionException.NEWER_VERSION, false);
			}
		}
	}

	@Override
	public void createRecord(long enumID, String name, long value) throws IOException {
		DBRecord record = V0_ENUM_VALUE_SCHEMA.createRecord(valueTable.getKey());
		record.setLongValue(V0_ENUMVAL_ID_COL, enumID);
		record.setString(V0_ENUMVAL_NAME_COL, name);
		record.setLongValue(V0_ENUMVAL_VALUE_COL, value);
		valueTable.putRecord(record);
	}

	@Override
	public DBRecord getRecord(long valueID) throws IOException {
		return valueTable.getRecord(valueID);
	}

	@Override
	public void removeRecord(long valueID) throws IOException {
		valueTable.deleteRecord(valueID);
	}

	@Override
	public void updateRecord(DBRecord record) throws IOException {
		valueTable.putRecord(record);
	}

	@Override
	public Field[] getValueIdsInEnum(long enumID) throws IOException {
		return valueTable.findRecords(new LongField(enumID), V0_ENUMVAL_ID_COL);
	}
}
