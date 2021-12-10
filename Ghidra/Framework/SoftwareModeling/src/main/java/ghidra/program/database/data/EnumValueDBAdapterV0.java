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
 */
class EnumValueDBAdapterV0 extends EnumValueDBAdapter {
	static final int VERSION = 0;

//  Keep for reference
//	static final Schema SCHEMA = new Schema(0, "Enum Value ID",
//		new Field[] { StringField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE },
//		new String[] { "Name", "Value", "Enum ID" });

	private Table table;

	/**
	 * Gets a version 0 adapter for the Enumeration Data Type Values database table.
	 * @param handle handle to the database containing the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 */
	public EnumValueDBAdapterV0(DBHandle handle) throws VersionException {

		table = handle.getTable(ENUM_VALUE_TABLE_NAME);
		if (table == null) {
			throw new VersionException("Missing Table: " + ENUM_VALUE_TABLE_NAME);
		}

		int version = table.getSchema().getVersion();
		if (version != VERSION) {
			String msg = "Expected version " + VERSION + " for table " + ENUM_VALUE_TABLE_NAME +
				" but got " + table.getSchema().getVersion();
			throw new VersionException(msg, VersionException.NEWER_VERSION, false);
		}
	}

	@Override
	public void createRecord(long enumID, String name, long value, String comment)
			throws IOException {
		throw new UnsupportedOperationException("Cannot update Version 0");
	}

	@Override
	public DBRecord getRecord(long valueID) throws IOException {
		return translateRecord(table.getRecord(valueID));
	}

	@Override
	public void removeRecord(long valueID) throws IOException {
		throw new UnsupportedOperationException("Cannot remove Version 0");
	}

	@Override
	public void updateRecord(DBRecord record) throws IOException {
		throw new UnsupportedOperationException("Cannot update Version 0");
	}

	@Override
	public Field[] getValueIdsInEnum(long enumID) throws IOException {
		return table.findRecords(new LongField(enumID), ENUMVAL_ID_COL);
	}

	@Override
	public DBRecord translateRecord(DBRecord oldRec) {
		if (oldRec == null) {
			return null;
		}

		DBRecord record = EnumValueDBAdapter.ENUM_VALUE_SCHEMA.createRecord(oldRec.getKey());
		record.setLongValue(ENUMVAL_ID_COL, oldRec.getLongValue(ENUMVAL_ID_COL));
		record.setString(ENUMVAL_NAME_COL, oldRec.getString(ENUMVAL_NAME_COL));
		record.setLongValue(ENUMVAL_VALUE_COL, oldRec.getLongValue(ENUMVAL_VALUE_COL));
		record.setString(ENUMVAL_COMMENT_COL, null);
		return record;
	}

	@Override
	RecordIterator getRecords() throws IOException {
		return new TranslatedRecordIterator(table.iterator(), this);
	}
}
