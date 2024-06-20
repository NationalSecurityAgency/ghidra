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
import ghidra.framework.data.OpenMode;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import ghidra.util.UniversalID;
import ghidra.util.UniversalIdGenerator;
import ghidra.util.exception.VersionException;

/**
 * Version 0 implementation for accessing the Address Model database table.
 */
class AddressModelDBAdapterV0 extends AddressModelDBAdapter {
	static final int VERSION = 0;
	static final int V0_ADDRESS_MODEL_DT_ID_COL = 0;
	static final int V0_ADDRESS_MODEL_ID_COL = 1;

	static final Schema V0_ADDRESS_MODEL_SCHEMA = new Schema(VERSION, "Address Model ID",
		new Field[] { LongField.INSTANCE, ByteField.INSTANCE },
		new String[] { "Data Type ID", "Return Type ID" }
	);

	private Table table;

	/**
	 * Gets a version 0 adapter for the Function Definition database table.
	 * @param handle handle to the database containing the table.
	 * @param openMode {@link OpenMode} value.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 * @throws IOException if unable to create database table.
	 */
	public AddressModelDBAdapterV0(DBHandle handle, OpenMode openMode) throws VersionException, IOException {

		if (openMode == OpenMode.CREATE) {
			table = handle.createTable(ADDRESS_MODEL_TABLE_NAME, V0_ADDRESS_MODEL_SCHEMA,
				new int[] { V0_ADDRESS_MODEL_DT_ID_COL });
		}
		else {
			table = handle.getTable(ADDRESS_MODEL_TABLE_NAME);
			if (table == null) {
				throw new VersionException("Missing Table: " + ADDRESS_MODEL_TABLE_NAME, 0, true);
			}
			int version = table.getSchema().getVersion();
			if (version != VERSION) {
				String msg = "Expected version " + VERSION + " for table " + ADDRESS_MODEL_TABLE_NAME +
					" but got " + table.getSchema().getVersion();
				if (version < VERSION) {
					throw new VersionException(msg, VersionException.OLDER_VERSION, true);
				}
				throw new VersionException(msg, VersionException.NEWER_VERSION, false);
			}
		}
	}

	@Override
	public DBRecord createRecord(long dataTypeID, byte modelID) throws IOException {
//		throw new UnsupportedOperationException("Not allowed to update prior version #" + VERSION +
//			" of " + ADDRESS_MODEL_TABLE_NAME + " table.");

		long tableKey = table.getKey();
		DBRecord record = V0_ADDRESS_MODEL_SCHEMA.createRecord(tableKey);
		record.setLongValue(V0_ADDRESS_MODEL_DT_ID_COL, dataTypeID);
		record.setByteValue(V0_ADDRESS_MODEL_ID_COL, modelID);
		table.putRecord(record);
		return record;
	}

	@Override
	public DBRecord getRecord(long dataTypeID) throws IOException {
		return table.getRecord(dataTypeID);
	}

	@Override
	public RecordIterator getRecords() throws IOException {
		return table.iterator();
	}

	@Override
	public void updateRecord(DBRecord record, boolean setLastChangeTime) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean removeRecord(long dataTypeID) throws IOException {
		return table.deleteRecord(dataTypeID);
	}

	@Override
	protected void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(ADDRESS_MODEL_TABLE_NAME);
	}

}
