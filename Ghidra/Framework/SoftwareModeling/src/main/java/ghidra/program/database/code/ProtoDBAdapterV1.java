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
package ghidra.program.database.code;

import ghidra.program.database.util.DatabaseVersionException;

import java.io.IOException;

import db.*;

/**
 * Implements version 1 of the ProtoDBAdapter interface.
 */
class ProtoDBAdapterV1 implements ProtoDBAdapter {
	private Table table;

	ProtoDBAdapterV1(DBHandle handle) throws DatabaseVersionException {

		table = handle.getTable(PrototypeManager.PROTO_TABLE_NAME);
		testVersion(1);
	}

	/**
	 * @see ghidra.program.database.code.ProtoDBAdapter#getVersion()
	 */
	public int getVersion() {
		return 1;
	}

	/**
	 * @see ghidra.program.database.code.ProtoDBAdapter#getNumRecords()
	 */
	public int getNumRecords() throws IOException {
		return table.getRecordCount();
	}

	private void testVersion(int expectedVersion) throws DatabaseVersionException {

		if (table == null) {
			throw new DatabaseVersionException("Instruction table not found");
		}
		int versionNumber = table.getSchema().getVersion();
		if (versionNumber != expectedVersion) {
			throw new DatabaseVersionException("Prototype table: Expected Version " +
				expectedVersion + ", got " + versionNumber);
		}
	}

	/**
	 * @see ghidra.program.database.code.ProtoDBAdapter#createRecord(int, byte[])
	 */
	public void createRecord(int protoID, long addr, byte[] b, boolean inDelaySlot)
			throws IOException {

		DBRecord record = PrototypeManager.PROTO_SCHEMA.createRecord(protoID);
		record.setBinaryData(PrototypeManager.BYTES_COL, b);
		record.setLongValue(PrototypeManager.ADDR_COL, addr);
		record.setBooleanValue(2, inDelaySlot);
		table.putRecord(record);
	}

	/**
	 * @see ghidra.program.database.code.ProtoDBAdapter#getKey()
	 */
	public long getKey() throws IOException {
		return table.getKey();
	}

	/**
	 * @see ghidra.program.database.code.ProtoDBAdapter#getRecord(int)
	 */
	public DBRecord getRecord(int protoId) throws IOException {
		return table.getRecord(protoId);
	}

	/**
	 * @see ghidra.program.database.code.ProtoDBAdapter#getRecords()
	 */
	public RecordIterator getRecords() throws IOException {
		return table.iterator();
	}

	/**s
	 * @see ghidra.program.database.code.ProtoDBAdapter#deleteAll()
	 */
	public void deleteAll() throws IOException {
		table.deleteAll();
	}
}
