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
 * Version 0 of the ProtoDBAdapter
 */

class ProtoDBAdapterV0 implements ProtoDBAdapter {
//	private Schema protoSchema_v0 = new Schema(0, "Keys",  
//							new Class[] {BinaryField.class, LongField.class},
//							new String[] {"Bytes", "Address"});

	private Table table;

	ProtoDBAdapterV0(DBHandle handle) throws DatabaseVersionException {

		table = handle.getTable(PrototypeManager.PROTO_TABLE_NAME);
		testVersion(0);
	}

	/**
	 * @see ghidra.program.database.code.ProtoDBAdapter#getVersion()
	 */
	public int getVersion() {
		return 0;
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
		throw new UnsupportedOperationException("Cannot create records with old schema");
	}

	/**
	 * @see ghidra.program.database.code.ProtoDBAdapter#deleteAll()
	 */
	public void deleteAll() {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.code.ProtoDBAdapter#getKey()
	 */
	public long getKey() throws IOException {
		return table.getKey();
	}

	/**
	 * @see ghidra.program.database.code.ProtoDBAdapter#getNumRecords()
	 */
	public int getNumRecords() throws IOException {
		return table.getRecordCount();
	}

	/**
	 * @see ghidra.program.database.code.ProtoDBAdapter#getRecord(int)
	 */
	public DBRecord getRecord(int protoId) throws IOException {
		return convertRecord(table.getRecord(protoId));
	}

	private DBRecord convertRecord(DBRecord oldRec) {
		long key = oldRec.getKey();
		if (key < 0)
			key = -key;
		DBRecord newRec = PrototypeManager.PROTO_SCHEMA.createRecord(key);
		newRec.setBinaryData(0, oldRec.getBinaryData(0));
		newRec.setLongValue(1, oldRec.getLongValue(1));
		newRec.setBooleanValue(2, false);
		return newRec;
	}

	/**
	 * @see ghidra.program.database.code.ProtoDBAdapter#getRecords()
	 */
	public RecordIterator getRecords() throws IOException {
		return new RecordUpdateIterator(table.iterator());
	}

	class RecordUpdateIterator implements RecordIterator {
		RecordIterator it;

		RecordUpdateIterator(RecordIterator it) {
			this.it = it;
		}

		public boolean delete() throws IOException {
			throw new UnsupportedOperationException();
		}

		public boolean hasNext() throws IOException {
			return it.hasNext();
		}

		public boolean hasPrevious() throws IOException {
			return it.hasPrevious();
		}

		public DBRecord next() throws IOException {
			return convertRecord(it.next());
		}

		public DBRecord previous() throws IOException {
			DBRecord rec = it.previous();
			long key = rec.getKey();
			if (key < 0)
				key = -key;
			DBRecord newRec = PrototypeManager.PROTO_SCHEMA.createRecord(key);
			newRec.setBinaryData(0, rec.getBinaryData(0));
			newRec.setLongValue(1, rec.getLongValue(1));
			newRec.setBooleanValue(2, false);
			return newRec;
		}

	}
}
