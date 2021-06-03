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
package ghidra.program.database.references;

import java.io.IOException;

import db.*;
import db.util.ErrorHandler;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.map.*;
import ghidra.program.model.address.*;
import ghidra.util.exception.VersionException;

class FromAdapterV0 extends FromAdapter {

	private Table table;
	private AddressMap addrMap;
	private ErrorHandler errHandler;

	FromAdapterV0(DBHandle handle, boolean create, AddressMap addrMap, ErrorHandler errHandler)
			throws IOException, VersionException {
		this.addrMap = addrMap;
		this.errHandler = errHandler;
		if (create) {
			table = handle.createTable(FROM_REFS_TABLE_NAME, FROM_REFS_SCHEMA);
		}
		else {
			table = handle.getTable(FROM_REFS_TABLE_NAME);
			if (table == null) {
				throw new VersionException("Missing Table: " + FROM_REFS_TABLE_NAME);
			}
			else if (table.getSchema().getVersion() != 0) {
				throw new VersionException(VersionException.NEWER_VERSION, false);
			}
		}
	}

	@Override
	public RefList createRefList(ProgramDB program, DBObjectCache<RefList> cache, Address from)
			throws IOException {
		return new RefListV0(from, this, addrMap, program, cache, true);
	}

	@Override
	public RefList getRefList(ProgramDB program, DBObjectCache<RefList> cache, Address from,
			long fromAddr) throws IOException {
		DBRecord rec = table.getRecord(fromAddr);
		if (rec != null) {
			if (rec.getBinaryData(REF_DATA_COL) == null) {
				return new BigRefListV0(rec, this, addrMap, program, cache, true);
			}
			return new RefListV0(rec, this, addrMap, program, cache, true);
		}
		return null;
	}

	@Override
	boolean hasRefFrom(long fromAddr) throws IOException {
		return table.hasRecord(fromAddr);
	}

	@Override
	public DBRecord createRecord(long key, int numRefs, byte refLevel, byte[] refData)
			throws IOException {
		DBRecord rec = FROM_REFS_SCHEMA.createRecord(key);
		rec.setIntValue(REF_COUNT_COL, numRefs);
		rec.setBinaryData(REF_DATA_COL, refData);
		table.putRecord(rec);
		return rec;
	}

	@Override
	public DBRecord getRecord(long key) throws IOException {
		return table.getRecord(key);
	}

	@Override
	public void putRecord(DBRecord record) throws IOException {
		table.putRecord(record);
	}

	@Override
	public void removeRecord(long key) throws IOException {
		table.deleteRecord(key);
	}

	@Override
	AddressIterator getFromIterator(boolean forward) throws IOException {
		return new AddressKeyAddressIterator(new AddressKeyIterator(table, addrMap, forward),
			forward, addrMap, errHandler);
	}

	@Override
	AddressIterator getFromIterator(Address startAddr, boolean forward) throws IOException {
		return new AddressKeyAddressIterator(
			new AddressKeyIterator(table, addrMap, startAddr, forward), forward, addrMap,
			errHandler);
	}

	@Override
	AddressIterator getFromIterator(AddressSetView set, boolean forward) throws IOException {
		return new AddressKeyAddressIterator(
			new AddressKeyIterator(table, addrMap, set, set.getMinAddress(), forward), forward,
			addrMap, errHandler);
	}

	@Override
	int getRecordCount() {
		return table.getRecordCount();
	}
}
