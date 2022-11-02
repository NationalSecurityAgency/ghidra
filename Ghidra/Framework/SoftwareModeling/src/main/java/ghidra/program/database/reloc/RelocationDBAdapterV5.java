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
package ghidra.program.database.reloc;

import java.io.IOException;

import db.*;
import ghidra.program.database.map.AddressIndexPrimaryKeyIterator;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.exception.VersionException;

public class RelocationDBAdapterV5 extends RelocationDBAdapter {
	final static int VERSION = 5;
	private Table relocTable;
	private AddressMap addrMap;

	RelocationDBAdapterV5(DBHandle handle, AddressMap addrMap, boolean create) throws IOException,
			VersionException {
		this.addrMap = addrMap;
		if (create) {
			relocTable = handle.createTable(TABLE_NAME, SCHEMA, new int[] { ADDR_COL });
		}
		else {
			relocTable = handle.getTable(TABLE_NAME);
			if (relocTable == null) {
				throw new VersionException(true);
			}
			int version = relocTable.getSchema().getVersion();
			if (version != VERSION) {
				throw new VersionException(version < VERSION);
			}
		}
	}

	@Override
	void add(Address addr, int type, long[] values, byte[] bytes, String symbolName)
			throws IOException {
		long key = relocTable.getKey();
		DBRecord r = SCHEMA.createRecord(key);
		r.setLongValue(ADDR_COL, addrMap.getKey(addr, true));
		r.setIntValue(TYPE_COL, type);
		r.setField(VALUE_COL, new BinaryCodedField(values));
		r.setBinaryData(BYTES_COL, bytes);
		r.setString(SYMBOL_NAME_COL, symbolName);
		relocTable.putRecord(r);
	}

	@Override
	int getRecordCount() {
		return relocTable.getRecordCount();
	}

	@Override
	RecordIterator iterator() throws IOException {
		return new KeyToRecordIterator(relocTable, new AddressIndexPrimaryKeyIterator(relocTable,
			ADDR_COL, addrMap, true));
	}

	@Override
	RecordIterator iterator(AddressSetView set) throws IOException {
		return new KeyToRecordIterator(relocTable, new AddressIndexPrimaryKeyIterator(relocTable,
			ADDR_COL, addrMap, set, true));
	}

	@Override
	RecordIterator iterator(Address start) throws IOException {
		return new KeyToRecordIterator(relocTable, new AddressIndexPrimaryKeyIterator(relocTable,
			ADDR_COL, addrMap, start, true));
	}

	@Override
	DBRecord adaptRecord(DBRecord rec) {
		// my guess is that we don't need to do this until there is a version newer than us
		throw new UnsupportedOperationException("Don't know how to adapt to the new version");
	}

	/**
	 * Add V5 relocation record to table.
	 * @param rec relocation record
	 * @throws IOException if database IO error occurs
	 */
	void add(DBRecord rec) throws IOException {
		relocTable.putRecord(rec);
	}

}
