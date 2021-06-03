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

import ghidra.program.database.map.AddressKeyRecordIterator;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.exception.VersionException;

import java.io.IOException;

import java.lang.UnsupportedOperationException;

import db.*;

class RelocationDBAdapterV1 extends RelocationDBAdapter {
	final static int VERSION = 1;
	private Table relocTable;
	private AddressMap addrMap;

	RelocationDBAdapterV1(DBHandle handle, AddressMap addrMap) throws VersionException {
		this.addrMap = addrMap.getOldAddressMap();
		relocTable = handle.getTable(TABLE_NAME);
		if (relocTable == null) {
			throw new VersionException("Missing Table: " + TABLE_NAME);
		}
		else if (relocTable.getSchema().getVersion() != VERSION) {
			throw new VersionException(false);
		}
	}

	@Override
	void add(long addrKey, int type, long[] values, byte[] bytes, String symbolName) {
		throw new UnsupportedOperationException();
	}

	@Override
	DBRecord get(long addrKey) throws IOException {
		return relocTable.getRecord(addrKey);
	}

	@Override
	int getRecordCount() {
		return relocTable.getRecordCount();
	}

	@Override
	int getVersion() {
		return VERSION;
	}

	@Override
	void remove(long addrKey) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	RecordIterator iterator() throws IOException {
		RecordIterator recIter = new AddressKeyRecordIterator(relocTable, addrMap);
		return new RecordIteratorAdapter(recIter);
	}

	@Override
	RecordIterator iterator(AddressSetView set) throws IOException {
		RecordIterator recIter =
			new AddressKeyRecordIterator(relocTable, addrMap, set, set.getMinAddress(), true);
		return new RecordIteratorAdapter(recIter);
	}

	@Override
	RecordIterator iterator(Address start) throws IOException {
		RecordIterator recIter = new AddressKeyRecordIterator(relocTable, addrMap, start, true);
		return new RecordIteratorAdapter(recIter);
	}

	@Override
	DBRecord adaptRecord(DBRecord rec) {
		DBRecord newRec = SCHEMA.createRecord(rec.getKey());
		newRec.setIntValue(TYPE_COL, rec.getIntValue(TYPE_COL));
		newRec.setBinaryData(BYTES_COL, null);
		return newRec;
	}
}
