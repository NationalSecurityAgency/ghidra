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

class RelocationDBAdapterV3 extends RelocationDBAdapter {
	final static int VERSION = 3;
	private Table relocTable;
	private AddressMap addrMap;

	RelocationDBAdapterV3(DBHandle handle, AddressMap addrMap, boolean create) throws IOException,
			VersionException {
		this.addrMap = addrMap;
		if (create) {
			relocTable = handle.createTable(TABLE_NAME, SCHEMA);
		}
		else {
			relocTable = handle.getTable(TABLE_NAME);
			if (relocTable == null) {
				throw new VersionException("Missing Table: " + TABLE_NAME);
			}
			else if (relocTable.getSchema().getVersion() != VERSION) {
				int version = relocTable.getSchema().getVersion();
				if (version < VERSION) {
					throw new VersionException(true);
				}
				throw new VersionException(VersionException.NEWER_VERSION, false);
			}
		}
	}

	@Override
	void add(long addrKey, int type, long[] values, byte[] bytes, String symbolName)
			throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	DBRecord get(long addrKey) throws IOException {
		return relocTable.getRecord(addrKey);
	}

	@Override
	void remove(long addrKey) throws IOException {
		throw new UnsupportedOperationException();
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
	RecordIterator iterator() throws IOException {
		return new AddressKeyRecordIterator(relocTable, addrMap);
	}

	@Override
	RecordIterator iterator(AddressSetView set) throws IOException {
		return new AddressKeyRecordIterator(relocTable, addrMap, set, set.getMinAddress(), true);
	}

	@Override
	RecordIterator iterator(Address start) throws IOException {
		return new AddressKeyRecordIterator(relocTable, addrMap, start, true);
	}

	@Override
	DBRecord adaptRecord(DBRecord rec) {
		DBRecord newRec = SCHEMA.createRecord(rec.getKey());
		newRec.setIntValue(TYPE_COL, rec.getIntValue(TYPE_COL));
		long[] values = new long[] { rec.getLongValue(VALU_COL) };
		newRec.setField(VALU_COL, new BinaryCodedField(values));
		newRec.setBinaryData(BYTES_COL, null);
		newRec.setString(SYMBOL_NAME_COL, null);
		return newRec;
	}
}
