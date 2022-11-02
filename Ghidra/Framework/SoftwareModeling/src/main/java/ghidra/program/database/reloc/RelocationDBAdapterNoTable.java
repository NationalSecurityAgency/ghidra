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
import ghidra.program.database.util.EmptyRecordIterator;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.exception.VersionException;

/**
 * A stub for a time when we did not produce these tables.
 */
class RelocationDBAdapterNoTable extends RelocationDBAdapter {
	final static int VERSION = 0;

	/**
	 * Construct V0 read-only adapter
	 * @param handle database adapter
	 * @throws IOException if database IO error occurs
	 * @throws VersionException throw if table schema is not V0
	 */
	RelocationDBAdapterNoTable(DBHandle handle) throws IOException, VersionException {
		Table relocTable = handle.getTable(TABLE_NAME);
		if (relocTable != null) {
			throw new VersionException();
		}
	}

	@Override
	void add(Address addrKey, int type, long[] values, byte[] bytes, String symbolName) {
		throw new UnsupportedOperationException();
	}

	@Override
	int getRecordCount() {
		return 0;
	}

	@Override
	RecordIterator iterator() throws IOException {
		return new EmptyRecordIterator();
	}

	@Override
	RecordIterator iterator(AddressSetView set) throws IOException {
		return new EmptyRecordIterator();
	}

	@Override
	RecordIterator iterator(Address start) throws IOException {
		return new EmptyRecordIterator();
	}

	@Override
	DBRecord adaptRecord(DBRecord rec) {
		throw new UnsupportedOperationException();
	}
}
