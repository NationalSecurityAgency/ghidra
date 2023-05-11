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
import ghidra.program.database.ProgramDB;
import ghidra.program.database.map.AddressIndexPrimaryKeyIterator;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.util.exception.VersionException;

/**
 * Relocation Adapter (v6) introduced a stored status and length value.  The byte-length value
 * is  only stored/used when stored bytes are not used and the original bytes are obtained from 
 * the underlying {@link FileBytes} via associated {@link Memory}.  Older program's may 
 * have a stored bytes array but is unneccessary when original FileBytes are available. 
 * <br>
 * During the transition of older relocation records we are unable to determine a proper status 
 * without comparing current memory to the original bytes.  It may also be neccessary to reconcile
 * overlapping relocations when the stored bytes value is null to obtain a valid length.  This
 * transition is too complicated for a low-level record translation so it must be deferred to 
 * a higher-level program upgrade (see {@link ProgramDB}).  This also holds true for establishing
 * a reasonable status for existing relocation records.  During the initial record migration a
 * status of {@link Status#UNKNOWN} and default length will be used.  After the program is 
 * ready another high-level upgrade, based on Program version, will then attempt to refine these 
 * records further.
 */
public class RelocationDBAdapterV6 extends RelocationDBAdapter {

	final static int VERSION = 6;
	private Table relocTable;
	private AddressMap addrMap;

	/**
	 * Construct V6 relocation adapter
	 * @param handle database adapter
	 * @param addrMap address map for decode
	 * @param create true if new table should be created, else open existing table
	 * @throws IOException if database IO error occurs
	 * @throws VersionException throw if table schema is not V6
	 */
	RelocationDBAdapterV6(DBHandle handle, AddressMap addrMap, boolean create) throws IOException,
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
	void add(Address addr, byte flags, int type, long[] values, byte[] bytes, String symbolName)
			throws IOException {
		long key = relocTable.getKey();
		DBRecord r = SCHEMA.createRecord(key);
		r.setLongValue(ADDR_COL, addrMap.getKey(addr, true));
		r.setByteValue(FLAGS_COL, flags);
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
	 * Add or update relocation table record.
	 * @param rec relocation record
	 * @throws IOException if database IO error occurs
	 */
	void put(DBRecord rec) throws IOException {
		relocTable.putRecord(rec);
	}

}
