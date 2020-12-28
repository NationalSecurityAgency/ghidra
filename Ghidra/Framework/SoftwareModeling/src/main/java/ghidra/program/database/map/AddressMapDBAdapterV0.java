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
package ghidra.program.database.map;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import db.*;
import ghidra.program.model.address.*;
import ghidra.util.exception.VersionException;

/**
 * Adapter version 0 (the first real adapter)
 */
class AddressMapDBAdapterV0 extends AddressMapDBAdapter {

	final Schema SCHEMA = new Schema(0, "Key",
		new Field[] { StringField.INSTANCE, IntField.INSTANCE, ShortField.INSTANCE },
		new String[] { "Space Name", "Segment", "Not Used" });

	final int SPACE_NAME_COL = 0;
	final int SEGMENT_COL = 1;

	private Table table;
	private DBHandle handle;
	private AddressFactory factory;
	private Address[] addresses;

	AddressMapDBAdapterV0(DBHandle handle, AddressFactory factory)
			throws VersionException, IOException {
		this.handle = handle;
		this.factory = factory;
		table = handle.getTable(TABLE_NAME);
		if (table == null) {
			throw new VersionException(true);
		}
		if (table.getSchema().getVersion() != 0) {
			throw new VersionException("Expected version 0 for table " + TABLE_NAME + " but got " +
				table.getSchema().getVersion());
		}
		readAddresses();
	}

	private void readAddresses() throws IOException {
		addresses = new Address[table.getRecordCount()];
		RecordIterator it = table.iterator();
		int deletedID = 1;
		while (it.hasNext()) {
			DBRecord rec = it.next();
			String spaceName = rec.getString(SPACE_NAME_COL);
			int segment = rec.getIntValue(SEGMENT_COL);
			AddressSpace space = factory.getAddressSpace(spaceName);
			if (space == null) {
				GenericAddressSpace sp = new GenericAddressSpace("Deleted_" + spaceName, 32,
					AddressSpace.TYPE_UNKNOWN, deletedID++);
				sp.setShowSpaceName(true);
				space = sp;
			}
			if (space.getSize() <= 32) {
				segment = 0;
			}
			Address addr =
				space.getAddressInThisSpaceOnly(((long) segment) << AddressMapDB.ADDR_OFFSET_SIZE);
			addresses[(int) rec.getKey()] = addr;
		}
	}

	/**
	 * @see ghidra.program.database.map.AddressMapDBAdapter#getBaseAddresses()
	 */
	@Override
	Address[] getBaseAddresses(boolean forceRead) throws IOException {
		if (forceRead || table.getRecordCount() != addresses.length) {
			readAddresses();
		}
		return addresses;
	}

	/**
	 * @see ghidra.program.database.map.AddressMapDBAdapter#getEntries()
	 */
	@Override
	List<AddressMapEntry> getEntries() throws IOException {
		ArrayList<AddressMapEntry> list = new ArrayList<AddressMapEntry>();
		RecordIterator it = table.iterator();
		while (it.hasNext()) {
			DBRecord rec = it.next();
			String spaceName = rec.getString(SPACE_NAME_COL);
			boolean deleted = (factory.getAddressSpace(spaceName) == null);
			list.add(new AddressMapEntry((int) rec.getKey(), spaceName,
				rec.getIntValue(SEGMENT_COL), deleted));
		}
		return list;
	}

	/**
	 * @see ghidra.program.database.map.AddressMapDBAdapter#setEntries(java.util.List)
	 */
	@Override
	void setEntries(List<AddressMapEntry> entries) throws IOException {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.map.AddressMapDBAdapter#addBaseAddress(ghidra.program.model.address.Address, long)
	 */
	@Override
	Address[] addBaseAddress(Address addr, long normalizedOffset) {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.map.AddressMapDBAdapter#clearAll()
	 */
	@Override
	void clearAll() throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	void setAddressFactory(AddressFactory addrFactory) {
		this.factory = addrFactory;
	}

	@Override
	void renameOverlaySpace(String oldName, String newName) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	void deleteOverlaySpace(String name) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	void deleteTable() throws IOException {
		handle.deleteTable(TABLE_NAME);
	}
}
