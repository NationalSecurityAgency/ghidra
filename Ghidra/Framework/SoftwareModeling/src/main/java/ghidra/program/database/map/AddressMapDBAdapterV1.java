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
class AddressMapDBAdapterV1 extends AddressMapDBAdapter {

	final Schema SCHEMA = new Schema(CURRENT_VERSION, "Key",
		new Field[] { StringField.INSTANCE, IntField.INSTANCE, BooleanField.INSTANCE },
		new String[] { "Space Name", "Segment", "Deleted" });

	final int SPACE_NAME_COL = 0;
	final int SEGMENT_COL = 1;
	final int DELETED_COL = 2;

	private Table table;
	private AddressFactory factory;
	private Address[] addresses;
	private final DBHandle handle;

	AddressMapDBAdapterV1(DBHandle handle, AddressFactory factory, boolean create)
			throws VersionException, IOException {
		this.handle = handle;
		this.factory = factory;
		if (create) {
			table = handle.createTable(TABLE_NAME, SCHEMA);
		}
		else {
			table = handle.getTable(TABLE_NAME);
			if (table == null || table.getSchema().getVersion() < 1) {
				throw new VersionException(true);
			}
			if (table.getSchema().getVersion() != CURRENT_VERSION) {
				throw new VersionException("Expected version 0 for table " + TABLE_NAME +
					" but got " + table.getSchema().getVersion());
			}
		}
		readAddresses();
	}

	private void readAddresses() throws IOException {
		addresses = new Address[table.getRecordCount()];
		RecordIterator it = table.iterator();
		while (it.hasNext()) {
			DBRecord rec = it.next();
			String spaceName = rec.getString(SPACE_NAME_COL);
			int segment = rec.getIntValue(SEGMENT_COL);
			boolean deleted = rec.getBooleanValue(DELETED_COL);
			AddressSpace space = factory.getAddressSpace(spaceName);
			if (deleted || space == null) {
				String deletedName = "Deleted_" + spaceName;
				if (segment != 0) {
					spaceName += "_" + segment;
				}
				GenericAddressSpace sp = new GenericAddressSpace(deletedName, 32,
					AddressSpace.TYPE_DELETED, (int) rec.getKey());
				sp.setShowSpaceName(true);
				space = sp;
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
			list.add(new AddressMapEntry((int) rec.getKey(), spaceName,
				rec.getIntValue(SEGMENT_COL), rec.getBooleanValue(DELETED_COL)));
		}
		return list;
	}

	/**
	 * @see ghidra.program.database.map.AddressMapDBAdapter#setEntries(java.util.List)
	 */
	@Override
	void setEntries(List<AddressMapEntry> entries) throws IOException {
		if (table.getRecordCount() != 0) {
			throw new IllegalStateException();
		}
		for (AddressMapEntry entry : entries) {
			if (entry.index != table.getRecordCount()) {
				throw new IllegalArgumentException("Bad map entry");
			}
			DBRecord rec = SCHEMA.createRecord(entry.index);
			rec.setString(SPACE_NAME_COL, entry.name);
			rec.setIntValue(SEGMENT_COL, entry.segment);
			rec.setBooleanValue(DELETED_COL, entry.deleted);
			table.putRecord(rec);
		}
		readAddresses();
	}

	/**
	 * @see ghidra.program.database.map.AddressMapDBAdapter#addBaseAddress(ghidra.program.model.address.Address, long)
	 */
	@Override
	Address[] addBaseAddress(Address addr, long normalizedOffset) {

		DBRecord rec = SCHEMA.createRecord(addresses.length);
		AddressSpace space = addr.getAddressSpace();
		rec.setString(SPACE_NAME_COL, space.getName());
		int segment = (int) (normalizedOffset >> AddressMapDB.ADDR_OFFSET_SIZE);
		rec.setIntValue(SEGMENT_COL, segment);
		rec.setBooleanValue(DELETED_COL, false);
		try {
			table.putRecord(rec);
		}
		catch (IOException e) {
			return addresses;
		}

		Address[] newAddrs = new Address[addresses.length + 1];
		System.arraycopy(addresses, 0, newAddrs, 0, addresses.length);
		newAddrs[addresses.length] = addr.getAddressSpace().getAddressInThisSpaceOnly(
			normalizedOffset & ~AddressMapDB.ADDR_OFFSET_MASK);
		addresses = newAddrs;

		return addresses;
	}

	/**
	 * @see ghidra.program.database.map.AddressMapDBAdapter#clearAll()
	 */
	@Override
	void clearAll() throws IOException {
		table.deleteAll();
		addresses = new Address[0];
	}

	@Override
	void setAddressFactory(AddressFactory addrFactory) {
		this.factory = addrFactory;
	}

	@Override
	void renameOverlaySpace(String oldName, String newName) throws IOException {
		RecordIterator it = table.iterator();
		while (it.hasNext()) {
			DBRecord rec = it.next();
			String spaceName = rec.getString(SPACE_NAME_COL);
			boolean deleted = rec.getBooleanValue(DELETED_COL);
			if (!deleted && spaceName.equals(oldName)) {
				rec.setString(SPACE_NAME_COL, newName);
				table.putRecord(rec);
			}
		}
	}

	@Override
	void deleteOverlaySpace(String name) throws IOException {
		RecordIterator it = table.iterator();
		while (it.hasNext()) {
			DBRecord rec = it.next();
			String spaceName = rec.getString(SPACE_NAME_COL);
			if (spaceName.equals(name)) {
				rec.setBooleanValue(DELETED_COL, true);
				table.putRecord(rec);
			}
		}
	}

	@Override
	void deleteTable() throws IOException {
		handle.deleteTable(TABLE_NAME);
	}
}
