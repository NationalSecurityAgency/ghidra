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
import java.util.List;

import db.DBConstants;
import db.DBHandle;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Database adapter for address map
 */
abstract class AddressMapDBAdapter {

	static String TABLE_NAME = "ADDRESS MAP";
	static final int CURRENT_VERSION = 1;

	AddressMap oldAddrMap;

	static AddressMapDBAdapter getAdapter(DBHandle handle, int openMode, AddressFactory factory,
			TaskMonitor monitor) throws VersionException, IOException {

		if (openMode == DBConstants.CREATE) {
			return new AddressMapDBAdapterV1(handle, factory, true);
		}
		try {
			return new AddressMapDBAdapterV1(handle, factory, false);
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			AddressMapDBAdapter adapter = findReadOnlyAdapter(handle, factory);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(handle, adapter, factory, monitor);
			}
			return adapter;
		}
	}

	static AddressMapDBAdapter findReadOnlyAdapter(DBHandle handle, AddressFactory factory)
			throws IOException {
		try {
			return new AddressMapDBAdapterV0(handle, factory);
		}
		catch (VersionException e) {
			return new AddressMapDBAdapterNoTable(handle, factory);
		}
	}

	static AddressMapDBAdapter upgrade(DBHandle handle, AddressMapDBAdapter oldAdapter,
			AddressFactory factory, TaskMonitor monitor) throws VersionException, IOException {

		monitor.setMessage("Upgrading Address Map...");
		List<AddressMapEntry> entries = oldAdapter.getEntries();
		oldAdapter.deleteTable();

		monitor.initialize(entries.size());

		AddressMapDBAdapter newAdapter = new AddressMapDBAdapterV1(handle, factory, true);
		newAdapter.oldAddrMap = oldAdapter.oldAddrMap;
		newAdapter.setEntries(entries);
		return newAdapter;
	}

	/**
	 * Deletes the table - used when upgrading;
	 */
	abstract void deleteTable() throws IOException;

	/**
	 * Adds a new base address
	 * @param addr the new base address to add.
	 * @param normalizedOffset the normalized offset (image base subtracted) for the address.
	 * @return the array of image bases.
	 */
	abstract Address[] addBaseAddress(Address addr, long normalizedOffset);

	/**
	 * Returns an array of image bases.
	 * @param forceRead forces the adapter to reread the data from the database.
	 * @throws IOException if a database io error occurs.
	 */
	abstract Address[] getBaseAddresses(boolean forceRead) throws IOException;

	/**
	 * Returns raw address map entries.
	 * @throws IOException
	 */
	abstract List<AddressMapEntry> getEntries() throws IOException;

	/**
	 * Initialize map with specified list of map entries (upgrade use only).
	 * @param entries map entries sorted by index (a missing index will cause an exception).
	 * @throws IOException
	 */
	abstract void setEntries(List<AddressMapEntry> entries) throws IOException;

	/**
	 * Clears all entries in the database table.
	 * @throws IOException if a database io error occurs.
	 */
	abstract void clearAll() throws IOException;

	/**
	 * Sets the addressFactory
	 * @param addrFactory the new factory to use.
	 */
	abstract void setAddressFactory(AddressFactory addrFactory);

	abstract void renameOverlaySpace(String oldName, String newName) throws IOException;

	abstract void deleteOverlaySpace(String name) throws IOException;

	static class AddressMapEntry {
		int index;
		String name;
		int segment;
		boolean deleted;

		public AddressMapEntry(int index, String name, int segment, boolean deleted) {
			this.index = index;
			this.name = name;
			this.segment = segment;
			this.deleted = deleted;
		}
	}

}
