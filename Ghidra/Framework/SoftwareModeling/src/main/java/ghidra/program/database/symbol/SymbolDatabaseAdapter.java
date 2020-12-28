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
package ghidra.program.database.symbol;

import java.io.IOException;
import java.util.Set;

import db.*;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Adapter to access records in the symbol table.
 */
abstract class SymbolDatabaseAdapter {

	static final String SYMBOL_TABLE_NAME = "Symbols";

	static final Schema SYMBOL_SCHEMA = new Schema(2, "Key",
		new Field[] { StringField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE,
			ByteField.INSTANCE, LongField.INSTANCE, IntField.INSTANCE, StringField.INSTANCE,
			ByteField.INSTANCE },
		new String[] { "Name", "Address", "Parent", "Symbol Type", "SymbolData1", "SymbolData2",
			"SymbolData3", "Flags" });

	static final int SYMBOL_NAME_COL = 0;
	static final int SYMBOL_ADDR_COL = 1;
	static final int SYMBOL_PARENT_COL = 2;
	static final int SYMBOL_TYPE_COL = 3;
	static final int SYMBOL_DATA1_COL = 4;
	static final int SYMBOL_DATA2_COL = 5;
	static final int SYMBOL_DATA3_COL = 6;
	static final int SYMBOL_FLAGS_COL = 7;

	// Bits 0 & 1 are used for the source of the symbol.
	static final byte SYMBOL_SOURCE_BITS = (byte) 0x3;
	static final byte SYMBOL_PINNED_FLAG = (byte) 0x4; // Bit 2 is flag for "anchored to address".

	// TODO: NEXT UPGRADE: remove all variable/parameter symbols with NO_ADDRESS

	/**
	 * Gets a new SymbolDatabaseAdapter
	 * @param dbHandle the database handle.
	 * @param openMode the openmode
	 * @param addrMap the address map
	 * @param monitor the progress monitor.
	 * @throws VersionException if the database table does not match the adapter.
	 * @throws CancelledException if the user cancels an upgrade.
	 * @throws IOException if a database io error occurs.
	 */
	static SymbolDatabaseAdapter getAdapter(DBHandle dbHandle, int openMode, AddressMap addrMap,
			TaskMonitor monitor) throws VersionException, CancelledException, IOException {

		if (openMode == DBConstants.CREATE) {
			return new SymbolDatabaseAdapterV2(dbHandle, addrMap, true);
		}

		try {
			SymbolDatabaseAdapter adapter = new SymbolDatabaseAdapterV2(dbHandle, addrMap, false);
			if (addrMap.isUpgraded()) {
				throw new VersionException(true);
			}
			return adapter;
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			SymbolDatabaseAdapter adapter = findReadOnlyAdapter(dbHandle, addrMap);
			if (openMode == DBConstants.UPGRADE) {
				adapter = SymbolDatabaseAdapterV2.upgrade(dbHandle, addrMap, adapter, monitor);
			}
			else if (adapter instanceof SymbolDatabaseAdapterV0) {
				// Upgrade required - read-only use not supported
				throw e;
			}
			return adapter;
		}
	}

	private static SymbolDatabaseAdapter findReadOnlyAdapter(DBHandle handle, AddressMap addrMap)
			throws VersionException, IOException {

		try {
			return new SymbolDatabaseAdapterV2(handle, addrMap.getOldAddressMap(), false);
		}
		catch (VersionException e1) {
		}

		try {
			return new SymbolDatabaseAdapterV1(handle, addrMap.getOldAddressMap());
		}
		catch (VersionException e1) {
		}

		return new SymbolDatabaseAdapterV0(handle, addrMap);
	}

	/**
	 * Create a new symbol
	 * @param name name of the symbol
	 * @param addr address of the symbol
	 * @param parentSymbolID the id of the containing namespace symbol
	 * @param symbolType the type of this symbol
	 * @param data1 place to store a long value that depends on the symbol type
	 * @param data2 place to store an int value that depends on the symbol type
	 * @param data3 place to store a String value that depends on the symbol type
	 * @param source the source of this symbol
	 * <br>Some symbol types, such as function symbols, can set the source to Symbol.DEFAULT.
	 * @return the new record
	 * @throws IOException if there was a problem accessing the database
	 * @throws IllegalArgumentException if you try to set the source to DEFAULT for a symbol type
	 * that doesn't allow it.
	 */
	abstract DBRecord createSymbol(String name, Address address, long parentSymbolID,
			SymbolType symbolType, long data1, int data2, String data3, SourceType source)
			throws IOException;

	/**
	 * Get the record with the given symbol ID
	 * @param symbolID key for the database record
	 * @return record with the given symbolID
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord getSymbolRecord(long symbolID) throws IOException;

	/**
	 * Remove the record for the given symbol ID
	 * @param symbolID key for the database record
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void removeSymbol(long symbolID) throws IOException;

	/**
	 * Check if the address has a symbol defined at it
	 *
	 * @param addr address to filter on
	 * @return true if there exists a record with the given address
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract boolean hasSymbol(Address addr) throws IOException;

	/**
	 * Get the symbolIDs at the given address.
	 * @param addr address to filter on
	 * @return array of database LongField keys contained within a Field array.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract Field[] getSymbolIDs(Address addr) throws IOException;

	/**
	 * Get the number of symbols.
	 */
	abstract int getSymbolCount();

	/**
	 * Get an iterator over all the symbols in ascending address order.
	 * @return
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract RecordIterator getSymbolsByAddress(boolean forward) throws IOException;

	/**
	 * Get an iterator over all the symbols starting at startAddr.
	 * @param startAddr start address of where to get symbols
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract RecordIterator getSymbolsByAddress(Address startAddr, boolean forward)
			throws IOException;

	/**
	 * Update the table with the given record.
	 * @param record
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void updateSymbolRecord(DBRecord record) throws IOException;

	/**
	 * Get all of the symbols.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract RecordIterator getSymbols() throws IOException;

	/**
	 * Get symbols in the given range.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract RecordIterator getSymbols(Address start, Address end, boolean forward)
			throws IOException;

	/**
	 * Update the address in all records to reflect the movement of a symbol address.
	 * @param oldAddr the original symbol address
	 * @param newAddr the new symbol address
	 * @throws IOException
	 */
	abstract void moveAddress(Address oldAddr, Address newAddr) throws IOException;

	/**
	 * Update the addresses in all records to reflect the movement of a memory block.
	 * @param fromAddr minimum address of the original block to be moved
	 * @param toAddr the new minimum address after the block move
	 * @param length the number of bytes in the memory block being moved
	 * @param monitor progress monitor
	 * @return returns the set of addresses where symbols where not moved because they were anchored
	 * @throws CancelledException
	 * @throws IOException
	 */
	abstract void moveAddressRange(Address fromAddr, Address toAddr, long length,
			TaskMonitor monitor) throws CancelledException, IOException;

	/**
	 * Delete all records which contain addresses within the specified range
	 * @param startAddr minimum address in range
	 * @param endAddr maximum address in range
	 * @param monitor progress monitor
	 * @return returns the set of addresses where symbols where not deleted because they were anchored
	 * @throws CancelledException
	 * @throws IOException
	 */
	abstract Set<Address> deleteAddressRange(Address startAddr, Address endAddr,
			TaskMonitor monitor) throws CancelledException, IOException;

	/**
	 * Get all symbols contained within the specified namespace
	 * @param id the namespace id.
	 * @return an iterator over all symbols in the given namespace.
	 * @throws IOException
	 */
	abstract RecordIterator getSymbolsByNamespace(long id) throws IOException;

	/**
	 * Get symbols starting with the specified name in name order
	 * @param name name to start with.
	 * @return a record iterator over the symbols.
	 * @throws IOException if a database io error occurs.
	 */
	abstract RecordIterator getSymbolsByName(String name) throws IOException;

	/**
	 * Returns the maximum symbol address within the specified address space.
	 * Intended for update use only.
	 * @param space address space
	 * @return maximum symbol address within space or null if none are found.
	 */
	abstract Address getMaxSymbolAddress(AddressSpace space) throws IOException;

	/**
	 * Returns the underlying symbol table (for upgrade use only).
	 */
	abstract Table getTable();
}
