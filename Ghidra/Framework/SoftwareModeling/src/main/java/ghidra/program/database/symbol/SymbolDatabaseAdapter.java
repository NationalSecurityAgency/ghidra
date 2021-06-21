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
import java.util.Objects;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;

import db.*;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.util.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Adapter to access records in the symbol table.
 */
abstract class SymbolDatabaseAdapter {
	static final String SYMBOL_TABLE_NAME = "Symbols";

	static final int SYMBOL_NAME_COL = 0;
	static final int SYMBOL_ADDR_COL = 1;
	static final int SYMBOL_PARENT_COL = 2;
	static final int SYMBOL_TYPE_COL = 3;
	static final int SYMBOL_STRING_DATA_COL = 4;
	static final int SYMBOL_FLAGS_COL = 5;

	// sparse fields - the following fields are not always applicable so they are optional and 
	// don't consume space in the database if they aren't used.
	static final int SYMBOL_HASH_COL = 6;
	static final int SYMBOL_PRIMARY_COL = 7;
	static final int SYMBOL_DATATYPE_COL = 8;
	static final int SYMBOL_VAROFFSET_COL = 9;

	static final Schema SYMBOL_SCHEMA = SymbolDatabaseAdapterV3.V3_SYMBOL_SCHEMA;

	// Bits 0 & 1 are used for the source of the symbol.
	static final byte SYMBOL_SOURCE_BITS = (byte) 0x3;
	static final byte SYMBOL_PINNED_FLAG = (byte) 0x4; // Bit 2 is flag for "anchored to address".

	// TODO: NEXT UPGRADE: remove all variable/parameter symbols with NO_ADDRESS

	/**
	 * Gets a new SymbolDatabaseAdapter
	 * @param dbHandle the database handle
	 * @param openMode the open mode. See {@link DBConstants}
	 * @param addrMap the address map
	 * @param monitor the progress monitor
	 * @return a new SymbolDatabaseAdapter
	 * @throws VersionException if the database table does not match the adapter
	 * @throws CancelledException if the user cancels an upgrade
	 * @throws IOException if a database io error occurs
	 */
	static SymbolDatabaseAdapter getAdapter(DBHandle dbHandle, int openMode, AddressMap addrMap,
			TaskMonitor monitor) throws VersionException, CancelledException, IOException {

		if (openMode == DBConstants.CREATE) {
			return new SymbolDatabaseAdapterV3(dbHandle, addrMap, true);
		}

		try {
			SymbolDatabaseAdapter adapter = new SymbolDatabaseAdapterV3(dbHandle, addrMap, false);
			return adapter;
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			SymbolDatabaseAdapter adapter = findReadOnlyAdapter(dbHandle, addrMap);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(dbHandle, addrMap, adapter, monitor);
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
			return new SymbolDatabaseAdapterV2(handle, addrMap.getOldAddressMap());
		}
		catch (VersionException e1) {
			// failed try older version
		}

		try {
			return new SymbolDatabaseAdapterV1(handle, addrMap.getOldAddressMap());
		}
		catch (VersionException e1) {
			// failed try older version
		}

		try {
			return new SymbolDatabaseAdapterV0(handle, addrMap.getOldAddressMap());
		}
		catch (VersionException e1) {
			// failed - can't handle whatever version this is trying to open
		}

		throw new VersionException(false);
	}

	static SymbolDatabaseAdapter upgrade(DBHandle dbHandle, AddressMap addrMap,
			SymbolDatabaseAdapter oldAdapter, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {

		monitor.setMessage("Upgrading Symbol Table...");
		monitor.initialize(oldAdapter.getSymbolCount() * 2);

		DBHandle tmpHandle = dbHandle.getScratchPad();

		try {
			SymbolDatabaseAdapter tmpAdapter =
				copyToTempAndFixupRecords(addrMap, oldAdapter, tmpHandle, monitor);

			dbHandle.deleteTable(SYMBOL_TABLE_NAME);

			SymbolDatabaseAdapter newAdapter =
				new SymbolDatabaseAdapterV3(dbHandle, addrMap, true);

			copyTempToNewAdapter(tmpAdapter, newAdapter, monitor);
			return newAdapter;
		}
		finally {
			tmpHandle.deleteTable(SYMBOL_TABLE_NAME);
		}
	}

	private static SymbolDatabaseAdapter copyToTempAndFixupRecords(AddressMap addrMap,
			SymbolDatabaseAdapter oldAdapter, DBHandle tmpHandle, TaskMonitor monitor)
			throws IOException, CancelledException, VersionException {

		AddressMap oldAddrMap = addrMap.getOldAddressMap();

		long nextKey = 1; // only used for V0 upgrade if a record with key 0 is encountered	
		if (oldAdapter instanceof SymbolDatabaseAdapterV0) {
			// V0 is so old that there is not enough info in the current record to create new
			// records. So store the current info in a temp database table and complete the upgrade
			// when SymbolManager.programReady() is called. The missing info can be retrieved from
			// other managers in the program at that point.
			nextKey =
				((SymbolDatabaseAdapterV0) oldAdapter).extractLocalSymbols(tmpHandle, monitor);
		}

		SymbolDatabaseAdapterV3 tmpAdapter = new SymbolDatabaseAdapterV3(tmpHandle, addrMap, true);
		RecordIterator iter = oldAdapter.getSymbols();
		while (iter.hasNext()) {
			monitor.checkCanceled();
			DBRecord rec = iter.next();
			Address addr = oldAddrMap.decodeAddress(rec.getLongValue(SYMBOL_ADDR_COL));
			rec.setLongValue(SYMBOL_ADDR_COL, addrMap.getKey(addr, true));

			// We don't allow 0 keys starting with V1, set its key to next available
			// which we got from the call to extractLocalSymbols() above
			if (rec.getKey() == 0) {
				rec.setKey(Math.max(1, nextKey));
			}

			tmpAdapter.updateSymbolRecord(rec);
			monitor.incrementProgress(1);
		}

		return tmpAdapter;
	}

	private static void copyTempToNewAdapter(SymbolDatabaseAdapter tmpAdapter,
			SymbolDatabaseAdapter newAdapter, TaskMonitor monitor)
			throws IOException, CancelledException {

		RecordIterator iter = tmpAdapter.getSymbols();
		while (iter.hasNext()) {
			monitor.checkCanceled();
			newAdapter.updateSymbolRecord(iter.next());
			monitor.incrementProgress(1);
		}
	}

	/**
	 * Create a new symbol
	 * @param name name of the symbol
	 * @param address the address for the symbol
	 * @param namespaceID the id of the containing namespace symbol
	 * @param symbolType the type of this symbol
	 * @param stringData place to store a String value that depends on the symbol type
	 * @param source the source type of this symbol
	 * Some symbol types, such as function symbols, can set the source to Symbol.DEFAULT
	 * @param dataTypeId the id of an associated datatype or null if there is no associated datatype
	 * @param varOffset the variable offset will be the ordinal for a parameter or first use offset
	 * for a local variable
	 * @param isPrimary true if the symbol is primary. Only applicable for labels and functions
	 * @return the new record
	 * @throws IOException if there was a problem accessing the database
	 * @throws IllegalArgumentException if you try to set the source to DEFAULT for a symbol type
	 * that doesn't allow it
	 */
	abstract DBRecord createSymbol(String name, Address address, long namespaceID,
			SymbolType symbolType, String stringData, Long dataTypeId, Integer varOffset,
			SourceType source, boolean isPrimary) throws IOException;

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
	 * Get the symbolIDs at the given address
	 * @param addr address to filter on
	 * @return array of database LongField keys contained within a Field array
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract Field[] getSymbolIDs(Address addr) throws IOException;

	/**
	 * Get the number of symbols
	 * @return the number of symbols
	 */
	abstract int getSymbolCount();

	/**
	 * Get an iterator over all the symbols in ascending address order
	 * @param forward the direction to iterator
	 * @return a record iterator over all symbols
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract RecordIterator getSymbolsByAddress(boolean forward) throws IOException;

	/**
	 * Get an iterator over all the symbols starting at startAddr
	 * @param startAddr start address of where to get symbols
	 * @param forward true to iterate from low to high addresses
	 * @return a record iterator over all symbols starting at the given start address
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract RecordIterator getSymbolsByAddress(Address startAddr, boolean forward)
			throws IOException;

	/**
	 * Update the table with the given record
	 * @param record the record to update in the database
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void updateSymbolRecord(DBRecord record) throws IOException;

	/**
	 * Get all of the symbols.
	 * @return a record iterator over all symbols
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract RecordIterator getSymbols() throws IOException;

	/**
	 * Get symbols in the given range
	 * @param start the start address of the range
	 * @param end the last address of the range
	 * @param forward true if iterating from start to end, otherwise iterate from end to start
	 * @return a record iterator for all symbols in the range
	 * @throws IOException if a database io error occurs
	 */
	abstract RecordIterator getSymbols(Address start, Address end, boolean forward)
			throws IOException;

	/**
	 * Get symbols in the given range
	 * @param set the set of addresses to iterate over
	 * @param forward true if iterating from start to end, otherwise iterate from end to start
	 * @return a record iterator for all symbols in the range
	 * @throws IOException if a database io error occurs
	 */
	abstract RecordIterator getSymbols(AddressSetView set, boolean forward)
			throws IOException;

	/** 
	 * Returns an iterator over the primary symbols in the given range
	 * @param set the address set to iterator over when getting primary symbol records
	 * @param forward true if iterating from start to end, otherwise iterate from end to start
	 * @return a record iterator for all symbols in the range
	 * @throws IOException if a database io error occurs
	 */
	abstract RecordIterator getPrimarySymbols(AddressSetView set, boolean forward)
			throws IOException;

	/**
	 * Returns the symbol record for the primary symbol at the given address
	 * @param address the address to get its primary symbol record
	 * @return the primary symbol record at the given address or null if no label or function
	 * exists at that address
	 * @throws IOException if a database io error occurs
	 */
	abstract DBRecord getPrimarySymbol(Address address) throws IOException;

	/**
	 * Update the address in all records to reflect the movement of a symbol address.
	 * @param oldAddr the original symbol address
	 * @param newAddr the new symbol address
	 * @throws IOException if a database io error occurs
	 */
	abstract void moveAddress(Address oldAddr, Address newAddr) throws IOException;

	/**
	 * Delete all records which contain addresses within the specified range
	 * @param startAddr minimum address in range
	 * @param endAddr maximum address in range
	 * @param monitor progress monitor
	 * @return returns the set of addresses where symbols where not deleted because they were anchored
	 * @throws CancelledException if the user cancels the operation
	 * @throws IOException if a database io error occurs
	 */
	abstract Set<Address> deleteAddressRange(Address startAddr, Address endAddr,
			TaskMonitor monitor) throws CancelledException, IOException;

	/**
	 * Get all symbols contained within the specified namespace
	 * @param id the namespace id
	 * @return an iterator over all symbols in the given namespace
	 * @throws IOException if a database io error occurs
	 */
	abstract RecordIterator getSymbolsByNamespace(long id) throws IOException;

	/**
	 * Get symbols that have the specified name
	 * @param name name to search
	 * @return a record iterator over the symbols with the given name
	 * @throws IOException if a database io error occurs
	 */
	abstract RecordIterator getSymbolsByName(String name) throws IOException;

	/**
	 * Get all symbols contained in the given {@link Namespace} that have the given name
	 * @param name the symbol name
	 * @param id the id of the parent namespace
	 * @return a record iterator all the symbols in the given namespace with the given name
	 * @throws IOException if a database io error occurs
	 */
	abstract RecordIterator getSymbolsByNameAndNamespace(String name, long id) throws IOException;

	/**
	 * Get the symbol Record with the given address, name, and namespace id or null if there is
	 * no match
	 * @param address the symbol address
	 * @param name the symbol name
	 * @param namespaceId the id of the parent namespace of the symbol
	 * @return a record that matches the address, name, and namespaceId or null if there is no match
	 * @throws IOException if a database io error occurs
	 */
	abstract DBRecord getSymbolRecord(Address address, String name, long namespaceId)
			throws IOException;

	/**
	 * Returns the maximum symbol address within the specified address space
	 * Intended for update use only
	 * @param space address space
	 * @return maximum symbol address within space or null if none are found
	 * @throws IOException if a database io error occurs
	 */
	abstract Address getMaxSymbolAddress(AddressSpace space) throws IOException;

	/**
	 * Returns the underlying symbol table (for upgrade use only)
	 * @return the database table for this adapter
	 */
	abstract Table getTable();

	/**
	 * Computes a hash value for a symbol that facilitates fast lookups of symbols given
	 * a name, namespace, and address. The hash is formed so that it can also be used for fast
	 * lookups of all symbols that have the same name and namespace regardless of address.
	 * @param name the symbol name
	 * @param namespaceID the namespace id
	 * @param addressKey the encoded address
	 * @return a database Long field containing the computed hash
	 */
	protected static LongField computeLocatorHash(String name, long namespaceID,
			long addressKey) {
		// Default functions have no name, no point in storing a hash for those.
		if (StringUtils.isEmpty(name)) {
			return null;
		}

		// store the name/namespace hash in upper 32 bits of the resulting hash and the 
		// addressKey's lower 32 bits in the lower 32 bits of the resulting hash
		long nameNamespaceHash = Objects.hash(name, namespaceID);
		long combinedHash = (nameNamespaceHash << 32) | (addressKey & 0xFFFFFFFFL);
		return new LongField(combinedHash);
	}

	// This wraps a record iterator to make sure it only returns records for symbols that match
	// the given name and name space.
	protected static RecordIterator getNameAndNamespaceFilterIterator(String name,
			long namespaceId, RecordIterator it) {
		Query nameQuery = new FieldMatchQuery(SYMBOL_NAME_COL, new StringField(name));
		Query namespaceQuery = new FieldMatchQuery(SYMBOL_PARENT_COL, new LongField(namespaceId));
		Query nameAndNamespaceQuery = new AndQuery(nameQuery, namespaceQuery);
		return new QueryRecordIterator(it, nameAndNamespaceQuery);
	}

	/**
	 * Wraps a record iterator to make sure it only returns records for symbols that match
	 * the given name and name space and address
	 * @param name the name of the symbol
	 * @param namespaceId the name space id of the symbol
	 * @param addressKey the address key of the symbol
	 * @param it the record iterator to wrap with the query
	 * @return a filtered RecordIterator that only returns records that match the name, name space,
	 * and address
	 */
	protected static RecordIterator getNameNamespaceAddressFilterIterator(String name,
			long namespaceId, long addressKey, RecordIterator it) {
		Query nameQuery = new FieldMatchQuery(SYMBOL_NAME_COL, new StringField(name));
		Query namespaceQuery = new FieldMatchQuery(SYMBOL_PARENT_COL, new LongField(namespaceId));
		Query addressQuery = new FieldMatchQuery(SYMBOL_ADDR_COL, new LongField(addressKey));
		Query nameAndNamespaceQuery = new AndQuery(nameQuery, namespaceQuery);
		Query fullQuery = new AndQuery(nameAndNamespaceQuery, addressQuery);
		return new QueryRecordIterator(it, fullQuery);
	}

	/**
	 * Wraps a record iterator to filter out any symbols that are not primary
	 * @param it the record iterator to wrap
	 * @return a record iterator that only returns primary symbols
	 */
	protected static RecordIterator getPrimaryFilterRecordIterator(RecordIterator it) {
		Query query = record -> !record.getFieldValue(SYMBOL_PRIMARY_COL).isNull();
		return new QueryRecordIterator(it, query);
	}

}
