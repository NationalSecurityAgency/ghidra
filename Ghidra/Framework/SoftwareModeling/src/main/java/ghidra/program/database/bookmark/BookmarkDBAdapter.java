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
package ghidra.program.database.bookmark;

import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;

import db.*;

abstract class BookmarkDBAdapter {
	static final Schema SCHEMA = BookmarkDBAdapterV3.V3_SCHEMA;

	static final int ADDRESS_COL = BookmarkDBAdapterV3.V3_ADDRESS_COL;
	static final int CATEGORY_COL = BookmarkDBAdapterV3.V3_CATEGORY_COL;
	static final int COMMENT_COL = BookmarkDBAdapterV3.V3_COMMENT_COL;

	static final String BOOKMARK_TABLE_NAME = "Bookmarks";

	static BookmarkDBAdapter getAdapter(DBHandle dbHandle, int openMode, int[] typeIds,
			AddressMap addrMap, TaskMonitor monitor) throws VersionException, IOException {

		if (openMode == DBConstants.CREATE) {
			return new BookmarkDBAdapterV3(dbHandle, true, typeIds, addrMap);
		}

		try {
			BookmarkDBAdapter adapter = new BookmarkDBAdapterV3(dbHandle, false, typeIds, addrMap);
			if (addrMap.isUpgraded()) {
				throw new VersionException(true);
			}
			return adapter;
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			BookmarkDBAdapter adapter = findReadOnlyAdapter(dbHandle, addrMap, typeIds);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(dbHandle, adapter, typeIds, addrMap, monitor);
			}
			return adapter;
		}
	}

	private static BookmarkDBAdapter findReadOnlyAdapter(DBHandle dbHandle, AddressMap addrMap,
			int[] typeIds) throws IOException {
		try {
			return new BookmarkDBAdapterV3(dbHandle, false, typeIds, addrMap.getOldAddressMap());
		}
		catch (VersionException e) {
			// rollback to version 2
		}

		try {
			return new BookmarkDBAdapterV2(dbHandle, addrMap);
		}
		catch (VersionException e) {
			// rollback to version 1
		}

		try {
			return new BookmarkDBAdapterV1(dbHandle, addrMap);
		}
		catch (VersionException e1) {
			// rollback to version 0
		}

		return new BookmarkDBAdapterV0(dbHandle);
	}

	private static BookmarkDBAdapter upgrade(DBHandle dbHandle, BookmarkDBAdapter oldAdapter,
			int[] typeIds, AddressMap addrMap, TaskMonitor monitor) throws VersionException,
			IOException {

		if (oldAdapter instanceof BookmarkDBAdapterV0) {
			// Actually upgrade from Version 0 delayed until BookmarkDBManager.setProgram is invoked
			return new BookmarkDBAdapterV3(dbHandle, true, typeIds, addrMap);
		}

		if (!(oldAdapter instanceof BookmarkDBAdapterV1)) {
			dbHandle.deleteTable(BOOKMARK_TABLE_NAME);
		}

		monitor.setMessage("Upgrading Bookmarks...");
		monitor.initialize(2 * oldAdapter.getBookmarkCount());
		int cnt = 0;

		AddressMap oldAddrMap = addrMap.getOldAddressMap();

		DBHandle tmpHandle = new DBHandle();
		long id = tmpHandle.startTransaction();
		BookmarkDBAdapter tmpAdapter = null;
		try {
			tmpAdapter = new BookmarkDBAdapterV3(tmpHandle, true, typeIds, addrMap);
			for (int i = 0; i < typeIds.length; i++) {
				RecordIterator it = oldAdapter.getRecordsByType(typeIds[i]);
				while (it.hasNext()) {
					if (monitor.isCancelled()) {
						throw new IOException("Upgrade Cancelled");
					}
					DBRecord rec = it.next();
					int typeId = getTypeId(rec);
					tmpAdapter.addType(typeId);
					Address addr = oldAddrMap.decodeAddress(rec.getLongValue(ADDRESS_COL));
					tmpAdapter.createBookmark(typeId, rec.getString(CATEGORY_COL),
						addrMap.getKey(addr, true), rec.getString(COMMENT_COL));
					monitor.setProgress(++cnt);
				}
			}
			dbHandle.deleteTable(BOOKMARK_TABLE_NAME);
			for (int i = 0; i < typeIds.length; i++) {
				dbHandle.deleteTable(BOOKMARK_TABLE_NAME + typeIds[i]);
			}
			BookmarkDBAdapter newAdapter =
				new BookmarkDBAdapterV3(dbHandle, true, typeIds, addrMap);
			for (int i = 0; i < typeIds.length; i++) {
				RecordIterator it = tmpAdapter.getRecordsByType(typeIds[i]);
				while (it.hasNext()) {
					if (monitor.isCancelled()) {
						throw new IOException("Upgrade Cancelled");
					}
					DBRecord rec = it.next();
					newAdapter.updateRecord(rec);
					monitor.setProgress(++cnt);
				}
			}
			return newAdapter;
		}
		finally {
			tmpHandle.endTransaction(id, true);
			tmpHandle.close();
		}
	}

	static int getTypeId(DBRecord rec) {
		long key = rec.getKey();
		return (int) (key >> 48);
	}

	static String mangleTypeCategory(long typeId, String category) {
		if (category == null) {
			category = "";
		}
		return typeId + "/" + category;
	}

	static String demangleTypeCategory(String typeCategory) {
		int ix = typeCategory.indexOf("/");
		if (ix < 0) {
			// Bad data - should not happen
			return typeCategory;
		}
		return typeCategory.substring(ix + 1);
	}

	/**
	 * Create a new bookmark record
	 * @param typeId
	 * @param category
	 * @param index
	 * @param comment
	 * @return
	 * @throws IOException 
	 */
	DBRecord createBookmark(int typeId, String category, long index, String comment)
			throws IOException {
		throw new UnsupportedOperationException("Bookmarks are read-only and may not be created");
	}

	/**
	 * Update the database with the specified bookmark record
	 * @param rec modified bookmark record
	 * @throws IOException
	 */
	void updateRecord(DBRecord rec) throws IOException {
		throw new UnsupportedOperationException("Bookmarks are read-only and may not be modified");
	}

	/**
	 * Delete a specific bookmark
	 * @param id bookmark ID / key
	 * @throws IOException
	 */
	void deleteRecord(long id) throws IOException {
		throw new UnsupportedOperationException("Bookmarks are read-only and may not be deleted");
	}

	/**
	 * Get the bookmark record corresponding to the specified bookmark ID.
	 * @param id bookmark ID
	 * @return bookmark record or null if not found.
	 */
	abstract DBRecord getRecord(long id) throws IOException;

	/**
	 * Get all bookmark records associated with a specific type and address.
	 * @param index address index
	 * @return record iterator
	 */
	abstract RecordIterator getRecordsByTypeAtAddress(int typeId, long address) throws IOException;

	abstract RecordIterator getRecordsByTypeStartingAtAddress(int typeID, long startAddress,
			boolean forward) throws IOException;

	abstract RecordIterator getRecordsByTypeForAddressRange(int typeId, long startAddr, long endAddr)
			throws IOException;

	/**
	 * Get all bookmark records with a specific type ID and category.
	 * @param typeId bookmark type ID (required)
	 * @param category type category or null for all categories
	 * @return record iterator
	 */
	abstract RecordIterator getRecordsByTypeAndCategory(int typeId, String category)
			throws IOException;

	/**
	 * Returns iterator over all bookmark records.
	 */
	abstract RecordIterator getRecordsByType(int typeId) throws IOException;

	/**
	 * Get list of all known categories for the specified bookmark type.
	 * Categories are sorted in ascending order.
	 * 
	 * @param typeId bookmark type ID
	 * @return list of category strings
	 */
	abstract String[] getCategories(int typeId) throws IOException;

	/**
	 * Get set of addresses where bookmarks of the specified type and category
	 * exist.
	 * 
	 * @param typeId bookmark type ID (required)
	 * @param addrMap address map
	 * @return address set
	 */
	abstract AddressSetView getBookmarkAddresses(int typeId) throws IOException;

	abstract int getBookmarkCount(int typeId);

	abstract int getBookmarkCount();

//==================================================================================================
// V3 and Newer Methods
//	
//	These methods are only used by the V3 adapter.  Older adapters did not support separate type
//	tables.  Further, the older versions are so old that we no longer support them and thus, these
//	methods should not get called.  So, we stub them out here, to save us from having to put them
//	in each of the older versions, which is the normal way of building the base, abstract adapter.
//==================================================================================================	

	/**
	 * Creates a new bookmark type.
	 * 
	 * @param typeID The new ID of the bookmark type
	 * @throws IOException if there is a problem creating the new table.
	 */
	void addType(int typeID) throws IOException {
		throw new UnsupportedOperationException();
	}

	/**
	 * Deletes the table associated with the given bookmark type.
	 * 
	 * @param typeID The ID of the existing bookmark type
	 * @throws IOException if there is a problem deleting the existing table.
	 */
	void deleteType(int typeID) throws IOException {
		throw new UnsupportedOperationException();
	}

	/**
	 * Returns true if a table exists for the given bookmark type ID.
	 * 
	 * @param typeID The bookmark type ID of the table in question.
	 * @return true if a table exists for the given bookmark type ID.
	 */
	boolean hasTable(int typeID) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Returns the table for the given bookmark type ID
	 * 
	 * @param typeID the bookmark type ID for which to get a table
	 * @return the table for the given bookmark type ID
	 */
	Table getTable(int typeID) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Reloads the tables from the database.
	 */
	void reloadTables() {
		throw new UnsupportedOperationException();
	}
}
