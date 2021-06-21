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
import ghidra.program.model.address.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;

import db.*;

class BookmarkDBAdapterV0 extends BookmarkDBAdapter {

	private DBHandle tmpHandle;
	private BookmarkDBAdapter conversionAdapter;

	BookmarkDBAdapterV0(DBHandle dbHandle) {
		// ?
	}

	/**
	 * Set the old bookmark manager which handles read-only access
	 * to bookmarks stored within property maps.
	 * The old bookmark manager must be set prior to invoking any other method;
	 * @param oldMgr old bookmark manager
	 */
	void setOldBookmarkManager(OldBookmarkManager oldMgr, AddressMap addrMap, TaskMonitor monitor)
			throws IOException {

		// Convert old bookmarks to new schema using temporary database
		// This is the easiest way to index into the old bookmarks
		tmpHandle = new DBHandle();
		try {
			conversionAdapter =
				BookmarkDBAdapter.getAdapter(tmpHandle, DBConstants.CREATE, new int[0], addrMap,
					monitor);
		}
		catch (VersionException e) {
			throw new AssertException();
		}
		DBRecord[] oldTypes = oldMgr.getTypeRecords();
		if (oldTypes.length == 0) {
			return;
		}

		monitor.setMessage("Translating Old Bookmarks...");
		int max = 0;
		for (int i = 0; i < oldTypes.length; i++) {
			max +=
				oldMgr.getBookmarkCount(oldTypes[i].getString(BookmarkTypeDBAdapter.TYPE_NAME_COL));
		}
		monitor.initialize(max);
		int cnt = 0;

		for (int i = 0; i < oldTypes.length; i++) {
			String type = oldTypes[i].getString(BookmarkTypeDBAdapter.TYPE_NAME_COL);
			int typeId = (int) oldTypes[i].getKey();
			conversionAdapter.addType(typeId);
			AddressIterator iter = oldMgr.getBookmarkAddresses(type);
			while (iter.hasNext()) {
				if (monitor.isCancelled()) {
					throw new IOException("Upgrade Cancelled");
				}
				Address addr = iter.next();
				OldBookmark bm = oldMgr.getBookmark(addr, type);
				conversionAdapter.createBookmark(typeId, bm.getCategory(),
					addrMap.getKey(addr, true), bm.getComment());
				monitor.setProgress(++cnt);
			}
		}
	}

	@Override
	DBRecord getRecord(long id) throws IOException {
		return conversionAdapter.getRecord(id);
	}

	@Override
	RecordIterator getRecordsByTypeAndCategory(int typeId, String category) throws IOException {
		return conversionAdapter.getRecordsByTypeAndCategory(typeId, category);
	}

	@Override
	RecordIterator getRecordsByType(int typeId) throws IOException {
		return conversionAdapter.getRecordsByType(typeId);
	}

	@Override
	String[] getCategories(int typeId) throws IOException {
		return conversionAdapter.getCategories(typeId);
	}

	@Override
	AddressSetView getBookmarkAddresses(int typeId) throws IOException {
		return conversionAdapter.getBookmarkAddresses(typeId);
	}

	@Override
	protected void finalize() throws Throwable {
		if (tmpHandle != null) {
			tmpHandle.close();
			tmpHandle = null;
		}
	}

	@Override
	int getBookmarkCount(int typeId) {
		return conversionAdapter.getBookmarkCount(typeId);
	}

	@Override
	int getBookmarkCount() {
		return conversionAdapter.getBookmarkCount();
	}

	@Override
	RecordIterator getRecordsByTypeAtAddress(int typeId, long address) throws IOException {
		return conversionAdapter.getRecordsByTypeAtAddress(typeId, address);
	}

	@Override
	RecordIterator getRecordsByTypeStartingAtAddress(int typeID, long startAddress, boolean forward)
			throws IOException {
		throw new UnsupportedOperationException(); // they tell me that this class is too old to care
	}

	@Override
	RecordIterator getRecordsByTypeForAddressRange(int typeId, long startAddr, long endAddr)
			throws IOException {
		return conversionAdapter.getRecordsByTypeForAddressRange(typeId, startAddr, endAddr);
	}
}
