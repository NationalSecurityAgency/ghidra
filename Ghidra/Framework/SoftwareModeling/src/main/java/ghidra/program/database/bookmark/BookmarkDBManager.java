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

import java.awt.Color;
import java.io.IOException;
import java.util.*;

import javax.swing.ImageIcon;

import org.apache.commons.lang3.StringUtils;

import db.*;
import db.util.ErrorHandler;
import generic.util.*;
import ghidra.program.database.*;
import ghidra.program.database.map.AddressIndexPrimaryKeyIterator;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.util.DatabaseTableUtils;
import ghidra.program.database.util.EmptyRecordIterator;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.ChangeManager;
import ghidra.util.Lock;
import ghidra.util.datastruct.ObjectArray;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class BookmarkDBManager implements BookmarkManager, ErrorHandler, ManagerDB {

	private ProgramDB program;

	private AddressMap addrMap;
	private BookmarkTypeDBAdapter bookmarkTypeAdapter;
	private BookmarkDBAdapter bookmarkAdapter;
	private DBObjectCache<BookmarkDB> cache;

	private boolean upgrade = false;

	private Map<String, BookmarkType> typesByName = new TreeMap<String, BookmarkType>();
	private ObjectArray typesArray = new ObjectArray();
	private Lock lock;

	/**
	 * Constructs a new CodeManager for a program.
	 * @param handle handle to database
	 * @param addrMap addressMap to convert between addresses and long values.
	 * @param openMode either READ_ONLY, UPDATE, or UPGRADE
	 * @param lock the program synchronization lock
	 * @param monitor the task monitor use while upgrading.
	 * @throws VersionException if the database is incompatible with the current
	 * schema
	 * @throws IOException if there is a problem accessing the database.
	 */
	public BookmarkDBManager(DBHandle handle, AddressMap addrMap, int openMode, Lock lock,
			TaskMonitor monitor) throws VersionException, IOException {
		this.addrMap = addrMap;
		this.lock = lock;
		upgrade = (openMode == DBConstants.UPGRADE);
		bookmarkTypeAdapter = BookmarkTypeDBAdapter.getAdapter(handle, openMode);
		int[] types = bookmarkTypeAdapter.getTypeIds();
		bookmarkAdapter = BookmarkDBAdapter.getAdapter(handle, openMode, types, addrMap, monitor);
		cache = new DBObjectCache<BookmarkDB>(100);
	}

	@Override
	public void setProgram(ProgramDB program) {
		if (this.program != null) {
			throw new AssertException();
		}
		this.program = program;

		try {
			if (upgrade) {
				upgradeOldBookmarks(program);
			}
			else if (bookmarkTypeAdapter instanceof BookmarkTypeDBAdapterNoTable &&
				bookmarkAdapter instanceof BookmarkDBAdapterV0) {
				// Old bookmarks were stored as user properties
				OldBookmarkManager oldMgr = new OldBookmarkManager(program);
				((BookmarkTypeDBAdapterNoTable) bookmarkTypeAdapter).setOldBookmarkManager(oldMgr);
				((BookmarkDBAdapterV0) bookmarkAdapter).setOldBookmarkManager(oldMgr, addrMap,
					TaskMonitor.DUMMY);
			}

			DBRecord[] typeRecords = bookmarkTypeAdapter.getRecords();
			for (DBRecord rec : typeRecords) {
				int typeId = (int) rec.getKey();
				BookmarkTypeDB type =
					new BookmarkTypeDB(typeId, rec.getString(BookmarkTypeDBAdapter.TYPE_NAME_COL));
				type.setHasBookmarks(true);
				typesByName.put(type.getTypeString(), type);
				typesArray.put(typeId, type);
			}
		}
		catch (IOException e) {
			dbError(e);
		}
	}

	@Override
	public void programReady(int openMode, int currentRevision, TaskMonitor monitor)
			throws IOException, CancelledException {
		// Nothing to do
	}

	/*
	 * @see ghidra.util.ErrorHandler#dbError(java.io.IOException)
	 */
	@Override
	public void dbError(IOException e) {
		program.dbError(e);
	}

	/**
	 * Invalidate cached objects held by this manager.
	 */
	@Override
	public void invalidateCache(boolean all) {
		lock.acquire();
		try {
			cache.invalidate();
			bookmarkAdapter.reloadTables();
			refreshBookmarkTypes();
		}
		finally {
			lock.release();
		}
	}

	private void refreshBookmarkTypes() {
		Iterator<BookmarkType> it = typesByName.values().iterator();
		while (it.hasNext()) {
			BookmarkTypeDB type = (BookmarkTypeDB) it.next();
			type.setHasBookmarks(bookmarkAdapter.hasTable(type.getTypeId()));
		}
	}

	/**
	 * Update stored bookmark and fire program change event for a bookmark which has
	 * had its category or comment changed.  All other fields are immutable.
	 * @param bm bookmark
	 */
	void bookmarkChanged(BookmarkDB bm) {
		lock.acquire();
		try {
			DBRecord rec = bm.getRecord();
			if (rec != null) {
				bookmarkAdapter.updateRecord(rec);
				Address addr = bm.getAddress();
				program.setObjChanged(ChangeManager.DOCR_BOOKMARK_CHANGED, addr, bm, null, null);

			}
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
	}

	/*
	 * Upgrade old property-based bookmarks to the new storage schema.
	 */
	private void upgradeOldBookmarks(ProgramDB programDB) {

		OldBookmarkManager oldMgr = new OldBookmarkManager(programDB);
		DBRecord[] oldTypes = oldMgr.getTypeRecords();
		if (oldTypes.length == 0) {
			return;
		}
		for (DBRecord oldType : oldTypes) {
			String type = oldType.getString(BookmarkTypeDBAdapter.TYPE_NAME_COL);
			AddressIterator iter = oldMgr.getBookmarkAddresses(type);
			while (iter.hasNext()) {
				OldBookmark bm = oldMgr.getBookmark(iter.next(), type);
				setBookmark(bm.getAddress(), type, bm.getCategory(), bm.getComment());
			}
			oldMgr.removeAllBookmarks(type);
		}
	}

	/*
	 * Get or create bookmark type
	 */
	private BookmarkTypeDB getBookmarkType(String type, boolean create) throws IOException {
		BookmarkTypeDB bmt = (BookmarkTypeDB) typesByName.get(type);
		if (bmt == null) {
			int typeId = findNextTypeId();
			bmt = new BookmarkTypeDB(typeId, type);
			typesByName.put(type, bmt);
			typesArray.put(typeId, bmt);
		}
		if (create && !bmt.hasBookmarks()) {
			bookmarkTypeAdapter.addType(bmt.getTypeId(), bmt.getTypeString());
			bmt.setHasBookmarks(true);
			bookmarkAdapter.addType(bmt.getTypeId());

			// fire event
			program.setObjChanged(ChangeManager.DOCR_BOOKMARK_TYPE_ADDED, bmt, null, null);

		}
		return bmt;
	}

	private int findNextTypeId() {
		int n = typesArray.getLastNonEmptyIndex() + 2;
		for (int i = 0; i < n; i++) {
			if (typesArray.get(i) == null) {
				return i;
			}
		}
		return n;
	}

	/*
	 * Get existing bookmark type
	 */
	BookmarkTypeDB getBookmarkType(int typeID) {
		return (BookmarkTypeDB) typesArray.get(typeID);
	}

	@Override
	public BookmarkType defineType(String type, ImageIcon icon, Color color, int priority) {
		lock.acquire();
		try {
			String validatedType = StringUtils.trim(type);
			if (StringUtils.isBlank(validatedType) || icon == null || color == null) {
				throw new IllegalArgumentException(
					"Invalid bookmark type parameters were specified");
			}

			BookmarkTypeDB bmt = null;
			try {
				bmt = getBookmarkType(validatedType, false);
				bmt.setIcon(icon);
				bmt.setMarkerColor(color);
				bmt.setMarkerPriority(priority);
			}
			catch (IOException e) {
				dbError(e);
			}
			return bmt;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public BookmarkType[] getBookmarkTypes() {
		lock.acquire();
		try {
			Collection<BookmarkType> c = typesByName.values();
			BookmarkTypeDB[] bmTypes = new BookmarkTypeDB[c.size()];
			c.toArray(bmTypes);
			return bmTypes;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Program getProgram() {
		return program;
	}

	@Override
	public BookmarkType getBookmarkType(String type) {
		return typesByName.get(type);
	}

	@Override
	public Bookmark setBookmark(Address addr, String type, String category, String comment) {
		lock.acquire();
		try {
			BookmarkTypeDB bmt = getBookmarkType(type, true);
			int typeId = bmt.getTypeId();
			BookmarkDB bm = (BookmarkDB) getBookmark(addr, type, category);
			if (bm != null) {
				bm.setComment(comment);
			}
			else {
				DBRecord rec = bookmarkAdapter.createBookmark(typeId, category,
					addrMap.getKey(addr, true), comment);
				bm = new BookmarkDB(this, cache, rec);

				// fire event
				program.setObjChanged(ChangeManager.DOCR_BOOKMARK_ADDED, addr, bm, null, null);
			}
			return bm;
		}
		catch (IOException e) {
			dbError(e);

		}
		finally {
			lock.release();
		}
		return null;
	}

	private BookmarkDB getBookmark(DBRecord bookmarkRecord) {
		BookmarkDB bm = cache.get(bookmarkRecord);
		if (bm == null) {
			bm = new BookmarkDB(this, cache, bookmarkRecord);
		}
		return bm;
	}

	@Override
	public Bookmark getBookmark(Address addr, String type, String category) {
		lock.acquire();
		try {
			BookmarkTypeDB bmt = getBookmarkType(type, false);
			if (bmt != null && bmt.hasBookmarks() && category != null) {
				int typeId = bmt.getTypeId();
				RecordIterator iter =
					bookmarkAdapter.getRecordsByTypeAtAddress(typeId, addrMap.getKey(addr, false));
				while (iter.hasNext()) {
					DBRecord rec = iter.next();
					String cat = rec.getString(BookmarkDBAdapter.CATEGORY_COL);
					if (category.equals(cat)) {
						return getBookmark(rec);
					}
				}
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	@Override
	public void removeBookmark(Bookmark bookmark) {
		lock.acquire();
		try {
			if (bookmark instanceof BookmarkDB) {
				BookmarkDB bm = (BookmarkDB) bookmark;
				BookmarkTypeDB type = (BookmarkTypeDB) bm.getType();
				int typeId = type.getTypeId();
				doRemoveBookmark(bm);
				if (bookmarkAdapter.getBookmarkCount(typeId) == 0) {
					removeBookmarks(type.getTypeString());
				}
			}
		}
		finally {
			lock.release();
		}
	}

	private void doRemoveBookmark(BookmarkDB bm) {
		Address addr = bm.getAddress();
		bm.setInvalid();
		try {
			bookmarkAdapter.deleteRecord(bm.getId());
			// fire event
			program.setObjChanged(ChangeManager.DOCR_BOOKMARK_REMOVED, addr, bm, null, null);
		}
		catch (IOException e) {
			dbError(e);
		}

	}

	@Override
	public void removeBookmarks(String type) {
		lock.acquire();
		try {

			boolean isSpecificType = type != null && type != BookmarkType.ALL_TYPES;
			if (!isSpecificType) {
				// no type specified; remove all
				Iterator<String> iter = typesByName.keySet().iterator();
				while (iter.hasNext()) {
					removeBookmarks(iter.next());
				}
				return;
			}

			try {
				BookmarkTypeDB bmt = (BookmarkTypeDB) typesByName.get(type);
				if (bmt.hasBookmarks()) {
					int typeId = bmt.getTypeId();
					bookmarkAdapter.deleteType(typeId);
					bookmarkTypeAdapter.deleteRecord(typeId);
					bmt.setHasBookmarks(false);
					program.setObjChanged(ChangeManager.DOCR_BOOKMARK_TYPE_REMOVED, bmt, null,
						null);
				}
			}
			catch (IOException e) {
				dbError(e);
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void removeBookmarks(String type, String category, TaskMonitor monitor)
			throws CancelledException {
		lock.acquire();
		try {
			BookmarkType bmt = getBookmarkType(type);
			if (bmt == null || !bmt.hasBookmarks()) {
				return;
			}
			RecordIterator iter =
				bookmarkAdapter.getRecordsByTypeAndCategory(bmt.getTypeId(), category);
			while (iter.hasNext()) {
				DBRecord rec = iter.next();
				BookmarkDB bm = getBookmark(rec);
				removeBookmark(bm);
				monitor.checkCanceled();
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Get address from index.
	 * @param index address index
	 * @return address
	 */
	Address getAddress(long index) {
		return addrMap.decodeAddress(index);
	}

	/**
	 * Get bookmark record (used by Bookmark.refresh() method)
	 * @param id bookmark ID
	 * @return bookmark record
	 */
	DBRecord getRecord(long id) {
		DBRecord rec = null;
		try {
			rec = bookmarkAdapter.getRecord(id);
		}
		catch (IOException e) {
			dbError(e);
		}
		return rec;
	}

	@Override
	public Bookmark[] getBookmarks(Address addr) {
		lock.acquire();
		try {
			int n = typesArray.getLastNonEmptyIndex();
			List<Bookmark> list = new ArrayList<Bookmark>();
			for (int i = 0; i <= n; i++) {
				BookmarkTypeDB bmt = (BookmarkTypeDB) typesArray.get(i);
				if (bmt != null && bmt.hasBookmarks()) {
					getBookmarks(addr, i, list);
				}
			}
			Bookmark[] bookmarks = new Bookmark[list.size()];
			list.toArray(bookmarks);
			return bookmarks;
		}
		finally {
			lock.release();
		}
	}

	private void getBookmarks(Address addr, int typeId, List<Bookmark> list) {
		if (typeId < 0) {
			return;
		}
		try {
			RecordIterator iter =
				bookmarkAdapter.getRecordsByTypeAtAddress(typeId, addrMap.getKey(addr, false));
			while (iter.hasNext()) {
				DBRecord rec = iter.next();
				list.add(getBookmark(rec));
			}
		}
		catch (IOException e) {
			dbError(e);
		}
	}

	@Override
	public Bookmark[] getBookmarks(Address address, String type) {
		lock.acquire();
		try {
			Bookmark[] bookmarks = null;
			List<Bookmark> list = new ArrayList<Bookmark>();
			BookmarkType bmt = getBookmarkType(type);
			if (bmt != null && bmt.hasBookmarks()) {
				getBookmarks(address, bmt.getTypeId(), list);
			}
			bookmarks = new Bookmark[list.size()];
			list.toArray(bookmarks);
			return bookmarks;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean hasBookmarks(String type) {
		lock.acquire();
		try {
			BookmarkType bmt = getBookmarkType(type);
			if (bmt == null) {
				return false;
			}
			return bmt.hasBookmarks();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public String[] getCategories(String type) {
		lock.acquire();
		try {
			BookmarkType bmt = getBookmarkType(type);
			if (bmt == null || !bmt.hasBookmarks()) {
				return new String[0];
			}
			try {
				return bookmarkAdapter.getCategories(bmt.getTypeId());
			}
			catch (IOException e) {
				dbError(e);
			}
			return null;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public AddressSetView getBookmarkAddresses(String type) {
		lock.acquire();
		try {
			BookmarkType bmt = getBookmarkType(type);
			if (bmt == null || !bmt.hasBookmarks()) {
				return new AddressSet();
			}
			try {
				return bookmarkAdapter.getBookmarkAddresses(bmt.getTypeId());
			}
			catch (IOException e) {
				dbError(e);
			}
			return null;
		}
		finally {
			lock.release();
		}
	}

	private Iterator<Bookmark> getBookmarksIterator(BookmarkType bmt) {
		RecordIterator it;
		try {
			if (bmt != null && bmt.hasBookmarks()) {
				it = bookmarkAdapter.getRecordsByType(bmt.getTypeId());
			}
			else {
				it = new EmptyRecordIterator();
			}
		}
		catch (IOException e) {
			program.dbError(e);
			it = new EmptyRecordIterator();
		}
		return new BookmarkRecordIterator(it);
	}

	private Iterator<Bookmark> getBookmarksIterator(Address startAddress, BookmarkType bmt,
			boolean forward) {
		RecordIterator it;
		try {
			if (bmt != null && bmt.hasBookmarks()) {
				it = bookmarkAdapter.getRecordsByTypeStartingAtAddress(bmt.getTypeId(),
					addrMap.getKey(startAddress, false), forward);
			}
			else {
				it = new EmptyRecordIterator();
			}
		}
		catch (IOException e) {
			program.dbError(e);
			it = new EmptyRecordIterator();
		}

		return new BookmarkRecordIterator(it, forward);
	}

	@Override
	public Bookmark getBookmark(long id) {
		lock.acquire();
		try {
			BookmarkDB bm = cache.get(id);
			if (bm == null) {
				DBRecord record = bookmarkAdapter.getRecord(id);
				if (record == null) {
					return null;
				}
				bm = new BookmarkDB(this, cache, record);
			}
			return bm;
		}
		catch (ClosedException e) {
			return null;
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	@Override
	public int getBookmarkCount() {
		lock.acquire();
		try {
			return bookmarkAdapter.getBookmarkCount();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public int getBookmarkCount(String type) {
		lock.acquire();
		try {
			BookmarkType bmt = getBookmarkType(type);
			if (bmt == null) {
				return 0;
			}
			return bookmarkAdapter.getBookmarkCount(bmt.getTypeId());
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Iterator<Bookmark> getBookmarksIterator(String type) {
		BookmarkType bmt = getBookmarkType(type);
		return getBookmarksIterator(bmt);
	}

	@Override
	public Iterator<Bookmark> getBookmarksIterator(Address startAddress, boolean forward) {

		List<PeekableIterator<Bookmark>> list = new ArrayList<PeekableIterator<Bookmark>>();
		int n = typesArray.getLastNonEmptyIndex();
		for (int i = 0; i <= n; i++) {
			BookmarkTypeDB bmt = (BookmarkTypeDB) typesArray.get(i);
			if (bmt != null && bmt.hasBookmarks()) {
				Iterator<Bookmark> bookmarksIterator =
					getBookmarksIterator(startAddress, bmt, forward);
				list.add(new WrappingPeekableIterator<Bookmark>(bookmarksIterator));
			}
		}

		return new MultiIterator<Bookmark>(list, forward);
	}

	@Override
	public Iterator<Bookmark> getBookmarksIterator() {
		lock.acquire();
		try {
			return new TotalIterator();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void removeBookmarks(AddressSetView set, TaskMonitor monitor) throws CancelledException {
		lock.acquire();
		try {
			Iterator<BookmarkType> it = typesByName.values().iterator();
			while (it.hasNext()) {
				BookmarkTypeDB bt = (BookmarkTypeDB) it.next();
				if (bt.hasBookmarks()) {
					removeBookmarks(set, bt, null, monitor);
				}
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void removeBookmarks(AddressSetView set, String type, TaskMonitor monitor)
			throws CancelledException {
		lock.acquire();
		try {
			BookmarkTypeDB bmt = (BookmarkTypeDB) getBookmarkType(type);
			if (bmt != null && bmt.hasBookmarks()) {
				removeBookmarks(set, bmt, null, monitor);
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void removeBookmarks(AddressSetView set, String type, String category,
			TaskMonitor monitor) throws CancelledException {
		lock.acquire();
		try {
			BookmarkTypeDB bmt = (BookmarkTypeDB) getBookmarkType(type);
			if (bmt != null && bmt.hasBookmarks()) {
				removeBookmarks(set, bmt, category, monitor);
			}
		}
		finally {
			lock.release();
		}
	}

	private void removeBookmarks(AddressSetView set, BookmarkTypeDB bmt, String category,
			TaskMonitor monitor) throws CancelledException {
		int typeId = bmt.getTypeId();
		try {
			Table table = bookmarkAdapter.getTable(typeId);
			if (table != null) {
				DBFieldIterator it = new AddressIndexPrimaryKeyIterator(table,
					BookmarkDBAdapter.ADDRESS_COL, addrMap, set, true);
				while (it.hasNext()) {
					BookmarkDB bm = (BookmarkDB) getBookmark(it.next().getLongValue());
					if (category == null || category.equals(bm.getCategory())) {
						doRemoveBookmark(bm);
					}
					monitor.checkCanceled();
				}
				if (bookmarkAdapter.getBookmarkCount(typeId) == 0) {
					removeBookmarks(bmt.getTypeString());
				}

			}
		}
		catch (IOException e) {
			dbError(e);
		}
	}

	@Override
	public void deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
		removeBookmarks(new AddressSet(startAddr, endAddr), monitor);
	}

	@Override
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException {
		lock.acquire();
		try {
			cache.invalidate();
			Iterator<BookmarkType> it = typesByName.values().iterator();
			while (it.hasNext()) {
				BookmarkTypeDB bt = (BookmarkTypeDB) it.next();
				int typeId = bt.getTypeId();
				if (bt.hasBookmarks()) {
					Table table = bookmarkAdapter.getTable(typeId);
					if (table == null) {
						continue;
					}
					int addrCol = BookmarkDBAdapter.ADDRESS_COL;
					try {
						DatabaseTableUtils.updateIndexedAddressField(table, addrCol, addrMap,
							fromAddr, toAddr, length, null, monitor);
					}
					catch (IOException e) {
						dbError(e);
					}
				}
			}
		}
		finally {
			lock.release();
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class BookmarkRecordIterator implements Iterator<Bookmark> {
		private RecordIterator it;
		private Bookmark nextBookmark;
		private boolean forward;

		BookmarkRecordIterator(RecordIterator it) {
			this(it, true);
		}

		BookmarkRecordIterator(RecordIterator it, boolean forward) {
			this.it = it;
			this.forward = forward;
		}

		@Override
		public boolean hasNext() {
			if (nextBookmark == null) {
				findNext();
			}

			return nextBookmark != null;
		}

		private void findNext() {
			lock.acquire();
			try {
				while (nextBookmark == null && (forward ? it.hasNext() : it.hasPrevious())) {
					DBRecord record = forward ? it.next() : it.previous();
					nextBookmark = getBookmark(record);
				}
			}
			catch (IOException ioe) {
				// do nothing; the nextBookmark will not be set and we will return false for hasNext()
			}
			finally {
				lock.release();
			}
		}

		@Override
		public Bookmark next() {
			if (hasNext()) {
				Bookmark ret = nextBookmark;
				nextBookmark = null;
				return ret;
			}
			return null;
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}
	}

	private class TotalIterator implements Iterator<Bookmark> {
		Iterator<BookmarkTypeDB> typeIt;
		Iterator<Bookmark> bookmarkIt;

		TotalIterator() {
			List<BookmarkTypeDB> list = new ArrayList<BookmarkTypeDB>();
			int n = typesArray.getLastNonEmptyIndex();
			for (int i = 0; i <= n; i++) {
				BookmarkTypeDB bmt = (BookmarkTypeDB) typesArray.get(i);
				if (bmt != null && bmt.hasBookmarks()) {
					list.add(bmt);
				}
			}
			typeIt = list.iterator();
		}

		@Override
		public boolean hasNext() {
			if (bookmarkIt != null && bookmarkIt.hasNext()) {
				return true;
			}
			while (typeIt.hasNext()) {
				bookmarkIt = getBookmarksIterator(typeIt.next());
				if (bookmarkIt != null && bookmarkIt.hasNext()) {
					return true;
				}
			}
			return false;
		}

		@Override
		public Bookmark next() {
			return hasNext() ? bookmarkIt.next() : null;
		}

		@Override
		public void remove() {
			bookmarkIt.remove();
		}

	}

}
