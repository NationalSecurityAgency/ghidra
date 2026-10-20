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

import javax.swing.Icon;

import org.apache.commons.lang3.StringUtils;

import db.*;
import db.util.ErrorHandler;
import generic.theme.GIcon;
import generic.util.*;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.*;
import ghidra.program.database.map.AddressIndexPrimaryKeyIterator;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.util.DatabaseTableUtils;
import ghidra.program.database.util.EmptyRecordIterator;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramEvent;
import ghidra.util.Lock;
import ghidra.util.Lock.Closeable;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class BookmarkDBManager implements BookmarkManager, ErrorHandler, ManagerDB {
	final static Icon DEFAULT_ICON = new GIcon("icon.plugin.bookmark.type.default");

	private ProgramDB program;

	private AddressMap addrMap;
	private BookmarkTypeDBAdapter bookmarkTypeAdapter;
	private BookmarkDBAdapter bookmarkAdapter;
	private DbCache<BookmarkDB> cache;
	private BookmarkTypes bookmarkTypes;

	private boolean upgrade = false;

	protected Lock lock;

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
	public BookmarkDBManager(DBHandle handle, AddressMap addrMap, OpenMode openMode, Lock lock,
			TaskMonitor monitor) throws VersionException, IOException {
		this.addrMap = addrMap;
		this.lock = lock;
		upgrade = (openMode == OpenMode.UPGRADE);
		bookmarkTypeAdapter = BookmarkTypeDBAdapter.getAdapter(handle, openMode);
		int[] types = bookmarkTypeAdapter.getTypeIds();
		bookmarkAdapter = BookmarkDBAdapter.getAdapter(handle, openMode, types, addrMap, monitor);
		cache = new DbCache<>(new BookmarkFactory(), lock, 100);
		bookmarkTypes = new BookmarkTypes();
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
				type.setHasBookmarks(bookmarkAdapter.hasTable(typeId));
				bookmarkTypes.addBookmarkType(type);
			}
		}
		catch (IOException e) {
			dbError(e);
		}
	}

	@Override
	public void programReady(OpenMode openMode, int currentRevision, TaskMonitor monitor)
			throws IOException, CancelledException {
		// Nothing to do
	}

	@Override
	public void dbError(IOException e) {
		program.dbError(e);
	}

	/**
	 * Invalidate cached objects held by this manager.
	 */
	@Override
	public void invalidateCache(boolean all) {
		try (Closeable c = lock.write()) {
			cache.invalidate();
			bookmarkAdapter.reloadTables();
			refreshBookmarkTypes();
		}
	}

	private void refreshBookmarkTypes() {
		for (BookmarkTypeDB type : bookmarkTypes.getAllTypes()) {
			type.setHasBookmarks(bookmarkAdapter.hasTable(type.getTypeId()));
		}
	}

	/**
	 * Update stored bookmark and fire program change event for a bookmark which has
	 * had its category or comment changed.  All other fields are immutable.
	 * @param bm bookmark
	 */
	void bookmarkChanged(BookmarkDB bm) {
		try {
			DBRecord rec = bm.getRecord();
			if (rec != null) {
				bookmarkAdapter.updateRecord(rec);
				Address addr = bm.getAddress();
				program.setObjChanged(ProgramEvent.BOOKMARK_CHANGED, addr, bm, null, null);

			}
		}
		catch (IOException e) {
			dbError(e);
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

	/**
	 * Get or create a bookmark type with the given name. This method should only be called while
	 * holding the program's write lock.
	 * @param typeName the name of the type.
	 * @param createInDatabase if true, create a record in the database for this new type. 
	 * Otherwise, create a bookmark type without a corresponding record.
	 * @return a new or existing bookmark type with the given name.
	 * @throws IOException if an I/O error occurs trying to write to the database
	 */
	private BookmarkTypeDB getBookmarkType(String typeName, boolean createInDatabase)
			throws IOException {
		BookmarkTypeDB bmt = bookmarkTypes.get(typeName);
		if (bmt == null) {
			// bookmark types are immutable, so need to create a new one with the new type, but
			// we only want one thread at a time able to do this.
			int typeId = bookmarkTypes.getLowestUnusedId();
			bmt = new BookmarkTypeDB(typeId, typeName);
			bookmarkTypes.addBookmarkType(bmt);
		}
		if (createInDatabase && !bmt.hasBookmarks()) {
			// Ensure that both type record and bookmarks table exists
			bookmarkTypeAdapter.addType(bmt.getTypeId(), bmt.getTypeString());
			bookmarkAdapter.addType(bmt.getTypeId());
			bmt.setHasBookmarks(true);

			// fire event
			program.setObjChanged(ProgramEvent.BOOKMARK_TYPE_ADDED, bmt, null, null);

		}
		return bmt;
	}

	/*
	 * Get existing bookmark type
	 */
	BookmarkTypeDB getBookmarkType(int typeID) {
		return bookmarkTypes.getTypeById(typeID);
	}

	@Override
	public BookmarkType defineType(String type, Icon icon, Color color, int priority) {
		try (Closeable c = lock.write()) {
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
	}

	@Override
	public BookmarkType[] getBookmarkTypes() {
		try (Closeable c = lock.read()) {
			Collection<BookmarkTypeDB> values = bookmarkTypes.getAllTypes();
			BookmarkType[] bmTypes = new BookmarkType[values.size()];
			values.toArray(bmTypes);
			return bmTypes;
		}
	}

	@Override
	public Program getProgram() {
		return program;
	}

	@Override
	public BookmarkType getBookmarkType(String typeName) {
		return bookmarkTypes.get(typeName);
	}

	@Override
	public Bookmark setBookmark(Address addr, String type, String category, String comment) {
		try (Closeable c = lock.write()) {
			BookmarkTypeDB bmt = getBookmarkType(type, true);
			int typeId = bmt.getTypeId();
			BookmarkDB bm = (BookmarkDB) getBookmark(addr, type, category);
			if (bm != null) {
				bm.setComment(comment);
			}
			else {
				DBRecord rec = bookmarkAdapter.createBookmark(typeId, category,
					addrMap.getKey(addr, true), comment);
				bm = new BookmarkDB(this, rec);
				cache.add(bm);
				// fire event
				program.setObjChanged(ProgramEvent.BOOKMARK_ADDED, addr, bm, null, null);
			}
			return bm;
		}
		catch (IOException e) {
			dbError(e);

		}
		return null;
	}

	@Override
	public Bookmark getBookmark(Address addr, String type, String category) {
		try (Closeable c = lock.read()) {
			BookmarkTypeDB bmt = bookmarkTypes.get(type);
			if (bmt != null && bmt.hasBookmarks() && category != null) {
				int typeId = bmt.getTypeId();
				RecordIterator iter =
					bookmarkAdapter.getRecordsByTypeAtAddress(typeId, addrMap.getKey(addr, false));
				while (iter.hasNext()) {
					DBRecord rec = iter.next();
					String cat = rec.getString(BookmarkDBAdapter.CATEGORY_COL);
					if (category.equals(cat)) {
						return cache.getCachedInstance(rec);
					}
				}
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		return null;
	}

	@Override
	public void removeBookmark(Bookmark bookmark) {
		try (Closeable c = lock.write()) {
			if (bookmark instanceof BookmarkDB bm) {
				bm.checkDeleted();
				if (!bm.isOwnedBy(this)) {
					throw new IllegalArgumentException("Bookmark is not from this program!");
				}
				BookmarkTypeDB type = (BookmarkTypeDB) bm.getType();
				int typeId = type.getTypeId();
				doRemoveBookmark(bm);
				if (bookmarkAdapter.getBookmarkCount(typeId) == 0) {
					removeBookmarks(type.getTypeString());
				}
			}
		}
	}

	private void doRemoveBookmark(BookmarkDB bm) {
		Address addr = bm.getAddress();
		cache.delete(bm.getKey());
		try {
			bookmarkAdapter.deleteRecord(bm.getId());
			// fire event
			program.setObjChanged(ProgramEvent.BOOKMARK_REMOVED, addr, bm, null, null);
		}
		catch (IOException e) {
			dbError(e);
		}

	}

	@Override
	public void removeBookmarks(String typeName) {
		try (Closeable c = lock.write()) {
			try {
				BookmarkTypeDB bmt = bookmarkTypes.get(typeName);
				if (bmt != null && bmt.hasBookmarks()) {
					int typeId = bmt.getTypeId();
					bookmarkAdapter.deleteType(typeId);
					bookmarkTypeAdapter.deleteRecord(typeId);
					bmt.setHasBookmarks(false);
					program.setObjChanged(ProgramEvent.BOOKMARK_TYPE_REMOVED, bmt, null, null);
				}
			}
			catch (IOException e) {
				dbError(e);
			}
		}
	}

	@Override
	public void removeBookmarks(String type, String category, TaskMonitor monitor)
			throws CancelledException {
		try (Closeable c = lock.write()) {
			BookmarkType bmt = getBookmarkType(type);
			if (bmt == null || !bmt.hasBookmarks()) {
				return;
			}
			RecordIterator iter =
				bookmarkAdapter.getRecordsByTypeAndCategory(bmt.getTypeId(), category);
			while (iter.hasNext()) {
				DBRecord rec = iter.next();
				BookmarkDB bm = cache.getCachedInstance(rec);
				removeBookmark(bm);
				monitor.checkCancelled();
			}
		}
		catch (IOException e) {
			dbError(e);
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
		try (Closeable c = lock.read()) {
			List<Bookmark> list = new ArrayList<>();
			for (BookmarkTypeDB type : bookmarkTypes.getAllTypes()) {
				if (type != null && type.hasBookmarks()) {
					getBookmarks(addr, type.getTypeId(), list);
				}
			}
			Bookmark[] bookmarks = new Bookmark[list.size()];
			list.toArray(bookmarks);
			return bookmarks;
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
				list.add(cache.getCachedInstance(rec));
			}
		}
		catch (IOException e) {
			dbError(e);
		}
	}

	@Override
	public Bookmark[] getBookmarks(Address address, String type) {
		try (Closeable c = lock.read()) {
			Bookmark[] bookmarks = null;
			List<Bookmark> list = new ArrayList<>();
			BookmarkType bmt = getBookmarkType(type);
			if (bmt != null && bmt.hasBookmarks()) {
				getBookmarks(address, bmt.getTypeId(), list);
			}
			bookmarks = new Bookmark[list.size()];
			list.toArray(bookmarks);
			return bookmarks;
		}
	}

	@Override
	public boolean hasBookmarks(String type) {
		try (Closeable c = lock.read()) {
			BookmarkType bmt = getBookmarkType(type);
			if (bmt == null) {
				return false;
			}
			return bmt.hasBookmarks();
		}
	}

	@Override
	public String[] getCategories(String type) {
		try (Closeable c = lock.read()) {
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
	}

	@Override
	public AddressSetView getBookmarkAddresses(String type) {
		try (Closeable c = lock.read()) {
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
		return cache.getCachedInstance(id);
	}

	@Override
	public int getBookmarkCount() {
		try (Closeable c = lock.read()) {
			return bookmarkAdapter.getBookmarkCount();
		}
	}

	@Override
	public int getBookmarkCount(String type) {
		try (Closeable c = lock.read()) {
			BookmarkType bmt = getBookmarkType(type);
			if (bmt == null) {
				return 0;
			}
			return bookmarkAdapter.getBookmarkCount(bmt.getTypeId());
		}
	}

	@Override
	public Iterator<Bookmark> getBookmarksIterator(String type) {
		BookmarkType bmt = getBookmarkType(type);
		return getBookmarksIterator(bmt);
	}

	@Override
	public Iterator<Bookmark> getBookmarksIterator(Address startAddress, boolean forward) {
		try (Closeable c = lock.read()) {
			List<PeekableIterator<Bookmark>> list = new ArrayList<>();
			for (BookmarkTypeDB type : bookmarkTypes.getAllTypes()) {
				if (type != null && type.hasBookmarks()) {
					Iterator<Bookmark> bookmarksIterator =
						getBookmarksIterator(startAddress, type, forward);
					list.add(new WrappingPeekableIterator<>(bookmarksIterator));
				}
			}
			return new MultiIterator<>(list, forward);
		}
	}

	@Override
	public Iterator<Bookmark> getBookmarksIterator() {
		try (Closeable c = lock.read()) {
			return new TotalIterator();
		}
	}

	@Override
	public void removeBookmarks(AddressSetView set, TaskMonitor monitor) throws CancelledException {
		try (Closeable c = lock.write()) {
			for (BookmarkTypeDB type : bookmarkTypes.getAllTypes()) {
				if (type.hasBookmarks()) {
					removeBookmarks(set, type, null, monitor);
				}
			}
		}
	}

	@Override
	public void removeBookmarks(AddressSetView set, String type, TaskMonitor monitor)
			throws CancelledException {
		try (Closeable c = lock.write()) {
			BookmarkTypeDB bmt = (BookmarkTypeDB) getBookmarkType(type);
			if (bmt != null && bmt.hasBookmarks()) {
				removeBookmarks(set, bmt, null, monitor);
			}
		}
	}

	@Override
	public void removeBookmarks(AddressSetView set, String type, String category,
			TaskMonitor monitor) throws CancelledException {
		try (Closeable c = lock.write()) {
			BookmarkTypeDB bmt = (BookmarkTypeDB) getBookmarkType(type);
			if (bmt != null && bmt.hasBookmarks()) {
				removeBookmarks(set, bmt, category, monitor);
			}
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
					monitor.checkCancelled();
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
		try (Closeable c = lock.write()) {
			cache.invalidate();
			for (BookmarkTypeDB type : bookmarkTypes.getAllTypes()) {
				if (type.hasBookmarks()) {
					int typeId = type.getTypeId();
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
			try (Closeable c = lock.read()) {
				while (nextBookmark == null && (forward ? it.hasNext() : it.hasPrevious())) {
					DBRecord record = forward ? it.next() : it.previous();
					nextBookmark = cache.getCachedInstance(record);
				}
			}
			catch (IOException ioe) {
				// do nothing; the nextBookmark will not be set and we will return false for hasNext()
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
			List<BookmarkTypeDB> list = new ArrayList<>();
			for (BookmarkTypeDB bmt : bookmarkTypes.getAllTypes()) {
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

	private class BookmarkFactory implements DbFactory<BookmarkDB> {
		@Override
		public BookmarkDB instantiate(long key) {
			try {
				DBRecord record = bookmarkAdapter.getRecord(key);
				return record == null ? null : instantiate(record);
			}
			catch (IOException e) {
				dbError(e);
				return null;
			}
		}

		@Override
		public BookmarkDB instantiate(DBRecord record) {
			return new BookmarkDB(BookmarkDBManager.this, record);
		}
	}
}
