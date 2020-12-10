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
package ghidra.trace.database.bookmark;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;

import com.google.common.collect.Range;

import ghidra.program.model.address.*;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapSpace;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.database.space.DBTraceSpaceBased;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.Trace.TraceBookmarkChangeType;
import ghidra.trace.model.bookmark.TraceBookmarkSpace;
import ghidra.trace.model.bookmark.TraceBookmarkType;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
import ghidra.util.database.DBCachedObjectIndex;
import ghidra.util.exception.VersionException;

public class DBTraceBookmarkSpace implements TraceBookmarkSpace, DBTraceSpaceBased {
	protected final DBTraceBookmarkManager manager;
	protected final ReadWriteLock lock;
	protected final DBTrace trace;

	protected final DBTraceAddressSnapRangePropertyMapSpace<DBTraceBookmark, DBTraceBookmark> bookmarkMapSpace;
	protected final DBCachedObjectIndex<String, DBTraceBookmark> bookmarksByTypeName;
	protected final Collection<DBTraceBookmark> bookmarkView;

	public DBTraceBookmarkSpace(DBTraceBookmarkManager manager, AddressSpace space)
			throws VersionException, IOException {
		this.manager = manager;
		this.lock = manager.getLock();
		this.trace = manager.getTrace();

		this.bookmarkMapSpace =
			new DBTraceAddressSnapRangePropertyMapSpace<>(DBTraceBookmark.tableName(space, -1, 0),
				trace.getStoreFactory(), lock, space, DBTraceBookmark.class,
				(t, s, r) -> new DBTraceBookmark(this, t, s, r));
		this.bookmarksByTypeName =
			bookmarkMapSpace.getUserIndex(String.class, DBTraceBookmark.TYPE_COLUMN);
		this.bookmarkView = Collections.unmodifiableCollection(bookmarkMapSpace.values());
	}

	@Override
	public AddressSpace getAddressSpace() {
		return bookmarkMapSpace.getAddressSpace();
	}

	@Override
	public DBTraceThread getThread() {
		return null;
	}

	@Override
	public int getFrameLevel() {
		return 0;
	}

	protected DBTraceBookmarkType assertInTrace(TraceBookmarkType type) {
		if (!(type instanceof DBTraceBookmarkType)) {
			throw new IllegalArgumentException("Given type is not part of this trace");
		}
		DBTraceBookmarkType dbType = (DBTraceBookmarkType) type;
		if (dbType.manager != manager) {
			throw new IllegalArgumentException("Given type is not part of this trace");
		}
		return dbType;
	}

	@Override
	public Set<String> getCategoriesForType(TraceBookmarkType type) {
		assertInTrace(type);
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			Set<String> result = new HashSet<>();
			for (DBTraceBookmark bookmark : bookmarksByTypeName.get(type.getTypeString())) {
				result.add(bookmark.getCategory());
			}
			return result;
		}
	}

	@Override
	public DBTraceBookmark addBookmark(Range<Long> lifespan, Address address,
			TraceBookmarkType type, String category, String comment) {
		assertInTrace(type);
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			DBTraceBookmark bookmark = bookmarkMapSpace.put(address, lifespan, null);
			bookmark.set(type.getTypeString(), category, comment);
			trace.setChanged(
				new TraceChangeRecord<>(TraceBookmarkChangeType.ADDED, this, bookmark));
			return bookmark;
		}
	}

	@Override
	public Collection<DBTraceBookmark> getAllBookmarks() {
		return bookmarkView;
	}

	@Override
	public Iterable<DBTraceBookmark> getBookmarksAt(long snap, Address address) {
		return bookmarkMapSpace.reduce(TraceAddressSnapRangeQuery.at(address, snap)).values();
	}

	@Override
	public Iterable<DBTraceBookmark> getBookmarksEnclosed(Range<Long> lifespan,
			AddressRange range) {
		return bookmarkMapSpace.reduce(
			TraceAddressSnapRangeQuery.enclosed(range, lifespan)).values();
	}

	@Override
	public Iterable<DBTraceBookmark> getBookmarksIntersecting(Range<Long> lifespan,
			AddressRange range) {
		return bookmarkMapSpace.reduce(
			TraceAddressSnapRangeQuery.intersecting(range, lifespan)).values();
	}

	public Collection<DBTraceBookmark> getBookmarksByType(String typeName) {
		return bookmarksByTypeName.getLazily(typeName);
	}

	@Override
	public void invalidateCache() {
		bookmarkMapSpace.invalidateCache();
	}
}
