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

import java.awt.Color;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;

import javax.swing.Icon;

import db.DBHandle;
import ghidra.framework.data.OpenMode;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager;
import ghidra.trace.database.space.DBTraceDelegatingManager;
import ghidra.trace.database.thread.DBTraceThreadManager;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.bookmark.TraceBookmarkManager;
import ghidra.trace.model.bookmark.TraceBookmarkType;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.trace.util.TraceEvents;
import ghidra.util.LockHold;
import ghidra.util.Msg;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class DBTraceBookmarkManager extends AbstractDBTraceSpaceBasedManager<DBTraceBookmarkSpace>
		implements TraceBookmarkManager, DBTraceDelegatingManager<DBTraceBookmarkSpace> {
	public static final String NAME = "Bookmark";

	/**
	 * For non-register space:
	 * 
	 * {@code
	 * +---12----+----52----+
	 * | SpaceID |    Key   |
	 * +---------+----------+
	 * }
	 */
	// NOTE: There are few address spaces, but their IDs encode other stuff :/
	protected static final int SPACE_ID_MASK = 0x0FFF;
	protected static final int SPACE_ID_SHIFT = 52;

	protected static final long MEM_KEY_MASK = 0x000F_FFFF_FFFF_FFFFL;
	protected static final int MEM_KEY_SHIFT = 0;

	protected static long packId(long key, AddressSpace space) {
		long spaceId = space.getSpaceID();

		if ((spaceId & SPACE_ID_MASK) != spaceId) {
			throw new AssertionError("Bad assumption");
		}
		if ((key & MEM_KEY_MASK) != key) {
			throw new AssertionError("Bad assumption");
		}
		return (spaceId << SPACE_ID_SHIFT) | (key << MEM_KEY_SHIFT);
	}

	protected static int unpackSpaceId(long id) {
		return (int) ((id >> SPACE_ID_SHIFT) & SPACE_ID_MASK);
	}

	protected static long unpackKey(long id) {
		return (id >> MEM_KEY_SHIFT) & MEM_KEY_MASK;
	}

	protected static AddressSpace unpackSpace(long id, AddressFactory addressFactory) {
		int spaceId = unpackSpaceId(id);
		return addressFactory.getAddressSpace(spaceId);
	}

	protected final Map<String, DBTraceBookmarkType> typesByName = new HashMap<>();
	protected final Collection<DBTraceBookmarkType> typesView =
		Collections.unmodifiableCollection(typesByName.values());

	public DBTraceBookmarkManager(DBHandle dbh, OpenMode openMode, ReadWriteLock lock,
			TaskMonitor monitor, Language baseLanguage, DBTrace trace,
			DBTraceThreadManager threadManager) throws VersionException, IOException {
		super(NAME, dbh, openMode, lock, monitor, baseLanguage, trace, threadManager);

		loadSpaces();
	}

	@Override
	protected DBTraceBookmarkSpace createSpace(AddressSpace space, DBTraceSpaceEntry ent)
			throws VersionException, IOException {
		return new DBTraceBookmarkSpace(this, space);
	}

	@Override
	public DBTraceBookmarkSpace getBookmarkSpace(AddressSpace space, boolean createIfAbsent) {
		return getForSpace(space, createIfAbsent);
	}

	@Override
	public DBTraceBookmarkSpace getBookmarkRegisterSpace(TraceThread thread,
			boolean createIfAbsent) {
		return getForRegisterSpace(thread, 0, createIfAbsent);
	}

	@Override
	public DBTraceBookmarkSpace getBookmarkRegisterSpace(TraceStackFrame frame,
			boolean createIfAbsent) {
		return getForRegisterSpace(frame, createIfAbsent);
	}

	@Override
	public DBTraceBookmarkSpace getForSpace(AddressSpace space, boolean createIfAbsent) {
		return super.getForSpace(space, createIfAbsent);
	}

	@Override
	public Lock readLock() {
		return lock.readLock();
	}

	@Override
	public Lock writeLock() {
		return lock.writeLock();
	}

	// Internal
	public DBTraceBookmarkType getOrDefineBookmarkType(String typeName) {
		DBTraceBookmarkType type;
		synchronized (this) {
			type = typesByName.get(typeName);
			if (type != null) {
				return type;
			}
			Msg.warn(this, "Created default bookmark type: " + typeName);
			type = new DBTraceBookmarkType(this, typeName);
			typesByName.put(typeName, type);
		}
		trace.setChanged(new TraceChangeRecord<>(TraceEvents.BOOKMARK_TYPE_ADDED, null, type));
		return type;
	}

	@Override
	public synchronized DBTraceBookmarkType defineBookmarkType(String typeName, Icon icon,
			Color color, int priority) {
		DBTraceBookmarkType type;
		synchronized (this) {
			type = typesByName.get(typeName);
			if (type != null) {
				type.icon = icon;
				type.color = color;
				type.priority = priority;
				return type;
			}
			type = new DBTraceBookmarkType(this, typeName, icon, color, priority);
			typesByName.put(typeName, type);
		}
		trace.setChanged(new TraceChangeRecord<>(TraceEvents.BOOKMARK_TYPE_ADDED, null, type));
		return type;
	}

	@Override
	public Collection<? extends DBTraceBookmarkType> getDefinedBookmarkTypes() {
		return typesView;
	}

	@Override
	public synchronized DBTraceBookmarkType getBookmarkType(String typeName) {
		return typesByName.get(typeName);
	}

	@Override
	public DBTraceBookmark getBookmark(long id) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			AddressSpace addressSpace = unpackSpace(id, trace.getInternalAddressFactory());
			if (addressSpace == null) {
				return null;
			}
			DBTraceBookmarkSpace space = get(addressSpace, false);
			if (space == null) {
				return null;
			}
			long bookmarkKey = unpackKey(id);
			return space.bookmarkMapSpace.getDataByKey(bookmarkKey);
		}
	}

	// Internal
	public Collection<DBTraceBookmark> getBookmarksByType(String typeName) {
		return delegateCollection(getActiveSpaces(), m -> m.getBookmarksByType(typeName));
	}

	@Override
	public Set<String> getCategoriesForType(TraceBookmarkType type) {
		return delegateHashSet(getActiveSpaces(), m -> m.getCategoriesForType(type));
	}

	@Override
	public DBTraceBookmark addBookmark(Lifespan lifespan, Address address, TraceBookmarkType type,
			String category, String comment) {
		return delegateWrite(address.getAddressSpace(),
			m -> m.addBookmark(lifespan, address, type, category, comment));
	}

	@Override
	public Collection<? extends DBTraceBookmark> getAllBookmarks() {
		return delegateCollection(getActiveSpaces(), m -> m.getAllBookmarks());
	}

	@Override
	public Iterable<? extends DBTraceBookmark> getBookmarksAt(long snap, Address address) {
		return delegateRead(address.getAddressSpace(), m -> m.getBookmarksAt(snap, address),
			Set.of());
	}

	@Override
	public Iterable<? extends DBTraceBookmark> getBookmarksEnclosed(Lifespan lifespan,
			AddressRange range) {
		return delegateRead(range.getAddressSpace(), m -> m.getBookmarksEnclosed(lifespan, range),
			Set.of());
	}

	@Override
	public Iterable<? extends DBTraceBookmark> getBookmarksIntersecting(Lifespan lifespan,
			AddressRange range) {
		return delegateRead(range.getAddressSpace(),
			m -> m.getBookmarksIntersecting(lifespan, range), Set.of());
	}

	@Override
	public Collection<? extends DBTraceBookmark> getBookmarksAdded(long from, long to) {
		if (from == to) {
			return Collections.emptySet();
		}
		Collection<DBTraceBookmark> result = new ArrayList<>();
		for (DBTraceBookmarkSpace space : spaces.values()) {
			result.addAll(space.bookmarkMapSpace
					.reduce(TraceAddressSnapRangeQuery.added(from, to, space.getAddressSpace()))
					.values());
		}
		return result;
	}

	@Override
	public Collection<? extends DBTraceBookmark> getBookmarksRemoved(long from, long to) {
		if (from == to) {
			return Collections.emptySet();
		}
		Collection<DBTraceBookmark> result = new ArrayList<>();
		for (DBTraceBookmarkSpace space : spaces.values()) {
			result.addAll(space.bookmarkMapSpace
					.reduce(TraceAddressSnapRangeQuery.removed(from, to, space.getAddressSpace()))
					.values());
		}
		return result;
	}
}
