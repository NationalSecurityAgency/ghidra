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

import javax.swing.ImageIcon;

import com.google.common.collect.Range;

import db.DBHandle;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.database.space.*;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.database.thread.DBTraceThreadManager;
import ghidra.trace.model.Trace.TraceBookmarkChangeType;
import ghidra.trace.model.bookmark.TraceBookmarkManager;
import ghidra.trace.model.bookmark.TraceBookmarkType;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
import ghidra.util.Msg;
import ghidra.util.database.DBOpenMode;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class DBTraceBookmarkManager
		extends AbstractDBTraceSpaceBasedManager<DBTraceBookmarkSpace, DBTraceBookmarkRegisterSpace>
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
	 * 
	 * For register space:
	 * 
	 * {@code
	 * +---12----+----32----+----8----+--12--+
	 * | SpaceID |  Thread  |  Frame  |  Key |
	 * +---------+----------+---------+------+
	 * }
	 */
	// NOTE: There are few address spaces, but their IDs encode other stuff :/
	protected static final int SPACE_ID_MASK = 0x0FFF;
	protected static final int SPACE_ID_SHIFT = 52;

	protected static final long MEM_KEY_MASK = 0x000F_FFFF_FFFF_FFFFL;
	protected static final int MEM_KEY_SHIFT = 0;

	protected static final long REG_THREAD_MASK = 0x0_FFFF_FFFFL;
	protected static final int REG_THREAD_SHIFT = 20;

	protected static final long REG_FRAME_MASK = 0x00FF;
	protected static final int REG_FRAME_SHIFT = 12;

	protected static final long REG_KEY_MASK = 0x0FFF;
	protected static final int REG_KEY_SHIFT = 0;

	protected static long packId(long key, DBTraceSpaceKey spaceKey) {
		return spaceKey.getAddressSpace().isRegisterSpace() ? packRegId(key, spaceKey)
				: packMemId(key, spaceKey);
	}

	protected static long packMemId(long key, DBTraceSpaceKey spaceKey) {
		long spaceId = spaceKey.getAddressSpace().getSpaceID();
		assert spaceKey.getThread() == null;

		if ((spaceId & SPACE_ID_MASK) != spaceId) {
			throw new AssertionError("Bad assumption");
		}
		if ((key & MEM_KEY_MASK) != key) {
			throw new AssertionError("Bad assumption");
		}
		return (spaceId << SPACE_ID_SHIFT) | (key << MEM_KEY_SHIFT);
	}

	protected static long packRegId(long key, DBTraceSpaceKey spaceKey) {
		long spaceId = spaceKey.getAddressSpace().getSpaceID();
		long threadKey = spaceKey.getThread().getKey();
		int frameLevel = spaceKey.getFrameLevel();

		if ((spaceId & SPACE_ID_MASK) != spaceId) {
			throw new AssertionError("Bad assumption");
		}
		if ((threadKey & REG_THREAD_MASK) != threadKey) {
			throw new AssertionError("Bad assumption");
		}
		if ((frameLevel & REG_FRAME_MASK) != frameLevel) {
			throw new AssertionError("Bad assumption");
		}
		if ((key & REG_KEY_MASK) != key) {
			throw new AssertionError("Bad assumption");
		}
		return (spaceId << SPACE_ID_SHIFT) | (threadKey << REG_THREAD_SHIFT) |
			(frameLevel << REG_FRAME_SHIFT) | (key << REG_KEY_SHIFT);
	}

	protected static int unpackSpaceId(long id) {
		return (int) ((id >> SPACE_ID_SHIFT) & SPACE_ID_MASK);
	}

	protected static long unpackMemKey(long id) {
		return (id >> MEM_KEY_SHIFT) & MEM_KEY_MASK;
	}

	protected static long unpackRegThread(long id) {
		return (id >> REG_THREAD_SHIFT) & REG_THREAD_MASK;
	}

	protected static int unpackRegFrame(long id) {
		return (int) ((id >> REG_FRAME_SHIFT) & REG_FRAME_MASK);
	}

	protected static long unpackRegKey(long id) {
		return (id >> REG_KEY_SHIFT) & REG_KEY_MASK;
	}

	protected static DBTraceSpaceKey unpackSpaceKey(long id, Language baseLanguage,
			DBTraceThreadManager threadManager) {
		int spaceId = unpackSpaceId(id);
		AddressSpace space = baseLanguage.getAddressFactory().getAddressSpace(spaceId);
		if (space == null) {
			return null;
		}
		return space.isRegisterSpace() ? unpackRegSpaceKey(space, threadManager, id)
				: unpackMemSpaceKey(space, id);
	}

	protected static DBTraceSpaceKey unpackMemSpaceKey(AddressSpace space, long id) {
		return DBTraceSpaceKey.create(space, null, 0);
	}

	protected static DBTraceSpaceKey unpackRegSpaceKey(AddressSpace space,
			DBTraceThreadManager threadManager, long id) {
		long threadKey = unpackRegThread(id);
		DBTraceThread thread = threadManager.getThread(threadKey);
		assert thread != null;
		int frameLevel = unpackRegFrame(id);
		return DBTraceSpaceKey.create(space, thread, frameLevel);
	}

	protected final Map<String, DBTraceBookmarkType> typesByName = new HashMap<>();
	protected final Collection<DBTraceBookmarkType> typesView =
		Collections.unmodifiableCollection(typesByName.values());

	public DBTraceBookmarkManager(DBHandle dbh, DBOpenMode openMode, ReadWriteLock lock,
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
	protected DBTraceBookmarkRegisterSpace createRegisterSpace(AddressSpace space,
			DBTraceThread thread, DBTraceSpaceEntry ent) throws VersionException, IOException {
		return new DBTraceBookmarkRegisterSpace(this, space, thread, ent.getFrameLevel());
	}

	@Override
	public DBTraceBookmarkSpace getBookmarkSpace(AddressSpace space, boolean createIfAbsent) {
		return getForSpace(space, createIfAbsent);
	}

	@Override
	public DBTraceBookmarkRegisterSpace getBookmarkRegisterSpace(TraceThread thread,
			boolean createIfAbsent) {
		return getForRegisterSpace(thread, 0, createIfAbsent);
	}

	@Override
	public DBTraceBookmarkRegisterSpace getBookmarkRegisterSpace(TraceStackFrame frame,
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
		trace.setChanged(new TraceChangeRecord<>(TraceBookmarkChangeType.TYPE_ADDED, null, type));
		return type;
	}

	@Override
	public synchronized DBTraceBookmarkType defineBookmarkType(String typeName, ImageIcon icon,
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
		trace.setChanged(new TraceChangeRecord<>(TraceBookmarkChangeType.TYPE_ADDED, null, type));
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
			DBTraceSpaceKey spaceKey = unpackSpaceKey(id, baseLanguage, threadManager);
			if (spaceKey == null) {
				return null;
			}
			DBTraceBookmarkSpace space = get(spaceKey, false);
			if (space == null) {
				return null;
			}
			long bookmarkKey =
				spaceKey.getAddressSpace().isRegisterSpace() ? unpackRegKey(id) : unpackMemKey(id);
			return space.bookmarkMapSpace.getDataByKey(bookmarkKey);
		}
	}

	// Internal
	public Collection<DBTraceBookmark> getBookmarksByType(String typeName) {
		return delegateCollection(getActiveSpaces(), m -> m.getBookmarksByType(typeName));
	}

	@Override
	public Set<String> getCategoriesForType(TraceBookmarkType type) {
		return delegateHashSet(getActiveMemorySpaces(), m -> m.getCategoriesForType(type));
	}

	@Override
	public DBTraceBookmark addBookmark(Range<Long> lifespan, Address address,
			TraceBookmarkType type, String category, String comment) {
		return delegateWrite(address.getAddressSpace(),
			m -> m.addBookmark(lifespan, address, type, category, comment));
	}

	@Override
	public Collection<? extends DBTraceBookmark> getAllBookmarks() {
		return delegateCollection(getActiveMemorySpaces(), m -> m.getAllBookmarks());
	}

	@Override
	public Iterable<? extends DBTraceBookmark> getBookmarksAt(long snap, Address address) {
		return delegateRead(address.getAddressSpace(), m -> m.getBookmarksAt(snap, address),
			Set.of());
	}

	@Override
	public Iterable<? extends DBTraceBookmark> getBookmarksEnclosed(Range<Long> lifespan,
			AddressRange range) {
		return delegateRead(range.getAddressSpace(), m -> m.getBookmarksEnclosed(lifespan, range),
			Set.of());
	}

	@Override
	public Iterable<? extends DBTraceBookmark> getBookmarksIntersecting(Range<Long> lifespan,
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
		for (DBTraceBookmarkSpace space : memSpaces.values()) {
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
		for (DBTraceBookmarkSpace space : memSpaces.values()) {
			result.addAll(space.bookmarkMapSpace
					.reduce(TraceAddressSnapRangeQuery.removed(from, to, space.getAddressSpace()))
					.values());
		}
		return result;
	}
}
