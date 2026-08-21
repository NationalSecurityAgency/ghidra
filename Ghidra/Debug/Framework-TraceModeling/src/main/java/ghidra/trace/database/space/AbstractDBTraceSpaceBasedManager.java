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
package ghidra.trace.database.space;

import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.locks.ReadWriteLock;

import db.DBHandle;
import db.DBRecord;
import ghidra.framework.data.OpenMode;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.trace.database.*;
import ghidra.trace.database.thread.DBTraceThreadManager;
import ghidra.trace.model.memory.TraceRegisterContainer;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceRegisterUtils;
import ghidra.util.LockHold;
import ghidra.util.Msg;
import ghidra.util.database.*;
import ghidra.util.database.annot.*;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractDBTraceSpaceBasedManager<M extends DBTraceSpaceBased>
		implements DBTraceManager {
	protected static final AddressSpace NO_ADDRESS_SPACE = Address.NO_ADDRESS.getAddressSpace();

	@DBAnnotatedObjectInfo(version = 1)
	public static class DBTraceSpaceEntry extends DBAnnotatedObject {
		static final String SPACE_COLUMN_NAME = "Space";

		@DBAnnotatedColumn(SPACE_COLUMN_NAME)
		static DBObjectColumn SPACE_COLUMN;

		@DBAnnotatedField(column = SPACE_COLUMN_NAME)
		private String spaceName;

		DBTraceSpaceBased space;

		public DBTraceSpaceEntry(DBCachedObjectStore<?> store, DBRecord record) {
			super(store, record);
		}

		void set(String spaceName, long threadKey, int frameLevel) {
			this.spaceName = spaceName;
			update(SPACE_COLUMN);
		}
	}

	private record TabledSpace(DBTraceSpaceEntry entry, AddressSpace space) {}

	protected final String name;
	protected final DBHandle dbh;
	protected final ReadWriteLock lock;
	protected final Language baseLanguage;
	protected final DBTrace trace;
	protected final DBTraceThreadManager threadManager;

	protected final DBCachedObjectStore<DBTraceSpaceEntry> spaceStore;
	// Note: use tree map so traversal is ordered by address space
	protected final Map<AddressSpace, M> spaces = new TreeMap<>();
	protected final Map<TraceRegisterContainer, M> regSpacesByContainer = new HashMap<>();

	protected final Collection<M> spacesView = Collections.unmodifiableCollection(spaces.values());

	public AbstractDBTraceSpaceBasedManager(String name, DBHandle dbh, OpenMode openMode,
			ReadWriteLock lock, TaskMonitor monitor, Language baseLanguage, DBTrace trace,
			DBTraceThreadManager threadManager) throws IOException, VersionException {
		this.name = name;
		this.dbh = dbh;
		this.lock = lock;
		this.baseLanguage = baseLanguage;
		this.trace = trace;
		this.threadManager = threadManager;

		DBCachedObjectStoreFactory factory = trace.getStoreFactory();

		spaceStore = factory.getOrCreateCachedStore(name + "Spaces", DBTraceSpaceEntry.class,
			DBTraceSpaceEntry::new, true);
	}

	protected String tableName(AddressSpace space) {
		return DBTraceUtils.tableName(name, space);
	}

	protected void loadSpaces() throws VersionException, IOException {
		Map<AddressSpace, TabledSpace> newSpaces = new HashMap<>();
		for (TabledSpace ts : getTabledSpaces()) {
			newSpaces.put(ts.space(), ts);
		}
		spaces.keySet().retainAll(newSpaces.keySet());
		for (Entry<AddressSpace, TabledSpace> ent : newSpaces.entrySet()) {
			if (!spaces.containsKey(ent.getKey())) {
				spaces.put(ent.getKey(), createSpace(ent.getValue()));
			}
		}
	}

	protected AddressSpace getSpaceByName(AddressFactory factory, String name) {
		if (NO_ADDRESS_SPACE.getName().equals(name)) {
			return NO_ADDRESS_SPACE;
		}
		return factory.getAddressSpace(name);
	}

	protected List<TabledSpace> getTabledSpaces() {
		AddressFactory factory = trace.getBaseAddressFactory();
		List<TabledSpace> result = new ArrayList<>();
		for (DBTraceSpaceEntry ent : spaceStore.asMap().values()) {
			AddressSpace space = getSpaceByName(factory, ent.spaceName);
			if (space == null) {
				Msg.error(this, "Space " + ent.spaceName + " does not exist in trace (language=" +
					baseLanguage + ").");
				continue;
			}
			result.add(new TabledSpace(ent, space));
		}
		return result;
	}

	protected M getForSpace(AddressSpace space, boolean createIfAbsent) {
		trace.assertValidSpace(Objects.requireNonNull(space));
		if (!space.isMemorySpace() && !space.isRegisterSpace() &&
			space != Address.NO_ADDRESS.getAddressSpace()) {
			throw new IllegalArgumentException(
				"Space must be a memory, register, or NO_ADDRESS space");
		}
		if (!createIfAbsent) {
			try (LockHold hold = LockHold.lock(lock.readLock())) {
				return spaces.get(space);
			}
		}
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			return spaces.computeIfAbsent(space, s -> {
				// NOTE: Require caller to start transaction
				try {
					DBTraceSpaceEntry ent = spaceStore.create();
					ent.set(space.getName(), -1, 0);
					return createSpace(space, ent);
				}
				catch (VersionException e) {
					throw new AssertionError(e);
				}
				catch (IOException e) {
					dbError(e);
					return null;
				}
			});
		}
	}

	protected M getForRegisterSpace(TraceThread thread, int frameLevel, boolean createIfAbsent) {
		trace.getThreadManager().assertIsMine(thread);
		TraceRegisterContainer container =
			TraceRegisterUtils.getRegisterContainer(thread.getObject(), frameLevel);
		return getForRegisterSpace(container, createIfAbsent);
	}

	protected M getForRegisterSpace(TraceStackFrame frame, boolean createIfAbsent) {
		TraceRegisterContainer container = TraceRegisterUtils.getRegisterContainer(frame);
		return getForRegisterSpace(container, createIfAbsent);
	}

	private M doGetForRegisterSpaceFoundContainer(TraceRegisterContainer container,
			boolean createIfAbsent) {
		AddressSpace as = TraceRegisterUtils.getRegisterAddressSpace(container, createIfAbsent);
		if (!createIfAbsent) {
			try (LockHold hold = LockHold.lock(lock.readLock())) {
				if (as == null) {
					// NOTE: Would like to cache this, but answer is likely to change
					return null;
				}
				M space = getForSpace(as, createIfAbsent);
				if (space == null) {
					return null;
				}
				synchronized (regSpacesByContainer) {
					regSpacesByContainer.put(container, space);
				}
				return space;
			}
		}
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			M space = getForSpace(as, createIfAbsent);
			synchronized (regSpacesByContainer) {
				regSpacesByContainer.put(container, space);
			}
			return space;
		}
	}

	protected M getForRegisterSpace(TraceRegisterContainer container, boolean createIfAbsent) {
		try (LockHold hold = LockHold.lock(createIfAbsent ? lock.writeLock() : lock.readLock())) {
			if (container == null) {
				return null;
			}
			synchronized (regSpacesByContainer) {
				M space = regSpacesByContainer.get(container);
				if (space != null) {
					return space;
				}
			}
			return doGetForRegisterSpaceFoundContainer(container, createIfAbsent);
		}
	}

	public DBTrace getTrace() {
		return trace;
	}

	public ReadWriteLock getLock() {
		return lock;
	}

	public Language getBaseLanguage() {
		return baseLanguage;
	}

	public M get(AddressSpace space, boolean createIfAbsent) {
		return getForSpace(space, createIfAbsent);
	}

	public Collection<M> getActiveSpaces() {
		return spacesView;
	}

	protected abstract M createSpace(AddressSpace space, DBTraceSpaceEntry ent)
			throws VersionException, IOException;

	@SuppressWarnings("unchecked")
	private M createSpace(TabledSpace ts) throws VersionException, IOException {
		if (ts.entry.space != null) {
			return (M) ts.entry.space;
		}
		M space = createSpace(ts.space, ts.entry);
		ts.entry.space = space;
		return space;
	}

	@Override
	public void dbError(IOException e) {
		trace.dbError(e);
	}

	@Override
	public void invalidateCache(boolean all) {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			regSpacesByContainer.clear();
			spaceStore.invalidateCache();
			loadSpaces();
			for (M m : spaces.values()) {
				m.invalidateCache();
			}
		}
		catch (VersionException e) {
			throw new AssertionError(e);
		}
		catch (IOException e) {
			dbError(e);
		}
	}
}
