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
package ghidra.trace.database.thread;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;

import com.google.common.collect.Range;

import db.DBHandle;
import ghidra.trace.database.*;
import ghidra.trace.model.Trace.TraceThreadChangeType;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.thread.TraceThreadManager;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
import ghidra.util.database.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class DBTraceThreadManager implements TraceThreadManager, DBTraceManager {
	protected final ReadWriteLock lock;
	protected final DBTrace trace;

	protected final DBCachedObjectStore<DBTraceThread> threadStore;
	protected final DBCachedObjectIndex<String, DBTraceThread> threadsByPath;

	public DBTraceThreadManager(DBHandle dbh, DBOpenMode openMode, ReadWriteLock lock,
			TaskMonitor monitor, DBTrace trace) throws IOException, VersionException {
		this.lock = lock;
		this.trace = trace;

		DBCachedObjectStoreFactory factory = trace.getStoreFactory();

		threadStore = factory.getOrCreateCachedStore(DBTraceThread.TABLE_NAME, DBTraceThread.class,
			(s, r) -> new DBTraceThread(this, s, r), true);
		threadsByPath = threadStore.getIndex(String.class, DBTraceThread.PATH_COLUMN);
	}

	@Override
	public void dbError(IOException e) {
		trace.dbError(e);
	}

	@Override
	public void invalidateCache(boolean all) {
		threadStore.invalidateCache();
	}

	// Internal
	public DBTraceThread assertIsMine(TraceThread thread) {
		if (!(thread instanceof DBTraceThread)) {
			throw new IllegalArgumentException("Thread " + thread + " is not part of this trace");
		}
		DBTraceThread dbThread = (DBTraceThread) thread;
		if (dbThread.manager != this) {
			throw new IllegalArgumentException("Thread " + thread + " is not part of this trace");
		}
		if (!getAllThreads().contains(dbThread)) {
			throw new IllegalArgumentException("Thread " + thread + " is not part of this trace");
		}
		return dbThread;
	}

	protected void checkConflictingPath(DBTraceThread ignore, String path, Range<Long> lifespan)
			throws DuplicateNameException {
		for (DBTraceThread pc : threadsByPath.get(path)) {
			if (pc == ignore) {
				continue;
			}
			if (!DBTraceUtils.intersect(pc.getLifespan(), lifespan)) {
				continue;
			}
			throw new DuplicateNameException(
				"A thread having path '" + path + "' already exists within an overlapping snap");
		}
	}

	@Override
	public DBTraceThread addThread(String path, Range<Long> lifespan)
			throws DuplicateNameException {
		return addThread(path, path, lifespan);
	}

	@Override
	public DBTraceThread addThread(String path, String display, Range<Long> lifespan)
			throws DuplicateNameException {
		DBTraceThread thread;
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			checkConflictingPath(null, path, lifespan);
			thread = threadStore.create();
			thread.set(path, display, lifespan);
		}
		trace.setChanged(new TraceChangeRecord<>(TraceThreadChangeType.ADDED, null, thread));
		return thread;
	}

	@Override
	public Collection<? extends DBTraceThread> getAllThreads() {
		return Collections.unmodifiableCollection(threadStore.asMap().values());
	}

	@Override
	public Collection<? extends DBTraceThread> getThreadsByPath(String path) {
		return Collections.unmodifiableCollection(threadsByPath.get(path));
	}

	@Override
	public DBTraceThread getLiveThreadByPath(long snap, String path) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return threadsByPath.get(path)
					.stream()
					.filter(t -> t.getLifespan().contains(snap))
					.findAny()
					.orElse(null);
		}
	}

	@Override
	public DBTraceThread getThread(long key) {
		return threadStore.getObjectAt(key);
	}

	@Override
	public Collection<? extends DBTraceThread> getLiveThreads(long snap) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			// NOTE: Should be few enough threads that this is fast
			Collection<DBTraceThread> result = new LinkedHashSet<>();
			for (DBTraceThread thread : threadStore.asMap().values()) {
				if (thread.getCreationSnap() <= snap && snap < thread.getDestructionSnap()) {
					result.add(thread);
				}
			}
			return result;
		}
	}

	public void deleteThread(DBTraceThread thread) {
		threadStore.delete(thread);
		trace.setChanged(new TraceChangeRecord<>(TraceThreadChangeType.DELETED, null, thread));
	}
}
