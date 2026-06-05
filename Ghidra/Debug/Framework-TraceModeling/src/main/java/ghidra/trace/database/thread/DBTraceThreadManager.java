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
import java.util.Collection;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.stream.Collectors;

import db.DBHandle;
import ghidra.framework.data.OpenMode;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceManager;
import ghidra.trace.database.target.DBTraceObject;
import ghidra.trace.database.target.DBTraceObjectManager;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.thread.TraceThreadManager;
import ghidra.util.LockHold;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class DBTraceThreadManager implements TraceThreadManager, DBTraceManager {
	protected final ReadWriteLock lock;
	protected final DBTrace trace;
	protected final DBTraceObjectManager objectManager;

	public DBTraceThreadManager(DBHandle dbh, OpenMode openMode, ReadWriteLock lock,
			TaskMonitor monitor, DBTrace trace, DBTraceObjectManager objectManager)
			throws IOException, VersionException {
		this.lock = lock;
		this.trace = trace;
		this.objectManager = objectManager;
	}

	@Override
	public void dbError(IOException e) {
		trace.dbError(e);
	}

	@Override
	public void invalidateCache(boolean all) {
		// NOTE: This is only a wrapper around the object manager
	}

	// Internal
	public TraceThread assertIsMine(TraceThread thread) {
		return objectManager.assertMyThread(thread);
	}

	@Override
	public TraceThread addThread(String path, Lifespan lifespan) throws DuplicateNameException {
		return addThread(path, path, lifespan);
	}

	@Override
	public TraceThread addThread(String path, String display, Lifespan lifespan)
			throws DuplicateNameException {
		return objectManager.addThread(path, display, lifespan);
	}

	@Override
	public Collection<? extends TraceThread> getAllThreads() {
		return objectManager.getAllObjects(TraceThread.class);
	}

	@Override
	public Collection<? extends TraceThread> getThreadsByPath(String path) {
		return objectManager.getObjectsByPath(path, TraceThread.class);
	}

	@Override
	public TraceThread getLiveThreadByPath(long snap, String path) {
		return objectManager.getObjectByPath(snap, path, TraceThread.class);
	}

	@Override
	public TraceThread getThread(long key) {
		DBTraceObject object = objectManager.getObjectById(key);
		return object == null ? null : object.queryInterface(TraceThread.class);
	}

	@Override
	public Collection<? extends TraceThread> getLiveThreads(long snap) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return objectManager.queryAllInterface(Lifespan.at(snap), TraceThread.class)
					.collect(Collectors.toSet());
		}
	}
}
