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
package ghidra.trace.database.stack;

import java.io.IOException;
import java.util.concurrent.locks.ReadWriteLock;

import db.DBHandle;
import generic.NestedIterator;
import ghidra.framework.data.OpenMode;
import ghidra.program.model.address.AddressSetView;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceManager;
import ghidra.trace.database.address.DBTraceOverlaySpaceAdapter;
import ghidra.trace.database.thread.DBTraceThreadManager;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.stack.*;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.iface.TraceObjectInterface;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.target.path.PathFilter;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.LockHold;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class DBTraceStackManager implements TraceStackManager, DBTraceManager {

	protected final DBHandle dbh;
	protected final ReadWriteLock lock;
	protected final DBTrace trace;

	protected final DBTraceThreadManager threadManager;
	protected final DBTraceOverlaySpaceAdapter overlayAdapter;

	public DBTraceStackManager(DBHandle dbh, OpenMode openMode, ReadWriteLock lock,
			TaskMonitor monitor, DBTrace trace, DBTraceThreadManager threadManager,
			DBTraceOverlaySpaceAdapter overlayAdapter) throws VersionException, IOException {
		this.dbh = dbh;
		this.lock = lock;
		this.trace = trace;
		this.threadManager = threadManager;
		this.overlayAdapter = overlayAdapter;
	}

	@Override
	public void dbError(IOException e) {
		trace.dbError(e);
	}

	@Override
	public void invalidateCache(boolean all) {
		// NOTE: This is only a wrapper around the object manager
	}

	public static PathFilter single(TraceObject seed,
			Class<? extends TraceObjectInterface> targetIf) {
		PathFilter stackFilter = seed.getSchema().searchFor(targetIf, false);
		if (stackFilter.getSingletonPath() == null) {
			throw new IllegalStateException("Schema doesn't provide a unique " +
				targetIf.getSimpleName() + " for " + seed.getCanonicalPath());
		}
		return stackFilter.getSingletonPattern();
	}

	protected TraceStack doGetOrAddObjectStack(TraceThread thread, long snap,
			boolean createIfAbsent) {
		TraceObject obj = thread.getObject();
		PathFilter filter = single(obj, TraceStack.class);
		if (createIfAbsent) {
			try (LockHold hold = trace.lockWrite()) {
				TraceStack stack =
					trace.getObjectManager().getSuccessor(obj, filter, snap, TraceStack.class);
				if (stack != null) {
					return stack;
				}
				KeyPath path = obj.getCanonicalPath().extend(filter.getSingletonPath());
				return trace.getObjectManager().addStack(path, snap);
			}
		}
		try (LockHold hold = trace.lockRead()) {
			return trace.getObjectManager().getSuccessor(obj, filter, snap, TraceStack.class);
		}
	}

	protected TraceStack doGetLatestObjectStack(TraceThread thread, long snap) {
		TraceObject obj = thread.getObject();
		KeyPath path = single(obj, TraceStack.class).getSingletonPath();
		return trace.getObjectManager().getLatestSuccessor(obj, path, snap, TraceStack.class);
	}

	@Override
	public TraceStack getStack(TraceThread thread, long snap, boolean createIfAbsent) {
		threadManager.assertIsMine(thread);
		return doGetOrAddObjectStack(thread, snap, createIfAbsent);
	}

	@Override
	public TraceStack getLatestStack(TraceThread thread, long snap) {
		threadManager.assertIsMine(thread);
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return doGetLatestObjectStack(thread, snap);
		}
	}

	@Override
	// TODO: Should probably include a lifespan parameter?
	public Iterable<TraceStackFrame> getFramesIn(AddressSetView set) {
		return () -> NestedIterator.start(set.iterator(),
			rng -> trace.getObjectManager()
					.getObjectsIntersecting(Lifespan.ALL, rng, TraceStackFrame.KEY_PC,
						TraceStackFrame.class)
					.iterator());
	}
}
