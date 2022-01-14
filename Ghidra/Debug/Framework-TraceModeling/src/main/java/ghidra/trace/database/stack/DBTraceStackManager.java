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
import java.util.List;
import java.util.concurrent.locks.ReadWriteLock;

import com.google.common.collect.Range;

import db.DBHandle;
import generic.NestedIterator;
import ghidra.dbg.target.*;
import ghidra.dbg.util.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceManager;
import ghidra.trace.database.address.DBTraceOverlaySpaceAdapter;
import ghidra.trace.database.stack.DBTraceStack.ThreadSnap;
import ghidra.trace.database.thread.DBTraceThreadManager;
import ghidra.trace.model.Trace.TraceStackChangeType;
import ghidra.trace.model.stack.*;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectKeyPath;
import ghidra.trace.model.thread.TraceObjectThread;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
import ghidra.util.database.*;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class DBTraceStackManager implements TraceStackManager, DBTraceManager {

	protected final DBHandle dbh;
	protected final ReadWriteLock lock;
	protected final DBTrace trace;

	protected final DBTraceThreadManager threadManager;
	protected final DBTraceOverlaySpaceAdapter overlayAdapter;

	protected final DBCachedObjectStore<DBTraceStack> stackStore;
	protected final DBCachedObjectIndex<ThreadSnap, DBTraceStack> stacksByThreadSnap;
	protected final DBCachedObjectStore<DBTraceStackFrame> frameStore;
	protected final DBCachedObjectIndex<Address, DBTraceStackFrame> framesByPC;

	public DBTraceStackManager(DBHandle dbh, DBOpenMode openMode, ReadWriteLock lock,
			TaskMonitor monitor, DBTrace trace, DBTraceThreadManager threadManager,
			DBTraceOverlaySpaceAdapter overlayAdapter)
			throws VersionException, IOException {
		this.dbh = dbh;
		this.lock = lock;
		this.trace = trace;
		this.threadManager = threadManager;
		this.overlayAdapter = overlayAdapter;

		DBCachedObjectStoreFactory factory = trace.getStoreFactory();

		stackStore = factory.getOrCreateCachedStore(DBTraceStack.TABLE_NAME,
			DBTraceStack.class, (s, r) -> new DBTraceStack(this, s, r), true);
		stacksByThreadSnap = stackStore.getIndex(ThreadSnap.class, DBTraceStack.THREAD_SNAP_COLUMN);

		frameStore = factory.getOrCreateCachedStore(DBTraceStackFrame.TABLE_NAME,
			DBTraceStackFrame.class, (s, r) -> new DBTraceStackFrame(this, s, r), true);
		framesByPC = frameStore.getIndex(Address.class, DBTraceStackFrame.PC_COLUMN);
	}

	@Override
	public void invalidateCache(boolean all) {
		stackStore.invalidateCache();
		frameStore.invalidateCache();
	}

	@Override
	public void dbError(IOException e) {
		trace.dbError(e);
	}

	protected DBTraceStack getStackByKey(long stackKey) {
		return stackStore.getObjectAt(stackKey);
	}

	protected DBTraceStackFrame getFrameByKey(long frameKey) {
		return frameStore.getObjectAt(frameKey);
	}

	public static PathPredicates single(TraceObject seed, Class<? extends TargetObject> targetIf) {
		PathMatcher stackMatcher = seed.getTargetSchema().searchFor(targetIf, false);
		PathPattern singleton = stackMatcher.getSingletonPattern();
		if (singleton.getSingletonPath() == null) {
			throw new IllegalStateException("Schema doesn't provide a unique " +
				targetIf.getSimpleName() + " for " + seed.getCanonicalPath());
		}
		return singleton;
	}

	protected TraceObjectStack doGetOrAddObjectStack(TraceThread thread, long snap,
			boolean createIfAbsent) {
		TraceObjectThread objThread = (TraceObjectThread) thread;
		TraceObject obj = objThread.getObject();
		PathPredicates predicates = single(obj, TargetStack.class);
		if (createIfAbsent) {
			try (LockHold hold = trace.lockWrite()) {
				TraceObjectStack stack =
					trace.getObjectManager()
							.getSuccessor(obj, predicates, snap, TraceObjectStack.class);
				if (stack != null) {
					return stack;
				}
				List<String> keyList = PathUtils.extend(obj.getCanonicalPath().getKeyList(),
					predicates.getSingletonPath());
				return trace.getObjectManager().addStack(keyList, snap);
			}
		}
		try (LockHold hold = trace.lockRead()) {
			return trace.getObjectManager()
					.getSuccessor(obj, predicates, snap, TraceObjectStack.class);
		}
	}

	protected TraceObjectStack doGetLatestObjectStack(TraceThread thread, long snap) {
		TraceObjectThread objThread = (TraceObjectThread) thread;
		TraceObject obj = objThread.getObject();
		List<String> keyList = single(obj, TargetStack.class).getSingletonPath();
		return trace.getObjectManager()
				.getLatestSuccessor(obj, TraceObjectKeyPath.of(keyList), snap,
					TraceObjectStack.class);
	}

	@Override
	public TraceStack getStack(TraceThread thread, long snap, boolean createIfAbsent) {
		threadManager.assertIsMine(thread);
		if (trace.getObjectManager().hasSchema()) {
			return doGetOrAddObjectStack(thread, snap, createIfAbsent);
		}
		DBTraceStack stack;
		ThreadSnap key = new ThreadSnap(thread.getKey(), snap);
		if (createIfAbsent) {
			try (LockHold hold = LockHold.lock(lock.writeLock())) {
				stack = stacksByThreadSnap.getOne(key);
				if (stack != null) {
					return stack;
				}
				stack = stackStore.create();
				stack.set(thread, snap);
			}
			trace.setChanged(new TraceChangeRecord<>(TraceStackChangeType.ADDED, null, stack));
			return stack;
		}
		return stacksByThreadSnap.getOne(key);
	}

	@Override
	public TraceStack getLatestStack(TraceThread thread, long snap) {
		threadManager.assertIsMine(thread);
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			if (trace.getObjectManager().hasSchema()) {
				return doGetLatestObjectStack(thread, snap);
			}
			DBTraceStack found =
				stacksByThreadSnap.floorValue(new ThreadSnap(thread.getKey(), snap));
			if (found == null) {
				return null;
			}
			if (found.getThread() != thread || found.getSnap() > snap) {
				// Encoded <thread,snap> field results in unsigned index
				// NB. Conventionally, a search should never traverse 0 (real to scratch space)
				return null;
			}
			return found;
		}
	}

	@Override
	// TODO: Should probably include a lifespan parameter?
	public Iterable<TraceStackFrame> getFramesIn(AddressSetView set) {
		if (trace.getObjectManager().hasSchema()) {
			return () -> NestedIterator.start(set.iterator(), rng -> trace.getObjectManager()
					.getObjectsIntersecting(Range.all(), rng, TargetStackFrame.PC_ATTRIBUTE_NAME,
						TraceObjectStackFrame.class)
					.iterator());
		}
		return () -> NestedIterator.start(set.iterator(), rng -> framesByPC
				.sub(rng.getMinAddress(), true, rng.getMaxAddress(), true)
				.values()
				.iterator());
	}

	protected void deleteStack(DBTraceStack stack) {
		// Caller must delete frames
		stackStore.delete(stack);
	}

	protected DBTraceStackFrame createFrame(DBTraceStack stack) {
		DBTraceStackFrame frame = frameStore.create();
		frame.set(stack);
		return frame;
	}

	protected void deleteFrame(DBTraceStackFrame frame) {
		frameStore.delete(frame);
	}
}
