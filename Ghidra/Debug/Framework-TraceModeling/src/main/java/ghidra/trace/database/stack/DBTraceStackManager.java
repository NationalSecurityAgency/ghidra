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
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceManager;
import ghidra.trace.database.stack.DBTraceStack.ThreadSnap;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.database.thread.DBTraceThreadManager;
import ghidra.trace.model.Trace.TraceStackChangeType;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.stack.TraceStackManager;
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

	protected final DBCachedObjectStore<DBTraceStack> stackStore;
	protected final DBCachedObjectIndex<ThreadSnap, DBTraceStack> stacksByThreadSnap;
	protected final DBCachedObjectStore<DBTraceStackFrame> frameStore;
	protected final DBCachedObjectIndex<Address, DBTraceStackFrame> framesByPC;

	public DBTraceStackManager(DBHandle dbh, DBOpenMode openMode, ReadWriteLock lock,
			TaskMonitor monitor, DBTrace trace, DBTraceThreadManager threadManager)
			throws VersionException, IOException {
		this.dbh = dbh;
		this.lock = lock;
		this.trace = trace;
		this.threadManager = threadManager;

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

	public DBTraceStack getStackByKey(long stackKey) {
		return stackStore.getObjectAt(stackKey);
	}

	public DBTraceStackFrame getFrameByKey(long frameKey) {
		return frameStore.getObjectAt(frameKey);
	}

	@Override
	public DBTraceStack getStack(TraceThread thread, long snap, boolean createIfAbsent) {
		DBTraceThread dbThread = threadManager.assertIsMine(thread);
		DBTraceStack stack;
		ThreadSnap key = new ThreadSnap(thread.getKey(), snap);
		if (createIfAbsent) {
			try (LockHold hold = LockHold.lock(lock.writeLock())) {
				stack = stacksByThreadSnap.getOne(key);
				if (stack != null) {
					return stack;
				}
				stack = stackStore.create();
				stack.set(dbThread, snap);
			}
			trace.setChanged(new TraceChangeRecord<>(TraceStackChangeType.ADDED, null, stack));
			return stack;
		}
		return stacksByThreadSnap.getOne(key);
	}

	@Override
	public DBTraceStack getLatestStack(TraceThread thread, long snap) {
		threadManager.assertIsMine(thread);
		DBTraceStack found = stacksByThreadSnap.floorValue(new ThreadSnap(thread.getKey(), snap));
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

	@Override
	public Iterable<TraceStackFrame> getFramesIn(AddressSetView set) {
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
