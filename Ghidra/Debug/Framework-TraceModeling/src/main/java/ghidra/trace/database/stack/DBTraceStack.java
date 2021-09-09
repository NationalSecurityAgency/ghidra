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
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.util.*;

import db.BinaryField;
import db.DBRecord;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.Trace.TraceStackChangeType;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
import ghidra.util.database.*;
import ghidra.util.database.DBCachedObjectStoreFactory.AbstractDBFieldCodec;
import ghidra.util.database.annot.*;

@DBAnnotatedObjectInfo(version = 0)
public class DBTraceStack extends DBAnnotatedObject implements TraceStack {
	public static final String TABLE_NAME = "Stacks";

	static final String THREAD_SNAP_COLUMN_NAME = "ThreadSnap";
	static final String FRAMES_COLUMN_NAME = "Frames";

	@DBAnnotatedColumn(THREAD_SNAP_COLUMN_NAME)
	static DBObjectColumn THREAD_SNAP_COLUMN;
	@DBAnnotatedColumn(FRAMES_COLUMN_NAME)
	static DBObjectColumn FRAMES_COLUMN;

	public static class ThreadSnap {
		long threadKey;
		long snap;

		public ThreadSnap() {
		}

		public ThreadSnap(long threadKey, long snap) {
			this.threadKey = threadKey;
			this.snap = snap;
		}
	}

	public static class ThreadSnapDBFieldCodec
			extends AbstractDBFieldCodec<ThreadSnap, DBAnnotatedObject, BinaryField> {

		public ThreadSnapDBFieldCodec(Class<DBAnnotatedObject> objectType, Field field,
				int column) {
			super(ThreadSnap.class, objectType, BinaryField.class, field, column);
		}

		protected byte[] encode(ThreadSnap value) {
			ByteBuffer buf = ByteBuffer.allocate(Long.BYTES * 2);
			buf.putLong(value.threadKey);
			buf.putLong(value.snap);
			return buf.array();
		}

		protected ThreadSnap decode(byte[] data) {
			ByteBuffer buf = ByteBuffer.wrap(data);
			ThreadSnap value = new ThreadSnap();
			value.threadKey = buf.getLong();
			value.snap = buf.getLong();
			return value;
		}

		@Override
		public void store(ThreadSnap value, BinaryField f) {
			f.setBinaryData(encode(value));
		}

		@Override
		protected void doStore(DBAnnotatedObject obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			record.setBinaryData(column, encode(getValue(obj)));
		}

		@Override
		protected void doLoad(DBAnnotatedObject obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			setValue(obj, decode(record.getBinaryData(column)));
		}
	}

	@DBAnnotatedField(
		column = THREAD_SNAP_COLUMN_NAME,
		indexed = true,
		codec = ThreadSnapDBFieldCodec.class)
	private ThreadSnap threadSnap;
	@DBAnnotatedField(column = FRAMES_COLUMN_NAME)
	private long[] frameKeys;

	private final DBTraceStackManager manager;

	private DBTraceThread thread;
	private final List<DBTraceStackFrame> frames = new ArrayList<>();

	public DBTraceStack(DBTraceStackManager manager, DBCachedObjectStore<?> store,
			DBRecord record) {
		super(store, record);
		this.manager = manager;
	}

	@Override
	protected void fresh(boolean created) throws IOException {
		if (created) {
			threadSnap = new ThreadSnap();
		}
		else {
			thread = manager.threadManager.getThread(threadSnap.threadKey);
			frames.clear();
			if (frameKeys == null) {
				return;
			}
			for (long k : frameKeys) {
				frames.add(manager.getFrameByKey(k));
			}
		}
	}

	void set(DBTraceThread thread, long snap) {
		this.thread = thread;
		threadSnap.threadKey = thread.getKey();
		threadSnap.snap = snap;
		update(THREAD_SNAP_COLUMN);
	}

	@Override
	public TraceThread getThread() {
		return thread;
	}

	@Override
	public long getSnap() {
		return threadSnap.snap;
	}

	@Override
	public int getDepth() {
		if (frameKeys == null) {
			return 0;
		}
		return frameKeys.length;
	}

	protected void doUpdateFrameKeys() {
		int depth = frames.size();
		frameKeys = new long[depth];
		for (int i = 0; i < depth; i++) {
			frameKeys[i] = frames.get(i).getKey();
		}
		update(FRAMES_COLUMN);
	}

	protected void doUpdateFrameDepths(int start, int end) {
		for (int i = start; i < end; i++) {
			frames.get(i).setLevel(i);
		}
	}

	@Override
	public void setDepth(int depth, boolean atInner) {
		//System.err.println("setDepth(threadKey=" + thread.getKey() + "snap=" + getSnap() +
		//	",depth=" + depth + ",inner=" + atInner + ");");
		int curDepth = frameKeys == null ? 0 : frameKeys.length;
		if (depth == curDepth) {
			return;
		}
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			if (depth < curDepth) {
				List<DBTraceStackFrame> toRemove =
					atInner ? frames.subList(0, curDepth - depth)
							: frames.subList(depth, curDepth);
				for (DBTraceStackFrame frame : toRemove) {
					manager.deleteFrame(frame);
				}
				toRemove.clear();
				if (atInner) {
					doUpdateFrameDepths(0, frames.size());
				}
			}
			else {
				List<DBTraceStackFrame> toAdd =
					Arrays.asList(new DBTraceStackFrame[depth - curDepth]);
				for (int i = 0; i < toAdd.size(); i++) {
					toAdd.set(i, manager.createFrame(this));
				}
				if (atInner) {
					frames.addAll(0, toAdd);
					doUpdateFrameDepths(0, frames.size());
				}
				else {
					frames.addAll(toAdd);
					doUpdateFrameDepths(frames.size() - toAdd.size(), frames.size());
				}
			}
			doUpdateFrameKeys();
		}
		manager.trace
				.setChanged(new TraceChangeRecord<>(TraceStackChangeType.CHANGED, null, this));
	}

	@Override
	public DBTraceStackFrame getFrame(int level, boolean ensureDepth) {
		if (ensureDepth) {
			try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
				if (level >= frames.size()) {
					setDepth(level + 1, false);
				}
				return frames.get(level);
			}
		}
		else {
			try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
				if (level >= frames.size()) {
					return null;
				}
				return frames.get(level);
			}
		}
	}

	@Override
	public List<TraceStackFrame> getFrames() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			return List.copyOf(frames);
		}
	}

	@Override
	public void delete() {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			for (DBTraceStackFrame frame : frames) {
				manager.deleteFrame(frame);
			}
			manager.deleteStack(this);
		}
		manager.trace
				.setChanged(new TraceChangeRecord<>(TraceStackChangeType.DELETED, null, this));
	}
}
