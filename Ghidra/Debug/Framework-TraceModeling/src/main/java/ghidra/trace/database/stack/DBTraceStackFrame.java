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
import java.util.Objects;

import db.DBRecord;
import ghidra.lifecycle.Internal;
import ghidra.program.model.address.Address;
import ghidra.trace.database.address.DBTraceOverlaySpaceAdapter;
import ghidra.trace.database.address.DBTraceOverlaySpaceAdapter.AddressDBFieldCodec;
import ghidra.trace.database.address.DBTraceOverlaySpaceAdapter.DecodesAddresses;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.trace.util.TraceEvents;
import ghidra.util.LockHold;
import ghidra.util.database.*;
import ghidra.util.database.annot.*;

/**
 * The implementation of a stack frame, directly via a database object
 * 
 * <p>
 * Version history:
 * <ul>
 * <li>1: Change {@link #pc} to 10-byte fixed encoding, make it sparse, so optional</li>
 * <li>0: Initial version and previous unversioned implementations</li>
 * </ul>
 */
@DBAnnotatedObjectInfo(version = 1)
public class DBTraceStackFrame extends DBAnnotatedObject
		implements TraceStackFrame, DecodesAddresses {
	public static final String TABLE_NAME = "StackFrames";

	static final String STACK_COLUMN_NAME = "Stack";
	static final String LEVEL_COLUMN_NAME = "Level";
	static final String PC_COLUMN_NAME = "PC";
	static final String COMMENT_COLUMN_NAME = "Comment";

	@DBAnnotatedColumn(STACK_COLUMN_NAME)
	static DBObjectColumn STACK_COLUMN;
	@DBAnnotatedColumn(LEVEL_COLUMN_NAME)
	static DBObjectColumn LEVEL_COLUMN;
	@DBAnnotatedColumn(PC_COLUMN_NAME)
	static DBObjectColumn PC_COLUMN;
	@DBAnnotatedColumn(COMMENT_COLUMN_NAME)
	static DBObjectColumn COMMENT_COLUMN;

	@DBAnnotatedField(column = STACK_COLUMN_NAME)
	private long stackKey;
	@DBAnnotatedField(column = LEVEL_COLUMN_NAME)
	private int level;
	@DBAnnotatedField(
		column = PC_COLUMN_NAME,
		indexed = true,
		codec = AddressDBFieldCodec.class,
		sparse = true)
	private Address pc;
	@DBAnnotatedField(column = COMMENT_COLUMN_NAME)
	private String comment;

	private final DBTraceStackManager manager;

	private DBTraceStack stack;

	public DBTraceStackFrame(DBTraceStackManager manager, DBCachedObjectStore<?> store,
			DBRecord record) {
		super(store, record);
		this.manager = manager;
	}

	@Override
	public DBTraceOverlaySpaceAdapter getOverlaySpaceAdapter() {
		return manager.overlayAdapter;
	}

	@Override
	protected void fresh(boolean created) throws IOException {
		if (!created) {
			stack = manager.getStackByKey(stackKey);
		}
	}

	public void set(DBTraceStack stack) {
		this.stack = stack;
		this.stackKey = stack.getKey();
		update(STACK_COLUMN);
	}

	@Override
	public DBTraceStack getStack() {
		return stack;
	}

	@Override
	public int getLevel() {
		return level;
	}

	@Override
	public Address getProgramCounter(long snap) {
		return pc;
	}

	@Override
	public void setProgramCounter(Lifespan span, Address pc) {
		//System.err.println("setPC(threadKey=" + stack.getThread().getKey() + ",snap=" +
		//	stack.getSnap() + ",level=" + level + ",pc=" + pc + ");");
		manager.trace.assertValidAddress(pc);
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			if (Objects.equals(this.pc, pc)) {
				return;
			}
			this.pc = pc;
			update(PC_COLUMN);
		}
		manager.trace.setChanged(
			new TraceChangeRecord<>(TraceEvents.STACK_CHANGED, null, stack, 0L, span.lmin()));
	}

	@Override
	public String getComment(long snap) {
		return comment;
	}

	@Override
	public void setComment(long snap, String comment) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			this.comment = comment;
			update(COMMENT_COLUMN);
		}
		manager.trace.setChanged(
			new TraceChangeRecord<>(TraceEvents.STACK_CHANGED, null, stack, 0L, snap));
	}

	@Internal
	protected void setLevel(int level) {
		this.level = level;
		update(LEVEL_COLUMN);
	}
}
