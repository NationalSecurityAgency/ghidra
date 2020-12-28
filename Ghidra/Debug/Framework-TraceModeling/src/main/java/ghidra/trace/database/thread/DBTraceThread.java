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

import com.google.common.collect.Range;

import db.DBRecord;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceThreadChangeType;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
import ghidra.util.database.*;
import ghidra.util.database.annot.*;
import ghidra.util.exception.DuplicateNameException;

@DBAnnotatedObjectInfo(version = 0)
public class DBTraceThread extends DBAnnotatedObject implements TraceThread {
	protected static final String TABLE_NAME = "Threads";

	static final String PATH_COLUMN_NAME = "Path";
	static final String NAME_COLUMN_NAME = "Name";
	static final String CREATION_SNAP_COLUMN_NAME = "CreatedAt";
	static final String DESTRUCTION_SNAP_COLUMN_NAME = "DestroyedAt";
	static final String COMMENT_COLUMN_NAME = "Comment";

	@DBAnnotatedColumn(PATH_COLUMN_NAME)
	static DBObjectColumn PATH_COLUMN;
	@DBAnnotatedColumn(NAME_COLUMN_NAME)
	static DBObjectColumn NAME_COLUMN;
	@DBAnnotatedColumn(CREATION_SNAP_COLUMN_NAME)
	static DBObjectColumn CREATION_SNAP_COLUMN;
	@DBAnnotatedColumn(DESTRUCTION_SNAP_COLUMN_NAME)
	static DBObjectColumn DESTRUCTION_SNAP_COLUMN;
	@DBAnnotatedColumn(COMMENT_COLUMN_NAME)
	static DBObjectColumn COMMENT_COLUMN;

	@DBAnnotatedField(column = PATH_COLUMN_NAME, indexed = true)
	private String path;
	@DBAnnotatedField(column = NAME_COLUMN_NAME)
	private String name;
	@DBAnnotatedField(column = CREATION_SNAP_COLUMN_NAME)
	private long creationSnap;
	@DBAnnotatedField(column = DESTRUCTION_SNAP_COLUMN_NAME)
	private long destructionSnap;
	@DBAnnotatedField(column = COMMENT_COLUMN_NAME)
	private String comment;

	public final DBTraceThreadManager manager;

	private Range<Long> lifespan;

	protected DBTraceThread(DBTraceThreadManager manager, DBCachedObjectStore<?> store,
			DBRecord record) {
		super(store, record);
		this.manager = manager;
	}

	public void set(String path, String name, Range<Long> lifespan) {
		this.path = path;
		this.name = name;
		this.creationSnap = DBTraceUtils.lowerEndpoint(lifespan);
		this.destructionSnap = DBTraceUtils.upperEndpoint(lifespan);
		update(PATH_COLUMN, NAME_COLUMN, CREATION_SNAP_COLUMN, DESTRUCTION_SNAP_COLUMN);

		this.lifespan = lifespan;
	}

	@Override
	protected void fresh(boolean created) throws IOException {
		if (created) {
			return;
		}
		lifespan = DBTraceUtils.toRange(creationSnap, destructionSnap);
	}

	@Override
	public String toString() {
		return "TraceThread: " + getName();
	}

	@Override
	public Trace getTrace() {
		return manager.trace;
	}

	@Override
	public String getPath() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			return path;
		}
	}

	@Override
	public String getName() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			return name;
		}
	}

	@Override
	public void setName(String name) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			this.name = name;
			update(NAME_COLUMN);
			manager.trace
					.setChanged(new TraceChangeRecord<>(TraceThreadChangeType.CHANGED, null, this));
		}
	}

	@Override
	public void setCreationSnap(long creationSnap) throws DuplicateNameException {
		setLifespan(DBTraceUtils.toRange(creationSnap, destructionSnap));
	}

	@Override
	public long getCreationSnap() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			return creationSnap;
		}
	}

	@Override
	public void setDestructionSnap(long destructionSnap) throws DuplicateNameException {
		setLifespan(DBTraceUtils.toRange(creationSnap, destructionSnap));
	}

	@Override
	public long getDestructionSnap() {
		return destructionSnap;
	}

	@Override
	public void setLifespan(Range<Long> newLifespan) throws DuplicateNameException {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			manager.checkConflictingPath(this, path, newLifespan);
			Range<Long> oldLifespan = this.lifespan;
			this.creationSnap = DBTraceUtils.lowerEndpoint(newLifespan);
			this.destructionSnap = DBTraceUtils.upperEndpoint(newLifespan);
			update(CREATION_SNAP_COLUMN, DESTRUCTION_SNAP_COLUMN);

			this.lifespan = newLifespan;

			manager.trace.setChanged(
				new TraceChangeRecord<>(TraceThreadChangeType.LIFESPAN_CHANGED, null,
					this, oldLifespan, newLifespan));
		}
	}

	@Override
	public Range<Long> getLifespan() {
		return lifespan;
	}

	@Override
	public void setComment(String comment) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			this.comment = comment;
			update(COMMENT_COLUMN);
			manager.trace
					.setChanged(new TraceChangeRecord<>(TraceThreadChangeType.CHANGED, null, this));
		}
	}

	@Override
	public String getComment() {
		return comment;
	}

	@Override
	public void delete() {
		manager.deleteThread(this);
	}
}
