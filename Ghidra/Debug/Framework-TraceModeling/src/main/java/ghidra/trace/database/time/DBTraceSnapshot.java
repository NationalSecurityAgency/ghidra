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
package ghidra.trace.database.time;

import java.io.IOException;

import db.DBRecord;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceSnapshotChangeType;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSchedule;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
import ghidra.util.Msg;
import ghidra.util.database.*;
import ghidra.util.database.annot.*;

@DBAnnotatedObjectInfo(version = 0)
public class DBTraceSnapshot extends DBAnnotatedObject implements TraceSnapshot {
	protected static final String TABLE_NAME = "Snapshots";

	protected static final String REAL_TIME_COLUMN_NAME = "RealTime";
	protected static final String SCHEDULE_COLUMN_NAME = "Schedule";
	protected static final String DESCRIPTION_COLUMN_NAME = "Description";
	protected static final String THREAD_COLUMN_NAME = "Thread";

	@DBAnnotatedColumn(REAL_TIME_COLUMN_NAME)
	static DBObjectColumn REAL_TIME_COLUMN;
	@DBAnnotatedColumn(SCHEDULE_COLUMN_NAME)
	static DBObjectColumn SCHEDULE_COLUMN;
	@DBAnnotatedColumn(DESCRIPTION_COLUMN_NAME)
	static DBObjectColumn DESCRIPTION_COLUMN;
	@DBAnnotatedColumn(THREAD_COLUMN_NAME)
	static DBObjectColumn THREAD_COLUMN;

	@DBAnnotatedField(column = REAL_TIME_COLUMN_NAME)
	long realTime; // milliseconds
	@DBAnnotatedField(column = SCHEDULE_COLUMN_NAME, indexed = true)
	String scheduleStr = "";
	@DBAnnotatedField(column = DESCRIPTION_COLUMN_NAME)
	String description;
	@DBAnnotatedField(column = THREAD_COLUMN_NAME)
	long threadKey = -1;

	public final DBTraceTimeManager manager;

	private DBTraceThread eventThread;
	private TraceSchedule schedule;

	public DBTraceSnapshot(DBTraceTimeManager manager, DBCachedObjectStore<?> store,
			DBRecord record) {
		super(store, record);
		this.manager = manager;
	}

	@Override
	protected void fresh(boolean created) throws IOException {
		if (created) {
			threadKey = -1;
			scheduleStr = "";
		}
		else {
			eventThread = manager.threadManager.getThread(threadKey);
			if (!"".equals(scheduleStr)) {
				try {
					schedule = TraceSchedule.parse(scheduleStr);
				}
				catch (IllegalArgumentException e) {
					Msg.error(this, "Could not parse schedule: " + schedule, e);
					// Leave as null (or previous value?)
				}
			}
		}
	}

	@Override
	public String toString() {
		return String.format(
			"<DBTraceSnapshot key=%d, realTime=%d, schedule='%s', description='%s'>",
			key, realTime, scheduleStr, description);
	}

	protected void set(long realTime, String description) {
		this.realTime = realTime;
		this.description = description;
		update(REAL_TIME_COLUMN, DESCRIPTION_COLUMN);
	}

	@Override
	public Trace getTrace() {
		return manager.trace;
	}

	@Override
	public long getRealTime() {
		return realTime;
	}

	@Override
	public void setRealTime(long millis) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			this.realTime = millis;
			update(REAL_TIME_COLUMN);
		}
		manager.trace.setChanged(
			new TraceChangeRecord<>(TraceSnapshotChangeType.CHANGED, null, this));
	}

	@Override
	public String getDescription() {
		return description;
	}

	@Override
	public void setDescription(String description) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			this.description = description;
			update(DESCRIPTION_COLUMN);
		}
		manager.trace.setChanged(
			new TraceChangeRecord<>(TraceSnapshotChangeType.CHANGED, null, this));
	}

	@Override
	public TraceThread getEventThread() {
		return eventThread;
	}

	@Override
	public void setEventThread(TraceThread thread) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			if (thread == null) {
				eventThread = null;
				threadKey = -1;
			}
			else {
				eventThread = manager.threadManager.assertIsMine(thread);
				threadKey = thread.getKey();
			}
			update(THREAD_COLUMN);
		}
		manager.trace.setChanged(
			new TraceChangeRecord<>(TraceSnapshotChangeType.CHANGED, null, this));
	}

	@Override
	public TraceSchedule getSchedule() {
		return schedule;
	}

	@Override
	public String getScheduleString() {
		return scheduleStr;
	}

	@Override
	public void setSchedule(TraceSchedule schedule) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			this.schedule = schedule;
			this.scheduleStr = schedule == null ? "" : schedule.toString();
			update(SCHEDULE_COLUMN);
		}
		manager.trace.setChanged(
			new TraceChangeRecord<>(TraceSnapshotChangeType.CHANGED, null, this));
	}

	@Override
	public void delete() {
		manager.deleteSnapshot(this);
	}
}
