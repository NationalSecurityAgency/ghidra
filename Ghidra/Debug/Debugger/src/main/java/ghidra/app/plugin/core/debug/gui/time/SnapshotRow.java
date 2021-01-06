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
package ghidra.app.plugin.core.debug.gui.time;

import java.util.Date;

import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.DateUtils;
import ghidra.util.database.UndoableTransaction;

public class SnapshotRow {
	//private static final DateFormat FORMAT = DateFormat.getDateTimeInstance();

	private final Trace trace;
	private final TraceSnapshot snapshot;

	public SnapshotRow(Trace trace, TraceSnapshot snapshot) {
		this.trace = snapshot.getTrace();
		this.snapshot = snapshot;
	}

	public TraceSnapshot getSnapshot() {
		return snapshot;
	}

	public long getSnap() {
		return snapshot.getKey();
	}

	public String getTimeStamp() {
		return DateUtils.formatDateTimestamp(new Date(snapshot.getRealTime()));
	}

	public String getEventThreadName() {
		TraceThread thread = snapshot.getEventThread();
		return thread == null ? "" : thread.getName();
	}

	public String getSchedule() {
		return snapshot.getScheduleString();
	}

	public String getDescription() {
		return snapshot.getDescription();
	}

	public void setDescription(String description) {
		try (UndoableTransaction tid =
			UndoableTransaction.start(trace, "Modify snapshot description", false)) {
			snapshot.setDescription(description);
			tid.commit();
		}
	}
}
