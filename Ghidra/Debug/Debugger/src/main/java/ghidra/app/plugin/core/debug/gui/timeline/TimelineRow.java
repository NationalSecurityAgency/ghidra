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
package ghidra.app.plugin.core.debug.gui.timeline;

import com.google.common.collect.Range;

import ghidra.app.services.DebuggerModelService;
import ghidra.app.services.TraceRecorder;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.trace.model.Trace;
import ghidra.util.database.UndoableTransaction;

public class TimelineRow {
	private final DebuggerModelService service;
	private final TraceObject object;

	public TimelineRow(DebuggerModelService service, TraceObject object) {
		this.service = service;
		this.object = object;
	}

	public TraceObject getObject() {
		return object;
	}

	public Trace getTrace() {
		return object.getTrace();
	}

	public void setName(String name) {
		try (UndoableTransaction tid =
			UndoableTransaction.start(object.getTrace(), "Renamed thread", true)) {
			object.setName(name);
		}
	}

	public String getName() {
		return object.getName();
	}

	public long getCreationTick() {
		return object.getCreationSnap();
	}

	public String getDestructionTick() {
		long tick = object.getDestructionSnap();
		return tick == Long.MAX_VALUE ? "" : Long.toString(tick);
	}

	public Range<Long> getLifespan() {
		return object.getLifespan();
	}

	public void setComment(String comment) {
		try (UndoableTransaction tid =
			UndoableTransaction.start(object.getTrace(), "Renamed thread", true)) {
			object.setComment(comment);
		}
	}

	public String getComment() {
		return object.getComment();
	}

	public TimelineState getState() {
		if (!object.isAlive()) {
			return TimelineState.TERMINATED;
		}
		TraceRecorder recorder = service.getRecorder(object.getTrace());
		if (recorder == null) {
			return TimelineState.ALIVE;
		}
		TargetExecutionState targetState = recorder.getTargetThreadState(object);
		if (targetState == null) {
			return TimelineState.UNKNOWN;
		}
		switch (targetState) {
			case ALIVE:
				return TimelineState.ALIVE;
			case INACTIVE:
				return TimelineState.UNKNOWN;
			case RUNNING:
				return TimelineState.RUNNING;
			case STOPPED:
				return TimelineState.STOPPED;
			case TERMINATED:
				return TimelineState.TERMINATED;
		}
		throw new AssertionError();
	}

	@Override
	public String toString() {
		return getName();
	}
}
