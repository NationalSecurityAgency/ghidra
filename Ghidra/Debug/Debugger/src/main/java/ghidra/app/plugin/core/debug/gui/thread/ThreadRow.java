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
package ghidra.app.plugin.core.debug.gui.thread;

import com.google.common.collect.Range;

import ghidra.app.services.DebuggerModelService;
import ghidra.app.services.TraceRecorder;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.database.UndoableTransaction;

public class ThreadRow {
	private final DebuggerModelService service;
	private final TraceThread thread;

	public ThreadRow(DebuggerModelService service, TraceThread thread) {
		this.service = service;
		this.thread = thread;
	}

	public TraceThread getThread() {
		return thread;
	}

	public Trace getTrace() {
		return thread.getTrace();
	}

	public void setName(String name) {
		try (UndoableTransaction tid =
			UndoableTransaction.start(thread.getTrace(), "Renamed thread", true)) {
			thread.setName(name);
		}
	}

	public String getName() {
		return thread.getName();
	}

	public long getCreationSnap() {
		return thread.getCreationSnap();
	}

	// TODO: Use a renderer to make this transformation instead, otherwise sorting is off.
	public String getDestructionSnap() {
		long snap = thread.getDestructionSnap();
		return snap == Long.MAX_VALUE ? "" : Long.toString(snap);
	}

	public Range<Long> getLifespan() {
		return thread.getLifespan();
	}

	public void setComment(String comment) {
		try (UndoableTransaction tid =
			UndoableTransaction.start(thread.getTrace(), "Renamed thread", true)) {
			thread.setComment(comment);
		}
	}

	public String getComment() {
		return thread.getComment();
	}

	public ThreadState getState() {
		if (!thread.isAlive()) {
			return ThreadState.TERMINATED;
		}
		if (service == null) {
			return ThreadState.ALIVE;
		}
		TraceRecorder recorder = service.getRecorder(thread.getTrace());
		if (recorder == null) {
			return ThreadState.ALIVE;
		}
		TargetExecutionState targetState = recorder.getTargetThreadState(thread);
		if (targetState == null) {
			return ThreadState.UNKNOWN;
		}
		switch (targetState) {
			case ALIVE:
				return ThreadState.ALIVE;
			case INACTIVE:
				return ThreadState.UNKNOWN;
			case RUNNING:
				return ThreadState.RUNNING;
			case STOPPED:
				return ThreadState.STOPPED;
			case TERMINATED:
				return ThreadState.TERMINATED;
		}
		throw new AssertionError();
	}

	@Override
	public String toString() {
		return getName();
	}
}
