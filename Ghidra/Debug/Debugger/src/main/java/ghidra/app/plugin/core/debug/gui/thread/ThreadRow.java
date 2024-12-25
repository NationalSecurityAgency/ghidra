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

import db.Transaction;
import ghidra.app.plugin.core.debug.gui.action.PCLocationTrackingSpec;
import ghidra.app.plugin.core.debug.gui.action.SPLocationTrackingSpec;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingUtils;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.trace.model.*;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Msg;

public class ThreadRow {
	private final DebuggerThreadsProvider provider;
	private final TraceThread thread;

	public ThreadRow(DebuggerThreadsProvider provider, TraceThread thread) {
		this.provider = provider;
		this.thread = thread;
	}

	public TraceThread getThread() {
		return thread;
	}

	public Trace getTrace() {
		return thread.getTrace();
	}

	public void setName(String name) {
		try (Transaction tx = thread.getTrace().openTransaction("Rename thread")) {
			thread.setName(name);
		}
	}

	public String getName() {
		return thread.getName();
	}

	private Address computeProgramCounter(DebuggerCoordinates coords) {
		// TODO: Cheating a bit. Also, can user configure whether by stack or regs?
		return PCLocationTrackingSpec.INSTANCE.computeTraceAddress(provider.getTool(),
			coords);
	}

	public Address getProgramCounter() {
		DebuggerCoordinates coords = provider.current.thread(thread);
		return computeProgramCounter(coords);
	}

	public Function getFunction() {
		DebuggerCoordinates coords = provider.current.thread(thread);
		Address pc = computeProgramCounter(coords);
		return DebuggerStaticMappingUtils.getFunction(pc, coords, provider.getTool());
	}

	public String getModule() {
		DebuggerCoordinates coords = provider.current.thread(thread);
		Address pc = computeProgramCounter(coords);
		return DebuggerStaticMappingUtils.getModuleName(pc, coords);
	}

	public Address getStackPointer() {
		DebuggerCoordinates coords = provider.current.thread(thread);
		return SPLocationTrackingSpec.INSTANCE.computeTraceAddress(provider.getTool(), coords);
	}

	public long getCreationSnap() {
		return thread.getCreationSnap();
	}

	// TODO: Use a renderer to make this transformation instead, otherwise sorting is off.
	public String getDestructionSnap() {
		long snap = thread.getDestructionSnap();
		return snap == Long.MAX_VALUE ? "" : Long.toString(snap);
	}

	public Lifespan getLifespan() {
		return thread.getLifespan();
	}

	public void setComment(String comment) {
		try (Transaction tx = thread.getTrace().openTransaction("Set thread comment")) {
			thread.setComment(comment);
		}
	}

	public String getComment() {
		return thread.getComment();
	}

	public ThreadState getState() {
		// TODO: Once transition to TraceRmi is complete, this is all in TraceObjectManager
		if (!thread.isAlive()) {
			return ThreadState.TERMINATED;
		}
		if (provider.targetService == null) {
			return ThreadState.ALIVE;
		}
		Target target = provider.targetService.getTarget(thread.getTrace());
		if (target == null) {
			return ThreadState.ALIVE;
		}
		TraceExecutionState state = target.getThreadExecutionState(thread);
		if (state == null) {
			return ThreadState.UNKNOWN;
		}
		switch (state) {
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
		try {
			return getName();
		}
		catch (Exception e) {
			Msg.error(this, "Error rendering as string: " + e);
			return "<ERROR>";
		}
	}
}
