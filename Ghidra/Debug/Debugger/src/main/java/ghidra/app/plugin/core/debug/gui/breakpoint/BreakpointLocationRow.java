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
package ghidra.app.plugin.core.debug.gui.breakpoint;

import java.util.stream.Collectors;

import ghidra.app.services.TraceRecorder;
import ghidra.dbg.target.TargetBreakpointLocation;
import ghidra.program.model.address.Address;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.database.UndoableTransaction;

public class BreakpointLocationRow {
	private final DebuggerBreakpointsProvider provider;
	private final TraceBreakpoint loc;

	public BreakpointLocationRow(DebuggerBreakpointsProvider provider, TraceBreakpoint loc) {
		this.provider = provider;
		this.loc = loc;
	}

	public String getName() {
		return loc.getName();
	}

	public boolean isEnabled() {
		return loc.isEnabled();
	}

	public void setEnabled(boolean enabled) {
		// TODO: Make this toggle the individual location, if possible, not the whole spec.
		TraceRecorder recorder = provider.modelService.getRecorder(loc.getTrace());
		TargetBreakpointLocation bpt = recorder.getTargetBreakpoint(loc);
		if (enabled) {
			bpt.getSpecification().enable().exceptionally(ex -> {
				provider.breakpointError("Toggle breakpoint", "Could not enable breakpoint", ex);
				return null;
			});
		}
		else {
			bpt.getSpecification().disable().exceptionally(ex -> {
				provider.breakpointError("Toggle breakpoint", "Could not disable breakpoint", ex);
				return null;
			});
		}
	}

	public void setName(String name) {
		try (UndoableTransaction tid =
			UndoableTransaction.start(loc.getTrace(), "Set breakpoint name", true)) {
			loc.setName(name);
		}
	}

	public Address getAddress() {
		return loc.getMinAddress();
	}

	public String getTraceName() {
		return loc.getTrace().getName();
	}

	public String getThreads() {
		return loc.getThreads()
				.stream()
				.map(TraceThread::getName)
				.collect(Collectors.toSet())
				.toString();
	}

	public String getComment() {
		return loc.getComment();
	}

	public void setComment(String comment) {
		try (UndoableTransaction tid =
			UndoableTransaction.start(loc.getTrace(), "Set breakpoint comment", true)) {
			loc.setComment(comment);
		}
	}

	public TraceBreakpoint getTraceBreakpoint() {
		return loc;
	}
}
