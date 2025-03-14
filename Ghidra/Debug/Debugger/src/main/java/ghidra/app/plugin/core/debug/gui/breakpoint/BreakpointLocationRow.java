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

import java.util.Set;
import java.util.stream.Collectors;

import db.Transaction;
import ghidra.debug.api.breakpoint.LogicalBreakpoint;
import ghidra.debug.api.breakpoint.LogicalBreakpoint.State;
import ghidra.pcode.exec.SleighUtils;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.breakpoint.TraceBreakpoint;

public class BreakpointLocationRow {
	private final DebuggerBreakpointsProvider provider;
	private final TraceBreakpoint loc;

	public BreakpointLocationRow(DebuggerBreakpointsProvider provider, TraceBreakpoint loc) {
		this.provider = provider;
		this.loc = loc;
	}

	private long getSnap() {
		return provider.traceManager.getCurrentFor(loc.getTrace()).getSnap();
	}

	public String getName() {
		return loc.getName(getSnap());
	}

	public boolean isEnabled() {
		return loc.isEnabled(getSnap());
	}

	public State getState() {
		LogicalBreakpoint lb = provider.breakpointService.getBreakpoint(loc);
		if (lb == null) {
			return State.NONE; // Should only happen in transition
		}
		return lb.computeStateForLocation(loc);
	}

	public void setEnabled(boolean enabled) {
		if (enabled) {
			provider.breakpointService.enableLocs(Set.of(loc)).exceptionally(ex -> {
				provider.breakpointError("Toggle breakpoint", "Could not enable breakpoint", ex);
				return null;
			});
		}
		else {
			provider.breakpointService.disableLocs(Set.of(loc)).exceptionally(ex -> {
				provider.breakpointError("Toggle breakpoint", "Could not disable breakpoint", ex);
				return null;
			});
		}
	}

	public void setState(State state) {
		assert state.isNormal();
		setEnabled(state.isEnabled());
	}

	public void setName(String name) {
		try (Transaction tid = loc.getTrace().openTransaction("Set breakpoint name")) {
			loc.setName(getSnap(), name);
		}
	}

	public Address getAddress() {
		return loc.getMinAddress(getSnap());
	}

	public ProgramLocation getProgramLocation() {
		return new ProgramLocation(loc.getTrace().getProgramView(), getAddress());
	}

	public String getTraceName() {
		return loc.getTrace().getName();
	}

	public String getThreads() {
		long snap = getSnap();
		return loc.getThreads(snap)
				.stream()
				.map(t -> t.getName(snap))
				.collect(Collectors.toSet())
				.toString();
	}

	public String getComment() {
		return loc.getComment(getSnap());
	}

	public void setComment(String comment) {
		try (Transaction tid = loc.getTrace().openTransaction("Set breakpoint comment")) {
			loc.setComment(getSnap(), comment);
		}
	}

	public boolean hasSleigh() {
		return !SleighUtils.UNCONDITIONAL_BREAK.equals(loc.getEmuSleigh(getSnap()));
	}

	public TraceBreakpoint getTraceBreakpoint() {
		return loc;
	}
}
