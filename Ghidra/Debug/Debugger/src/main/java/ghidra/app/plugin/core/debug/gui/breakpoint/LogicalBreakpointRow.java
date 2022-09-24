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

import java.util.concurrent.CompletableFuture;

import ghidra.app.services.LogicalBreakpoint;
import ghidra.app.services.LogicalBreakpoint.Mode;
import ghidra.app.services.LogicalBreakpoint.State;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.breakpoint.TraceBreakpointKind.TraceBreakpointKindSet;

public class LogicalBreakpointRow {
	private final DebuggerBreakpointsProvider provider;
	private final LogicalBreakpoint lb;

	public LogicalBreakpointRow(DebuggerBreakpointsProvider provider, LogicalBreakpoint lb) {
		this.provider = provider;
		this.lb = lb;
	}

	@Override
	public String toString() {
		return "<Row " + lb + ">";
	}

	public LogicalBreakpoint getLogicalBreakpoint() {
		return lb;
	}

	public State getState() {
		return provider.isFilterByCurrentTrace() && provider.currentTrace != null
				? lb.computeStateForTrace(provider.currentTrace)
				: lb.computeState();
	}

	public void setState(State state) {
		assert state.isNormal();
		setEnabled(state.isEnabled());
	}

	public Mode getMode() {
		return getState().mode;
	}

	public void setEnabled(boolean enabled) {
		boolean filter = provider.isFilterByCurrentTrace();
		if (enabled) {
			String status = lb.generateStatusEnable(filter ? provider.currentTrace : null);
			if (status != null) {
				provider.getTool().setStatusInfo(status, true);
			}
			lb.enableForProgram();
			CompletableFuture<Void> future = filter
					? lb.enableForTrace(provider.currentTrace)
					: lb.enable();
			future.exceptionally(ex -> {
				provider.breakpointError("Toggle Breakpoint", "Could not enable breakpoint", ex);
				return null;
			});
		}
		else {
			lb.disableForProgram();
			CompletableFuture<Void> future = filter
					? lb.disableForTrace(provider.currentTrace)
					: lb.disable();
			future.exceptionally(ex -> {
				provider.breakpointError("Toggle Breakpoint", "Could not disable breakpoint", ex);
				return null;
			});
		}
	}

	public String getName() {
		return lb.getName();
	}

	public void setName(String name) {
		lb.setName(name);
	}

	public boolean isNamable() {
		return lb.getProgramBookmark() != null;
	}

	public String getImageName() {
		Program program = lb.getProgram();
		if (program == null) {
			return "";
		}
		DomainFile df = program.getDomainFile();
		if (df == null) {
			return program.getName();
		}
		return df.getName();
	}

	public Address getAddress() {
		return lb.getAddress();
	}

	public long getLength() {
		return lb.getLength();
	}

	public DomainObject getDomainObject() {
		return lb.getDomainObject();
	}

	public String getKinds() {
		return TraceBreakpointKindSet.encode(lb.getKinds());
	}

	/**
	 * Count the number of locations, enabled and disabled, among live traces
	 * 
	 * @return the count
	 */
	public int getLocationCount() {
		if (provider.isFilterByCurrentTrace()) {
			return lb.getTraceBreakpoints(provider.currentTrace).size();
		}
		return lb.getTraceBreakpoints().size();
	}

	/**
	 * Check if it has mapped locations, regardless of whether those locations are present
	 * 
	 * @return true if mapped (or mappable), false if not.
	 */
	public boolean isMapped() {
		if (provider.isFilterByCurrentTrace()) {
			if (provider.currentTrace == null) {
				return false;
			}
			return lb.getMappedTraces().contains(provider.currentTrace);
		}
		return !lb.getMappedTraces().isEmpty();
	}
}
