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
package ghidra.app.plugin.core.debug.service.breakpoint;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import ghidra.app.services.TraceRecorder;
import ghidra.async.AsyncUtils;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;

public class LoneLogicalBreakpoint implements LogicalBreakpointInternal {
	private final Set<Trace> justThisTrace;
	private final TraceBreakpointSet breaks;
	private final long length;
	private final Set<TraceBreakpointKind> kinds;

	public LoneLogicalBreakpoint(TraceRecorder recorder, Address address, long length,
			Collection<TraceBreakpointKind> kinds) {
		this.breaks = new TraceBreakpointSet(recorder, address);
		this.length = length;
		this.kinds = Set.copyOf(kinds);

		this.justThisTrace = Set.of(recorder.getTrace());
	}

	@Override
	public String toString() {
		return String.format("<%s trace=%s>", getClass().getSimpleName(), breaks);
	}

	@Override
	public boolean isEmpty() {
		return breaks.isEmpty();
	}

	@Override
	public long getLength() {
		return length;
	}

	@Override
	public Set<TraceBreakpointKind> getKinds() {
		return kinds;
	}

	@Override
	public ProgramLocation getProgramLocation() {
		return null;
	}

	@Override
	public Bookmark getProgramBookmark() {
		return null;
	}

	@Override
	public void setTraceAddress(TraceRecorder recorder, Address address) {
		throw new AssertionError();
	}

	@Override
	public Set<TraceBreakpoint> getTraceBreakpoints() {
		return new HashSet<>(breaks.getBreakpoints());
	}

	@Override
	public Set<TraceBreakpoint> getTraceBreakpoints(Trace trace) {
		return breaks.getTrace() != trace ? Set.of() : getTraceBreakpoints();
	}

	@Override
	public Set<Trace> getMappedTraces() {
		return justThisTrace;
	}

	@Override
	public Set<Trace> getParticipatingTraces() {
		if (breaks.isEmpty()) {
			return Set.of();
		}
		return justThisTrace;
	}

	@Override
	public Address getTraceAddress(Trace trace) {
		if (trace != breaks.getTrace()) {
			return null;
		}
		return breaks.getAddress();
	}

	@Override
	public DomainObject getDomainObject() {
		return breaks.getTrace();
	}

	@Override
	public Address getAddress() {
		return breaks.getAddress();
	}

	@Override
	public Enablement computeEnablementForProgram(Program program) {
		return Enablement.NONE;
	}

	@Override
	public Enablement computeEnablementForTrace(Trace trace) {
		if (trace != breaks.getTrace()) {
			return Enablement.NONE;
		}
		return ProgramEnablement.NONE.combineTrace(breaks.computeEnablement());
	}

	@Override
	public Enablement computeEnablement() {
		return ProgramEnablement.NONE.combineTrace(breaks.computeEnablement());
	}

	@Override
	public void enableForProgram() {
		// Ignore silently
	}

	@Override
	public void disableForProgram() {
		// Ignore silently
	}

	@Override
	public void deleteForProgram() {
		// Ignore silently
	}

	@Override
	public CompletableFuture<Void> enableForTrace(Trace trace) {
		if (trace != breaks.getTrace()) {
			// Ignore silently
			return AsyncUtils.NIL;
		}
		return enable();
	}

	@Override
	public CompletableFuture<Void> disableForTrace(Trace trace) {
		if (trace != breaks.getTrace()) {
			// Ignore silently
			return AsyncUtils.NIL;
		}
		return disable();
	}

	@Override
	public CompletableFuture<Void> deleteForTrace(Trace trace) {
		if (trace != breaks.getTrace()) {
			// Ignore silently
			return AsyncUtils.NIL;
		}
		return delete();
	}

	@Override
	public void planEnable(BreakpointActionSet actions, Trace trace) {
		if (trace != null && trace != breaks.getTrace()) {
			return;
		}
		breaks.planEnable(actions, length, kinds);
	}

	@Override
	public CompletableFuture<Void> enable() {
		BreakpointActionSet actions = new BreakpointActionSet();
		planEnable(actions, null);
		return actions.execute();
	}

	@Override
	public void planDisable(BreakpointActionSet actions, Trace trace) {
		if (trace != null && trace != breaks.getTrace()) {
			return;
		}
		breaks.planDisable(actions, length, kinds);
	}

	@Override
	public CompletableFuture<Void> disable() {
		BreakpointActionSet actions = new BreakpointActionSet();
		planDisable(actions, null);
		return actions.execute();
	}

	@Override
	public void planDelete(BreakpointActionSet actions, Trace trace) {
		if (trace != null && trace != breaks.getTrace()) {
			return;
		}
		breaks.planDelete(actions, length, kinds);
	}

	@Override
	public CompletableFuture<Void> delete() {
		BreakpointActionSet actions = new BreakpointActionSet();
		planDelete(actions, null);
		return actions.execute();
	}

	@Override
	public boolean canMerge(Program program, Bookmark bookmark) {
		return false;
	}

	@Override
	public boolean canMerge(TraceBreakpoint breakpoint) {
		if (!Objects.equals(kinds, breakpoint.getKinds())) {
			return false;
		}
		return breaks.canMerge(breakpoint);
	}

	@Override
	public boolean trackBreakpoint(Bookmark bookmark) {
		throw new AssertionError();
	}

	@Override
	public boolean trackBreakpoint(TraceBreakpoint breakpoint) {
		return breaks.add(breakpoint);
	}

	@Override
	public boolean untrackBreakpoint(Program program, Bookmark bookmark) {
		return false;
	}

	@Override
	public boolean untrackBreakpoint(TraceBreakpoint breakpoint) {
		return breaks.remove(breakpoint);
	}
}
