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

import ghidra.app.services.DebuggerModelService;
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

public class MappedLogicalBreakpoint implements LogicalBreakpointInternal {

	private final Set<TraceBreakpointKind> kinds;
	private final long length;

	private final ProgramBreakpoint progBreak;

	// Debuggers tend to allow multiple breakpoints (even of the same kind) at the same address
	// They may have different names and/or different conditions
	private final Map<Trace, TraceBreakpointSet> traceBreaks = new HashMap<>();
	private final Set<Trace> tracesView = Collections.unmodifiableSet(traceBreaks.keySet());

	protected MappedLogicalBreakpoint(Program program, Address progAddr, long length,
			Collection<TraceBreakpointKind> kinds) {
		this.length = length;
		this.kinds = Set.copyOf(kinds);
		this.progBreak = new ProgramBreakpoint(program, progAddr, length, this.kinds);
	}

	@Override
	public String toString() {
		return String.format("<%s prog=%s, traces=%s>", getClass().getSimpleName(), progBreak,
			traceBreaks.values());
	}

	protected boolean hasProgramBreakpoint() {
		return progBreak.getBookmark() != null;
	}

	@Override
	public boolean isEmpty() {
		if (!progBreak.isEmpty()) {
			return false;
		}
		for (TraceBreakpointSet breaks : traceBreaks.values()) {
			if (!breaks.isEmpty()) {
				return false;
			}
		}
		return true;
	}

	protected TraceRecorder requireRecorder(DebuggerModelService modelService, Trace trace) {
		TraceRecorder recorder = modelService.getRecorder(trace);
		if (recorder == null) {
			throw new AssertionError("This trace is not live");
		}
		return recorder;
	}

	/**
	 * TODO: How best to allow the user to control behavior when a new static mapping is created
	 * that could generate new breakpoints in the target. Options:
	 * 
	 * 1) A toggle during mapping creation for how to sync breakpoints.
	 * 
	 * 2) A prompt when the mapping is created, asking the user to sync breakpoints.
	 * 
	 * 3) A UI indicator (probably in the breakpoints provider) that some breakpoints are not in
	 * sync. Different actions for directions of sync.
	 * 
	 * I'm thinking both 1 and 3. Option 2 is probably too abrasive, esp., if several mappings are
	 * created at once.
	 */

	@Override
	public void enableForProgram() {
		progBreak.enable();
	}

	@Override
	public void disableForProgram() {
		progBreak.disable();
	}

	@Override
	public void deleteForProgram() {
		progBreak.deleteFromProgram();
	}

	@Override
	public CompletableFuture<Void> enableForTrace(Trace trace) {
		BreakpointActionSet actions = new BreakpointActionSet();
		TraceBreakpointSet breaks = traceBreaks.get(trace);
		if (breaks == null) {
			return AsyncUtils.NIL;
		}
		breaks.planEnable(actions, length, kinds);
		return actions.execute();
	}

	@Override
	public CompletableFuture<Void> disableForTrace(Trace trace) {
		BreakpointActionSet actions = new BreakpointActionSet();
		TraceBreakpointSet breaks = traceBreaks.get(trace);
		if (breaks == null) {
			return AsyncUtils.NIL;
		}
		breaks.planDisable(actions, length, kinds);
		return actions.execute();
	}

	@Override
	public CompletableFuture<Void> deleteForTrace(Trace trace) {
		BreakpointActionSet actions = new BreakpointActionSet();
		TraceBreakpointSet breaks = traceBreaks.get(trace);
		if (breaks == null) {
			return AsyncUtils.NIL;
		}
		breaks.planDelete(actions, length, kinds);
		return actions.execute();
	}

	@Override
	public void planEnable(BreakpointActionSet actions, Trace trace) {
		if (trace != null) {
			TraceBreakpointSet breaks = traceBreaks.get(trace);
			if (breaks == null) {
				return;
			}
			breaks.planEnable(actions, length, kinds);
			return;
		}
		for (TraceBreakpointSet breaks : traceBreaks.values()) {
			breaks.planEnable(actions, length, kinds);
		}
	}

	@Override
	public CompletableFuture<Void> enable() {
		progBreak.enable();
		BreakpointActionSet actions = new BreakpointActionSet();
		planEnable(actions, null);
		return actions.execute();
		// NOTE: Recorder will cause appropriate updates
	}

	@Override
	public void planDisable(BreakpointActionSet actions, Trace trace) {
		if (trace != null) {
			TraceBreakpointSet breaks = traceBreaks.get(trace);
			if (breaks == null) {
				return;
			}
			breaks.planDisable(actions, length, kinds);
			return;
		}
		for (TraceBreakpointSet breaks : traceBreaks.values()) {
			breaks.planDisable(actions, length, kinds);
		}
	}

	@Override
	public CompletableFuture<Void> disable() {
		progBreak.disable(); // Will generate disabled breakpoint if absent
		BreakpointActionSet actions = new BreakpointActionSet();
		planDisable(actions, null);
		return actions.execute();
		// NOTE: Recorder will cause appropriate updates
	}

	@Override
	public void planDelete(BreakpointActionSet actions, Trace trace) {
		if (trace != null) {
			TraceBreakpointSet breaks = traceBreaks.get(trace);
			if (breaks == null) {
				return;
			}
			breaks.planDelete(actions, length, kinds);
			return;
		}
		for (TraceBreakpointSet breaks : traceBreaks.values()) {
			breaks.planDelete(actions, length, kinds);
		}
	}

	@Override
	public CompletableFuture<Void> delete() {
		progBreak.deleteFromProgram();
		BreakpointActionSet actions = new BreakpointActionSet();
		planDelete(actions, null);
		return actions.execute();
		// NOTE: Recorder will cause appropriate updates
	}

	@Override
	public Bookmark getProgramBookmark() {
		return progBreak.getBookmark();
	}

	@Override
	public ProgramLocation getProgramLocation() {
		return progBreak.getLocation();
	}

	@Override
	public void setTraceAddress(TraceRecorder recorder, Address address) {
		traceBreaks.put(recorder.getTrace(), new TraceBreakpointSet(recorder, address));
	}

	@Override
	public Set<TraceBreakpoint> getTraceBreakpoints() {
		Set<TraceBreakpoint> result = new HashSet<>();
		for (TraceBreakpointSet breaks : traceBreaks.values()) {
			result.addAll(breaks.getBreakpoints());
		}
		return result;
	}

	@Override
	public Set<TraceBreakpoint> getTraceBreakpoints(Trace trace) {
		TraceBreakpointSet breaks = traceBreaks.get(trace);
		return breaks == null ? Set.of() : new HashSet<>(breaks.getBreakpoints());
	}

	@Override
	public Set<Trace> getMappedTraces() {
		return tracesView;
	}

	@Override
	public Set<Trace> getParticipatingTraces() {
		Set<Trace> result = new HashSet<>();
		for (TraceBreakpointSet breaks : traceBreaks.values()) {
			if (breaks.isEmpty()) {
				continue;
			}
			result.add(breaks.getTrace());
		}
		return result;
	}

	@Override
	public Address getTraceAddress(Trace trace) {
		TraceBreakpointSet breaks = traceBreaks.get(trace);
		if (breaks == null) {
			return null;
		}
		return breaks.getAddress();
	}

	@Override
	public DomainObject getDomainObject() {
		return progBreak.getProgram();
	}

	@Override
	public Address getAddress() {
		return progBreak.getLocation().getByteAddress();
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
	public Enablement computeEnablementForProgram(Program program) {
		if (progBreak.getProgram() != program) {
			return Enablement.NONE;
		}
		return computeEnablement();
	}

	@Override
	public Enablement computeEnablementForTrace(Trace trace) {
		TraceBreakpointSet breaks = traceBreaks.get(trace);
		ProgramEnablement progEn = progBreak.computeEnablement();
		if (breaks == null) {
			return TraceEnablement.MISSING.combineProgram(progEn);
		}
		// NB: Order matters. Trace is primary
		return breaks.computeEnablement().combineProgram(progEn);
	}

	@Override
	public Enablement computeEnablement() {
		ProgramEnablement progEn = progBreak.computeEnablement();
		TraceEnablement traceEn = TraceEnablement.NONE;
		for (TraceBreakpointSet breaks : traceBreaks.values()) {
			TraceEnablement tEn = breaks.computeEnablement();
			traceEn = traceEn.combine(tEn);
			if (traceEn == TraceEnablement.MIXED) {
				break;
			}
		}
		return progEn.combineTrace(traceEn);
	}

	@Override
	public boolean canMerge(Program program, Bookmark bookmark) {
		return progBreak.canMerge(program, bookmark);
	}

	@Override
	public boolean canMerge(TraceBreakpoint breakpoint) {
		TraceBreakpointSet breaks = traceBreaks.get(breakpoint.getTrace());
		if (breaks == null) {
			throw new AssertionError();
		}
		if (length != breakpoint.getLength()) {
			return false;
		}
		if (!Objects.equals(kinds, breakpoint.getKinds())) {
			return false;
		}
		return breaks.canMerge(breakpoint);
	}

	@Override
	public boolean trackBreakpoint(Bookmark bookmark) {
		return progBreak.add(bookmark);
	}

	@Override
	public boolean trackBreakpoint(TraceBreakpoint breakpoint) {
		TraceBreakpointSet breaks = traceBreaks.get(breakpoint.getTrace());
		return breaks.add(breakpoint);
	}

	@Override
	public boolean untrackBreakpoint(Program program, Bookmark bookmark) {
		assert progBreak.getProgram() == program;
		return progBreak.remove(bookmark);
	}

	@Override
	public boolean untrackBreakpoint(TraceBreakpoint breakpoint) {
		TraceBreakpointSet breaks = traceBreaks.get(breakpoint.getTrace());
		if (breaks == null) {
			return false;
		}
		return breaks.remove(breakpoint);
	}

	public boolean appliesTo(Program program) {
		return progBreak.getProgram() == Objects.requireNonNull(program);
	}

	public boolean appliesTo(Trace trace) {
		TraceBreakpointSet breaks = traceBreaks.get(Objects.requireNonNull(trace));
		return !breaks.isEmpty();
	}
}
