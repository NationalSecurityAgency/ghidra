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
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.exec.SleighUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;

public class MappedLogicalBreakpoint implements LogicalBreakpointInternal {

	private final PluginTool tool;
	private final Set<TraceBreakpointKind> kinds;
	private final long length;

	private final ProgramBreakpoint progBreak;

	// Debuggers tend to allow multiple breakpoints (even of the same kind) at the same address
	// They may have different names and/or different conditions
	private final Map<Trace, TraceBreakpointSet> traceBreaks = new HashMap<>();

	protected MappedLogicalBreakpoint(PluginTool tool, Program program, Address progAddr,
			long length,
			Collection<TraceBreakpointKind> kinds) {
		this.tool = tool;
		this.kinds = Set.copyOf(kinds);
		this.length = length;

		this.progBreak = new ProgramBreakpoint(program, progAddr, length, this.kinds);
	}

	@Override
	public String toString() {
		synchronized (traceBreaks) {
			return String.format("<%s prog=%s, traces=%s>", getClass().getSimpleName(), progBreak,
				traceBreaks.values());
		}
	}

	protected boolean hasProgramBreakpoint() {
		return progBreak.getBookmark() != null;
	}

	@Override
	public boolean isEmpty() {
		if (!progBreak.isEmpty()) {
			return false;
		}
		synchronized (traceBreaks) {
			for (TraceBreakpointSet breaks : traceBreaks.values()) {
				if (!breaks.isEmpty()) {
					return false;
				}
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

	@Override
	public void enableForProgram() {
		progBreak.enable();
	}

	/**
	 * Place the program's bookmark with a comment specifying a desired name
	 * 
	 * <p>
	 * <b>WARNING:</b> Use only when this breakpoint was just placed, otherwise, this will reset
	 * other extrinsic properties, such as the sleigh injection.
	 * 
	 * @param name the desired name
	 */
	public void enableForProgramWithName(String name) {
		progBreak.toggleWithComment(true, name);
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
		TraceBreakpointSet breaks;
		synchronized (traceBreaks) {
			breaks = traceBreaks.get(trace);
		}
		if (breaks == null) {
			return AsyncUtils.NIL;
		}
		breaks.planEnable(actions, length, kinds);
		return actions.execute();
	}

	@Override
	public CompletableFuture<Void> disableForTrace(Trace trace) {
		BreakpointActionSet actions = new BreakpointActionSet();
		TraceBreakpointSet breaks;
		synchronized (traceBreaks) {
			breaks = traceBreaks.get(trace);
		}
		if (breaks == null) {
			return AsyncUtils.NIL;
		}
		breaks.planDisable(actions, length, kinds);
		return actions.execute();
	}

	@Override
	public CompletableFuture<Void> deleteForTrace(Trace trace) {
		BreakpointActionSet actions = new BreakpointActionSet();
		TraceBreakpointSet breaks;
		synchronized (traceBreaks) {
			breaks = traceBreaks.get(trace);
		}
		if (breaks == null) {
			return AsyncUtils.NIL;
		}
		breaks.planDelete(actions, length, kinds);
		return actions.execute();
	}

	@Override
	public void planEnable(BreakpointActionSet actions, Trace trace) {
		if (trace != null) {
			TraceBreakpointSet breaks;
			synchronized (traceBreaks) {
				breaks = traceBreaks.get(trace);
			}
			if (breaks == null) {
				return;
			}
			breaks.planEnable(actions, length, kinds);
			return;
		}
		synchronized (traceBreaks) {
			for (TraceBreakpointSet breaks : traceBreaks.values()) {
				breaks.planEnable(actions, length, kinds);
			}
		}
	}

	public CompletableFuture<Void> enableForTraces() {
		BreakpointActionSet actions = new BreakpointActionSet();
		planEnable(actions, null);
		return actions.execute();
		// NOTE: Recorder will cause appropriate updates
	}

	public CompletableFuture<Void> enableWithName(String name) {
		// TODO: Consider more fields than name in comment
		enableForProgramWithName(name);
		return enableForTraces();
	}

	@Override
	public String generateStatusEnable(Trace trace) {
		// NB. It'll place a breakpoint if mappable but not present
		if (trace == null) {
			if (!traceBreaks.values().isEmpty()) {
				return null;
			}
			return "A breakpoint is not mapped to any trace. Cannot enable it. " +
				"Is there a target? Check your module map.";
		}
		TraceBreakpointSet breaks = traceBreaks.get(trace);
		if (breaks != null) {
			return null;
		}
		return "A breakpoint is not mapped to the trace. " +
			"Cannot enable it. Is there a target? Check your module map.";
	}

	@Override
	public CompletableFuture<Void> enable() {
		enableForProgram();
		return enableForTraces();
	}

	@Override
	public void planDisable(BreakpointActionSet actions, Trace trace) {
		if (trace != null) {
			TraceBreakpointSet breaks;
			synchronized (traceBreaks) {
				breaks = traceBreaks.get(trace);
			}
			if (breaks == null) {
				return;
			}
			breaks.planDisable(actions, length, kinds);
			return;
		}
		synchronized (traceBreaks) {
			for (TraceBreakpointSet breaks : traceBreaks.values()) {
				breaks.planDisable(actions, length, kinds);
			}
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
			TraceBreakpointSet breaks;
			synchronized (traceBreaks) {
				breaks = traceBreaks.get(trace);
			}
			if (breaks == null) {
				return;
			}
			breaks.planDelete(actions, length, kinds);
			return;
		}
		synchronized (traceBreaks) {
			for (TraceBreakpointSet breaks : traceBreaks.values()) {
				breaks.planDelete(actions, length, kinds);
			}
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
	public String getName() {
		return progBreak.getName();
	}

	@Override
	public void setName(String name) {
		progBreak.setName(name);
	}

	@Override
	public ProgramLocation getProgramLocation() {
		return progBreak.getLocation();
	}

	@Override
	public void setTraceAddress(Trace trace, Address address) {
		synchronized (traceBreaks) {
			TraceBreakpointSet newSet = new TraceBreakpointSet(tool, trace, address);
			newSet.setEmuSleigh(progBreak.getEmuSleigh());
			traceBreaks.put(trace, newSet);
		}
	}

	@Override
	public void setRecorder(Trace trace, TraceRecorder recorder) {
		synchronized (traceBreaks) {
			traceBreaks.get(trace).setRecorder(recorder);
		}
	}

	@Override
	public void removeTrace(Trace trace) {
		synchronized (traceBreaks) {
			traceBreaks.remove(trace);
		}
	}

	@Override
	public Set<TraceBreakpoint> getTraceBreakpoints() {
		Set<TraceBreakpoint> result = new HashSet<>();
		synchronized (traceBreaks) {
			for (TraceBreakpointSet breaks : traceBreaks.values()) {
				result.addAll(breaks.getBreakpoints());
			}
		}
		return result;
	}

	@Override
	public Set<TraceBreakpoint> getTraceBreakpoints(Trace trace) {
		TraceBreakpointSet breaks;
		synchronized (traceBreaks) {
			breaks = traceBreaks.get(trace);
		}
		return breaks == null ? Set.of() : breaks.getBreakpoints();
	}

	@Override
	public Set<Trace> getMappedTraces() {
		synchronized (traceBreaks) {
			return Set.copyOf(traceBreaks.keySet());
		}
	}

	@Override
	public Set<Trace> getParticipatingTraces() {
		Set<Trace> result = new HashSet<>();
		synchronized (traceBreaks) {
			for (TraceBreakpointSet breaks : traceBreaks.values()) {
				if (breaks.isEmpty()) {
					continue;
				}
				result.add(breaks.getTrace());
			}
		}
		return result;
	}

	@Override
	public Address getTraceAddress(Trace trace) {
		TraceBreakpointSet breaks;
		synchronized (traceBreaks) {
			breaks = traceBreaks.get(trace);
		}
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
	public State computeStateForProgram(Program program) {
		if (progBreak.getProgram() != program) {
			return State.NONE;
		}
		return computeState();
	}

	@Override
	public State computeStateForTrace(Trace trace) {
		TraceBreakpointSet breaks;
		synchronized (traceBreaks) {
			breaks = traceBreaks.get(trace);
		}
		ProgramMode progMode = progBreak.computeMode();
		TraceMode traceMode = breaks == null ? TraceMode.NONE : breaks.computeMode();
		return progMode.combineTrace(traceMode, Perspective.TRACE);
	}

	protected TraceMode computeTraceModeForLocation(TraceBreakpoint loc) {
		TraceBreakpointSet breaks;
		synchronized (traceBreaks) {
			breaks = traceBreaks.get(loc.getTrace());
		}
		if (breaks == null || !breaks.getBreakpoints().contains(loc)) {
			return TraceMode.NONE;
		}
		return breaks.computeMode(loc);
	}

	@Override
	public State computeStateForLocation(TraceBreakpoint loc) {
		ProgramMode progMode = progBreak.computeMode();
		TraceMode traceMode = computeTraceModeForLocation(loc);
		return progMode.combineTrace(traceMode, Perspective.TRACE);
	}

	protected TraceMode computeTraceMode() {
		TraceMode traceMode = TraceMode.NONE;
		synchronized (traceBreaks) {
			for (TraceBreakpointSet breaks : traceBreaks.values()) {
				TraceMode tm = breaks.computeMode();
				traceMode = traceMode.combine(tm);
				if (traceMode == TraceMode.MISSING) {
					break;
				}
			}
		}
		return traceMode;
	}

	@Override
	public State computeState() {
		ProgramMode progMode = progBreak.computeMode();
		TraceMode traceMode = computeTraceMode();
		return progMode.combineTrace(traceMode, Perspective.LOGICAL);
	}

	protected String computeTraceSleigh() {
		String sleigh = null;
		synchronized (traceBreaks) {
			for (TraceBreakpointSet breaks : traceBreaks.values()) {
				String s = breaks.computeSleigh();
				if (sleigh != null && !sleigh.equals(s)) {
					return null;
				}
				sleigh = s;
			}
			return sleigh;
		}
	}

	@Override
	public String getEmuSleigh() {
		return progBreak.getEmuSleigh();
	}

	protected void setTraceBreakEmuSleigh(String sleigh) {
		synchronized (traceBreaks) {
			for (TraceBreakpointSet breaks : traceBreaks.values()) {
				breaks.setEmuSleigh(sleigh);
			}
		}
	}

	@Override
	public void setEmuSleigh(String sleigh) {
		progBreak.setEmuSleigh(sleigh);
		setTraceBreakEmuSleigh(sleigh);
	}

	@Override
	public boolean canMerge(Program program, Bookmark bookmark) {
		return progBreak.canMerge(program, bookmark);
	}

	@Override
	public boolean canMerge(TraceBreakpoint breakpoint) throws TrackedTooSoonException {
		TraceBreakpointSet breaks;
		synchronized (traceBreaks) {
			breaks = traceBreaks.get(breakpoint.getTrace());
		}
		if (breaks == null) {
			/**
			 * This happens when the trace is first added to the manager, between the listener being
			 * installed and the current breakpoints being loaded. We received a breakpoint-changed
			 * event for a trace that hasn't been loaded, so we don't see its break set in this
			 * logical breakpoint. The solution is "easy": Just punt, and it'll get generated later.
			 * It's not enough to return false, because that will generate another logical
			 * breakpoint, which may actually duplicate this one.
			 */
			throw new TrackedTooSoonException();
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
		if (progBreak.add(bookmark)) {
			String sleigh = progBreak.getEmuSleigh();
			if (sleigh != null && !SleighUtils.UNCONDITIONAL_BREAK.equals(sleigh)) {
				setEmuSleigh(sleigh);
			}
			return true;
		}
		return false;
	}

	protected void makeBookmarkConsistent() {
		// NB. Apparently it is specified that the bookmark should be created automatically
		/*if (progBreak.isEmpty()) {
			return;
		}*/
		TraceMode traceMode = computeTraceMode();
		if (traceMode == TraceMode.ENABLED) {
			progBreak.enable();
		}
		else if (traceMode == TraceMode.DISABLED) {
			progBreak.disable();
		}
	}

	@Override
	public boolean trackBreakpoint(TraceBreakpoint breakpoint) {
		TraceBreakpointSet breaks;
		synchronized (traceBreaks) {
			breaks = traceBreaks.get(breakpoint.getTrace());
		}
		boolean result = breaks.add(breakpoint);
		if (result) {
			String traceSleigh = computeTraceSleigh();
			if (traceSleigh != null && !SleighUtils.UNCONDITIONAL_BREAK.equals(traceSleigh)) {
				String progSleigh = progBreak.getEmuSleigh();
				if (progSleigh == null || SleighUtils.UNCONDITIONAL_BREAK.equals(progSleigh)) {
					progBreak.setEmuSleigh(traceSleigh);
				}
			}
		}
		makeBookmarkConsistent();
		return result;
	}

	@Override
	public boolean untrackBreakpoint(Program program, Bookmark bookmark) {
		assert progBreak.getProgram() == program;
		return progBreak.remove(bookmark);
	}

	@Override
	public boolean untrackBreakpoint(TraceBreakpoint breakpoint) {
		TraceBreakpointSet breaks;
		synchronized (traceBreaks) {
			breaks = traceBreaks.get(breakpoint.getTrace());
		}
		if (breaks == null) {
			return false;
		}
		boolean result = breaks.remove(breakpoint);
		makeBookmarkConsistent();
		return result;
	}

	public boolean appliesTo(Program program) {
		return progBreak.getProgram() == Objects.requireNonNull(program);
	}

	public boolean appliesTo(Trace trace) {
		TraceBreakpointSet breaks;
		synchronized (traceBreaks) {
			breaks = traceBreaks.get(Objects.requireNonNull(trace));
		}
		return !breaks.isEmpty();
	}
}
