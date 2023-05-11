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
import java.util.stream.Collectors;

import db.Transaction;
import ghidra.app.services.*;
import ghidra.app.services.LogicalBreakpoint.TraceMode;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.exec.SleighUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import utilities.util.IDHashed;

/**
 * The trace side of a logical breakpoint
 * 
 * <p>
 * If the logical breakpoint is a mapped, it will have one of these sets for each trace where the
 * breakpoint has (or could have) a location. For a lone logical breakpoint, it will have just one
 * of these for the one trace where its located.
 */
class TraceBreakpointSet {
	private final PluginTool tool;
	private final Trace trace;
	private final Address address;

	private final Set<IDHashed<TraceBreakpoint>> breakpoints = new HashSet<>();

	private TraceRecorder recorder;
	private String emuSleigh;

	/**
	 * Create a set of breakpoint locations for a given trace
	 * 
	 * @param tool the plugin tool for the UI
	 * @param trace the trace whose locations this set collects
	 * @param address the dynamic address where the breakpoint is (or would be) located
	 */
	public TraceBreakpointSet(PluginTool tool, Trace trace, Address address) {
		this.tool = Objects.requireNonNull(tool);
		this.trace = Objects.requireNonNull(trace);
		this.address = Objects.requireNonNull(address);
	}

	@Override
	public String toString() {
		return String.format("<at %s in %s: %s>", address, trace.getName(), breakpoints);
	}

	/**
	 * Set the recorder when the trace is associated to a live target
	 * 
	 * @param recorder the recorder
	 */
	public void setRecorder(TraceRecorder recorder) {
		this.recorder = recorder;
	}

	private ControlMode getControlMode() {
		DebuggerControlService service = tool.getService(DebuggerControlService.class);
		return service == null ? ControlMode.DEFAULT : service.getCurrentMode(trace);
	}

	private long getSnap() {
		/**
		 * TODO: Not exactly ideal.... It'd be nice to have it passed in, but that's infecting a lot
		 * of methods and putting a burden on the caller, when in most cases, it's going to be the
		 * "current snap" anyway.
		 */
		DebuggerTraceManagerService service = tool.getService(DebuggerTraceManagerService.class);
		if (service == null) {
			return trace.getProgramView().getViewport().getReversedSnaps().get(0);
		}
		return service.getCurrentFor(trace).getSnap();
	}

	/**
	 * Get the trace
	 * 
	 * @return
	 */
	public Trace getTrace() {
		return trace;
	}

	/**
	 * Get the dynamic address where the breakpoint is (or would be) located in this trace
	 * 
	 * @return the dynamic address
	 */
	public Address getAddress() {
		return address;
	}

	/**
	 * If there is a live target, get the dynamic address in the target's space
	 * 
	 * @return the dynamic address on target
	 */
	public Address computeTargetAddress() {
		if (recorder == null) {
			throw new AssertionError();
		}
		return recorder.getMemoryMapper().traceToTarget(address);
	}

	/**
	 * Compute the mode (enablement) of this set
	 * 
	 * <p>
	 * In most cases, there is 0 or 1 trace breakpoints that "fit" the logical breakpoint. The mode
	 * is derived from one of {@link TraceBreakpoint#isEnabled(long)} or
	 * {@link TraceBreakpoint#isEmuEnabled(long)}, depending on the UI's control mode for this
	 * trace.
	 * 
	 * @return the mode
	 */
	public TraceMode computeMode() {
		TraceMode mode = TraceMode.NONE;
		if (getControlMode().useEmulatedBreakpoints()) {
			for (IDHashed<TraceBreakpoint> bpt : breakpoints) {
				mode = mode.combine(computeEmuMode(bpt.obj));
				if (mode == TraceMode.MISSING) {
					return mode;
				}
			}
			return mode;
		}
		for (IDHashed<TraceBreakpoint> bpt : breakpoints) {
			mode = mode.combine(computeTargetMode(bpt.obj));
			if (mode == TraceMode.MISSING) {
				return mode;
			}
		}
		return mode;
	}

	/**
	 * Compute the mode (enablement) of the given breakpoint
	 * 
	 * <p>
	 * The mode is derived from one of {@link TraceBreakpoint#isEnabled(long)} or
	 * {@link TraceBreakpoint#isEmuEnabled(long)}, depending on the UI's control mode for this
	 * trace.
	 * 
	 * @param bpt the breakpoint
	 * @return the mode
	 */
	public TraceMode computeMode(TraceBreakpoint bpt) {
		return getControlMode().useEmulatedBreakpoints()
				? computeEmuMode(bpt)
				: computeTargetMode(bpt);
	}

	/**
	 * Compute the mode of the given breakpoint for the target
	 * 
	 * @param bpt the breakpoint
	 * @return the mode
	 */
	public TraceMode computeTargetMode(TraceBreakpoint bpt) {
		return TraceMode.fromBool(bpt.isEnabled(getSnap()));
	}

	/**
	 * Compute the mode of the given breakpoint for the emulator
	 * 
	 * @param bpt the breakpoint
	 * @return the mode
	 */
	public TraceMode computeEmuMode(TraceBreakpoint bpt) {
		return TraceMode.fromBool(bpt.isEmuEnabled(getSnap()));
	}

	/**
	 * If all breakpoints agree on sleigh injection, get that injection
	 * 
	 * @return the injection, or null if there's disagreement.
	 */
	public String computeSleigh() {
		String sleigh = null;
		for (IDHashed<TraceBreakpoint> bpt : breakpoints) {
			String s = bpt.obj.getEmuSleigh();
			if (sleigh != null && !sleigh.equals(s)) {
				return null;
			}
			sleigh = s;
		}
		return sleigh;
	}

	/**
	 * Set the sleigh injection for all breakpoints in this set
	 * 
	 * @param emuSleigh the sleigh injection
	 */
	public void setEmuSleigh(String emuSleigh) {
		this.emuSleigh = emuSleigh;
		try (Transaction tx = trace.openTransaction("Set breakpoint Sleigh")) {
			for (IDHashed<TraceBreakpoint> bpt : breakpoints) {
				bpt.obj.setEmuSleigh(emuSleigh);
			}
		}
	}

	/**
	 * Check if this set actually contains any trace breakpoints
	 * 
	 * @return true if empty, false otherwise
	 */
	public boolean isEmpty() {
		return breakpoints.isEmpty();
	}

	/**
	 * Get the breakpoints in this set
	 * 
	 * @return the breakpoints
	 */
	public Set<TraceBreakpoint> getBreakpoints() {
		return breakpoints.stream().map(e -> e.obj).collect(Collectors.toUnmodifiableSet());
	}

	/**
	 * Add a breakpoint to this set
	 * 
	 * <p>
	 * The caller should first call {@link #canMerge(TraceBreakpoint)} to check if the breakpoint
	 * "fits."
	 * 
	 * @param bpt
	 * @return true if the set actually changed as a result
	 */
	public boolean add(TraceBreakpoint bpt) {
		if (SleighUtils.UNCONDITIONAL_BREAK.equals(bpt.getEmuSleigh()) && emuSleigh != null) {
			try (Transaction tx = trace.openTransaction("Set breakpoint Sleigh")) {
				bpt.setEmuSleigh(emuSleigh);
			}
		}
		return breakpoints.add(new IDHashed<>(bpt));
	}

	/**
	 * Check if the given trace breakpoint "fits" in this set
	 * 
	 * <p>
	 * The breakpoint fits if it's dynamic location matches that expected in this set
	 * 
	 * @param bpt the breakpoint
	 * @return true if it fits
	 */
	public boolean canMerge(TraceBreakpoint bpt) {
		if (trace != bpt.getTrace()) {
			return false;
		}
		if (!address.equals(bpt.getMinAddress())) {
			return false;
		}
		return true;
	}

	/**
	 * Remove a breakpoint from this set
	 * 
	 * @param bpt the breakpoint
	 * @return true if the set actually changes as a result
	 */
	public boolean remove(TraceBreakpoint bpt) {
		return breakpoints.remove(new IDHashed<>(bpt));
	}

	/**
	 * Plan to enable the logical breakpoint within this trace
	 * 
	 * <p>
	 * This method prefers to use the existing breakpoint specifications which result in breakpoints
	 * at this address. In other words, it favors what the user has already done to effect a
	 * breakpoint at this logical breakpoint's address. If there is no such existing specification,
	 * then it attempts to place a new breakpoint via the target's breakpoint container, usually
	 * resulting in a new spec, which should effect exactly the one specified address. If the
	 * control mode indicates emulated breakpoints, then this simply writes the breakpoint to the
	 * trace database.
	 * 
	 * <p>
	 * This method may convert applicable addresses to the target space. If the address cannot be
	 * mapped, it's usually because this logical breakpoint does not apply to the given trace's
	 * target. E.g., the trace may not have a live target, or the logical breakpoint may be in a
	 * module not loaded by the trace.
	 * 
	 * @param actions the action set to populate
	 * @param length the length in bytes of the breakpoint
	 * @param kinds the kinds of breakpoint
	 */
	public void planEnable(BreakpointActionSet actions, long length,
			Collection<TraceBreakpointKind> kinds) {
		long snap = getSnap();
		if (breakpoints.isEmpty()) {
			if (recorder == null || getControlMode().useEmulatedBreakpoints()) {
				planPlaceEmu(actions, snap, length, kinds);
			}
			else {
				planPlaceTarget(actions, snap, length, kinds);
			}
		}
		else {
			if (recorder == null || getControlMode().useEmulatedBreakpoints()) {
				planEnableEmu(actions);
			}
			else {
				planEnableTarget(actions);
			}
		}
	}

	private void planPlaceTarget(BreakpointActionSet actions, long snap, long length,
			Collection<TraceBreakpointKind> kinds) {
		if (snap != recorder.getSnap()) {
			throw new AssertionError("Target breakpoints must be requested at present snap");
		}
		Set<TargetBreakpointKind> tKinds =
			TraceRecorder.traceToTargetBreakpointKinds(kinds);

		for (TargetBreakpointSpecContainer cont : recorder
				.collectBreakpointContainers(null)) {
			LinkedHashSet<TargetBreakpointKind> supKinds = new LinkedHashSet<>(tKinds);
			supKinds.retainAll(cont.getSupportedBreakpointKinds());
			actions.add(new PlaceTargetBreakpointActionItem(cont, computeTargetAddress(),
				length, supKinds));
		}
	}

	private void planPlaceEmu(BreakpointActionSet actions, long snap, long length,
			Collection<TraceBreakpointKind> kinds) {
		actions.add(
			new PlaceEmuBreakpointActionItem(trace, snap, address, length, Set.copyOf(kinds),
				emuSleigh));
	}

	private void planEnableTarget(BreakpointActionSet actions) {
		for (IDHashed<TraceBreakpoint> bpt : breakpoints) {
			TargetBreakpointLocation loc = recorder.getTargetBreakpoint(bpt.obj);
			if (loc == null) {
				continue;
			}
			actions.planEnableTarget(loc);
		}
	}

	private void planEnableEmu(BreakpointActionSet actions) {
		for (IDHashed<TraceBreakpoint> bpt : breakpoints) {
			actions.planEnableEmu(bpt.obj);
		}
	}

	/**
	 * Plan to disable the logical breakpoint in this trace
	 * 
	 * @param actions the action set to populate
	 * @param length the length in bytes of the breakpoint
	 * @param kinds the kinds of breakpoint
	 */
	public void planDisable(BreakpointActionSet actions, long length,
			Collection<TraceBreakpointKind> kinds) {
		if (getControlMode().useEmulatedBreakpoints()) {
			planDisableEmu(actions);
		}
		else {
			planDisableTarget(actions, length, kinds);
		}
	}

	private void planDisableTarget(BreakpointActionSet actions, long length,
			Collection<TraceBreakpointKind> kinds) {
		Set<TargetBreakpointKind> tKinds = TraceRecorder.traceToTargetBreakpointKinds(kinds);
		Address targetAddr = computeTargetAddress();
		for (TargetBreakpointLocation loc : recorder.collectBreakpoints(null)) {
			AddressRange range = loc.getRange();
			if (!targetAddr.equals(range.getMinAddress())) {
				continue;
			}
			if (length != range.getLength()) {
				continue;
			}
			TargetBreakpointSpec spec = loc.getSpecification();
			if (!Objects.equals(spec.getKinds(), tKinds)) {
				continue;
			}
			actions.planDisableTarget(loc);
		}
	}

	private void planDisableEmu(BreakpointActionSet actions) {
		for (IDHashed<TraceBreakpoint> bpt : breakpoints) {
			actions.planDisableEmu(bpt.obj);
		}
	}

	/**
	 * Plan to delete the logical breakpoint in this trace
	 * 
	 * @param actions the action set to populate
	 * @param length the length in bytes of the breakpoint
	 * @param kinds the kinds of breakpoint
	 */
	public void planDelete(BreakpointActionSet actions, long length,
			Set<TraceBreakpointKind> kinds) {
		if (getControlMode().useEmulatedBreakpoints()) {
			planDeleteEmu(actions);
		}
		else {
			planDeleteTarget(actions, length, kinds);
		}
	}

	private void planDeleteTarget(BreakpointActionSet actions, long length,
			Set<TraceBreakpointKind> kinds) {
		Set<TargetBreakpointKind> tKinds = TraceRecorder.traceToTargetBreakpointKinds(kinds);
		Address targetAddr = computeTargetAddress();
		for (TargetBreakpointLocation loc : recorder.collectBreakpoints(null)) {
			AddressRange range = loc.getRange();
			if (!targetAddr.equals(range.getMinAddress())) {
				continue;
			}
			if (length != range.getLength()) {
				continue;
			}
			TargetBreakpointSpec spec = loc.getSpecification();
			if (!Objects.equals(spec.getKinds(), tKinds)) {
				continue;
			}
			actions.planDeleteTarget(loc);
		}
	}

	private void planDeleteEmu(BreakpointActionSet actions) {
		for (IDHashed<TraceBreakpoint> bpt : breakpoints) {
			actions.planDeleteEmu(bpt.obj);
		}
	}
}
