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
package ghidra.app.services;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.BiFunction;

import ghidra.app.plugin.core.debug.service.breakpoint.DebuggerLogicalBreakpointServicePlugin;
import ghidra.app.services.LogicalBreakpoint.Enablement;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.program.TraceProgramView;

@ServiceInfo( //
	defaultProvider = DebuggerLogicalBreakpointServicePlugin.class, //
	description = "Aggregate breakpoints for programs and live traces" //
)
public interface DebuggerLogicalBreakpointService {
	/**
	 * Get all logical breakpoints known to the tool.
	 * 
	 * @return the set of all logical breakpoints
	 */
	Set<LogicalBreakpoint> getAllBreakpoints();

	/**
	 * Get a map of addresses to collected logical breakpoints for a given program.
	 * 
	 * <p>
	 * The program ought to be a program database, not a view of a trace.
	 * 
	 * @param program the program database
	 * @return the map of logical breakpoints
	 */
	NavigableMap<Address, Set<LogicalBreakpoint>> getBreakpoints(Program program);

	/**
	 * Get a map of addresses to collected logical breakpoints (at present) for a given trace.
	 * 
	 * <p>
	 * The trace must be associated with a live target. The returned map collects live breakpoints
	 * in the recorded target, using trace breakpoints from the recorder's current snapshot.
	 * 
	 * @param trace the trace database
	 * @return the map of logical breakpoints
	 */
	NavigableMap<Address, Set<LogicalBreakpoint>> getBreakpoints(Trace trace);

	/**
	 * Get the collected logical breakpoints at the given program location.
	 * 
	 * <p>
	 * The program ought to be a program database, not a view of a trace.
	 * 
	 * @param program the program database
	 * @param address the address
	 * @return the set of logical breakpoints
	 */
	Set<LogicalBreakpoint> getBreakpointsAt(Program program, Address address);

	/**
	 * Get the collected logical breakpoints (at present) at the given trace location.
	 * 
	 * <p>
	 * The trace must be associated with a live target. The returned collection includes live
	 * breakpoints in the recorded target, using trace breakpoints from the recorders' current
	 * snapshot.
	 * 
	 * @param trace the trace database
	 * @param address the address
	 * @return the set of logical breakpoints
	 */
	Set<LogicalBreakpoint> getBreakpointsAt(Trace trace, Address address);

	/**
	 * Get the collected logical breakpoints (at present) at the given location.
	 * 
	 * <p>
	 * The {@code program} field for the location may be either a program database (static image) or
	 * a view for a trace associated with a live target. If it is the latter, the view's current
	 * snapshot is ignored, in favor of the associated recorder's current snapshot.
	 * 
	 * <p>
	 * If {@code program} is a static image, this is equivalent to using
	 * {@link #getBreakpointsAt(Program, Address)}. If {@code program} is a trace view, this is
	 * equivalent to using {@link #getBreakpointsAt(Trace, Address)}.
	 * 
	 * @param loc the location
	 * @return the set of logical breakpoints
	 */
	Set<LogicalBreakpoint> getBreakpointsAt(ProgramLocation loc);

	/**
	 * Add a listener for logical breakpoint changes.
	 * 
	 * <p>
	 * Logical breakpoints may change from time to time for a variety of reasons: A new trace is
	 * started; a static image is opened; the user adds or removes breakpoints; mappings change;
	 * etc. The service reacts to these events, reconciles the breakpoints, and invokes callbacks
	 * for the changes, allowing other UI components and services to update accordingly.
	 * 
	 * <p>
	 * The listening component must maintain a strong reference to the listener, otherwise it will
	 * be removed and garbage collected. Automatic removal is merely a resource-management
	 * protection; the listening component should politely remove its listener (see
	 * {@link #removeChangeListener(LogicalBreakpointsChangeListener)} when no longer needed.
	 * 
	 * @param l the listener
	 */
	void addChangeListener(LogicalBreakpointsChangeListener l);

	/**
	 * Remove a listener for logical breakpoint changes.
	 * 
	 * @see #addChangeListener(LogicalBreakpointsChangeListener)
	 * @param l the listener to remove
	 */
	void removeChangeListener(LogicalBreakpointsChangeListener l);

	static <T> T programOrTrace(ProgramLocation loc,
			BiFunction<? super Program, ? super Address, ? extends T> progFunc,
			BiFunction<? super Trace, ? super Address, ? extends T> traceFunc) {
		Program progOrView = loc.getProgram();
		if (progOrView instanceof TraceProgramView) {
			TraceProgramView view = (TraceProgramView) progOrView;
			return traceFunc.apply(view.getTrace(), loc.getByteAddress());
		}
		return progFunc.apply(progOrView, loc.getByteAddress());
	}

	default Enablement computeEnablement(Collection<LogicalBreakpoint> col) {
		Enablement en = Enablement.NONE;
		for (LogicalBreakpoint lb : col) {
			en = en.sameAdddress(lb.computeEnablement());
		}
		return en;
	}

	default Enablement computeEnablement(Collection<LogicalBreakpoint> col, Program program) {
		Enablement en = Enablement.NONE;
		for (LogicalBreakpoint lb : col) {
			en = en.sameAdddress(lb.computeEnablementForProgram(program));
		}
		return en;
	}

	default Enablement computeEnablement(Collection<LogicalBreakpoint> col, Trace trace) {
		Enablement en = Enablement.NONE;
		for (LogicalBreakpoint lb : col) {
			en = en.sameAdddress(lb.computeEnablementForTrace(trace));
		}
		return en;
	}

	default Enablement computeEnablement(Collection<LogicalBreakpoint> col, ProgramLocation loc) {
		return programOrTrace(loc,
			(p, a) -> computeEnablement(col, p),
			(t, a) -> computeEnablement(col, t));
	}

	default Enablement computeEnablement(ProgramLocation loc) {
		Set<LogicalBreakpoint> col = getBreakpointsAt(loc);
		return computeEnablement(col, loc);
	}

	default boolean anyMapped(Collection<LogicalBreakpoint> col, Trace trace) {
		if (trace == null) {
			return anyMapped(col);
		}
		for (LogicalBreakpoint lb : col) {
			if (lb.getMappedTraces().contains(trace)) {
				return true;
			}
		}
		return false;
	}

	default boolean anyMapped(Collection<LogicalBreakpoint> col) {
		for (LogicalBreakpoint lb : col) {
			if (!lb.getMappedTraces().isEmpty()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Create an enabled breakpoint at the given program location and each mapped live trace
	 * location.
	 * 
	 * <p>
	 * The implementation should take care not to create the same breakpoint multiple times. The
	 * risk of this happening derives from the possibility of one module mapped to multiple targets
	 * which are all managed by the same debugger, having a single breakpoint container.
	 * 
	 * @param program the static module image
	 * @param address the address in the image
	 * @param length size of the breakpoint, may be ignored by debugger
	 * @param kinds the kinds of breakpoint
	 * @return a future which completes when all relevant breakpoints have been placed
	 */
	CompletableFuture<Void> placeBreakpointAt(Program program, Address address, long length,
			Collection<TraceBreakpointKind> kinds);

	/**
	 * Create an enabled breakpoint at the given trace location only.
	 * 
	 * <p>
	 * If the given location is mapped to a static module, this still only creates the breakpoint in
	 * the given trace. However, a logical breakpoint mark will appear at all mapped locations.
	 * 
	 * <p>
	 * Note, the debugger ultimately determines the placement behavior. If it is managing multiple
	 * targets, it is possible the breakpoint will be effective in another trace. This fact should
	 * be reflected correctly in the resulting logical markings once all resulting events have been
	 * processed.
	 * 
	 * @param trace the given trace, which must be live
	 * @param address the address in the trace (as viewed in the present)
	 * @param length size of the breakpoint, may be ignored by debugger
	 * @param kinds the kinds of breakpoint
	 * @return a future which completes when the breakpoint has been placed
	 */
	CompletableFuture<Void> placeBreakpointAt(Trace trace, Address address, long length,
			Collection<TraceBreakpointKind> kinds);

	/**
	 * Create an enabled breakpoint at the given location.
	 * 
	 * <p>
	 * If the given location refers to a static image, this behaves as in
	 * {@link #placeBreakpointAt(Program, Address, TraceBreakpointKind)}. If it refers to a trace
	 * view, this behaves as in {@link #placeBreakpointAt(Trace, Address, TraceBreakpointKind)},
	 * ignoring the view's current snapshot in favor of the present.
	 * 
	 * @param loc the location
	 * @param length size of the breakpoint, may be ignored by debugger
	 * @param kinds the kinds of breakpoint
	 * @return a future which completes when the breakpoints have been placed
	 */
	CompletableFuture<Void> placeBreakpointAt(ProgramLocation loc, long length,
			Collection<TraceBreakpointKind> kinds);

	/**
	 * Enable a collection of logical breakpoints on target, if applicable
	 * 
	 * <p>
	 * This method is preferable to calling {@link LogicalBreakpoint#enable()} on each logical
	 * breakpoint, because depending on the debugger, a single breakpoint specification may produce
	 * several effective breakpoints, perhaps spanning multiple targets. While not terribly
	 * critical, this method will prevent multiple requests (which a debugger may consider
	 * erroneous) to enable the same specification, if that specification happens to be involved in
	 * more than one logical breakpoint in the given collection.
	 * 
	 * @param col the collection
	 * @param trace a trace, if the command should be limited to the given trace
	 * @return a future which completes when all associated specifications have been enabled
	 */
	CompletableFuture<Void> enableAll(Collection<LogicalBreakpoint> col, Trace trace);

	/**
	 * Disable a collection of logical breakpoints on target, if applicable
	 * 
	 * @see #enableAll(Collection)
	 * @param col the collection
	 * @param trace a trace, if the command should be limited to the given trace
	 * @return a future which completes when all associated specifications have been disabled
	 */
	CompletableFuture<Void> disableAll(Collection<LogicalBreakpoint> col, Trace trace);

	/**
	 * Delete, if possible, a collection of logical breakpoints on target, if applicable
	 * 
	 * @see #enableAll(Collection)
	 * @param col the collection
	 * @param trace a trace, if the command should be limited to the given trace
	 * @return a future which completes when all associated specifications have been deleted
	 */
	CompletableFuture<Void> deleteAll(Collection<LogicalBreakpoint> col, Trace trace);

	/**
	 * Presuming the given locations are live, enable them
	 * 
	 * @param col the trace breakpoints
	 * @return a future which completes when the command has been processed
	 */
	CompletableFuture<Void> enableLocs(Collection<TraceBreakpoint> col);

	/**
	 * Presuming the given locations are live, disable them
	 * 
	 * @param col the trace breakpoints
	 * @return a future which completes when the command has been processed
	 */
	CompletableFuture<Void> disableLocs(Collection<TraceBreakpoint> col);

	/**
	 * Presuming the given locations are live, delete them
	 * 
	 * @param col the trace breakpoints
	 * @return a future which completes when the command has been processed
	 */
	CompletableFuture<Void> deleteLocs(Collection<TraceBreakpoint> col);
}
