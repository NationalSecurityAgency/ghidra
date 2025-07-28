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
import java.util.function.Supplier;

import ghidra.debug.api.breakpoint.LogicalBreakpoint;
import ghidra.debug.api.breakpoint.LogicalBreakpoint.State;
import ghidra.debug.api.breakpoint.LogicalBreakpointsChangeListener;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.CodeUnitLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.breakpoint.TraceBreakpointLocation;
import ghidra.trace.model.program.TraceProgramView;

@ServiceInfo(
	defaultProviderName = "ghidra.app.plugin.core.debug.service.breakpoint.DebuggerLogicalBreakpointServicePlugin",
	description = "Aggregate breakpoints for programs and traces")
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
	 * Get a map of addresses to collected logical breakpoints for a given trace.
	 * 
	 * <p>
	 * The map only includes breakpoints visible in the trace's primary view. Visibility depends on
	 * the view's snapshot.
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
	 * Get the collected logical breakpoints at the given trace location.
	 * 
	 * <p>
	 * The set only includes breakpoints visible in the trace's primary view. Visibility depends on
	 * the view's snapshot.
	 * 
	 * @param trace the trace database
	 * @param address the address
	 * @return the set of logical breakpoints
	 */
	Set<LogicalBreakpoint> getBreakpointsAt(Trace trace, Address address);

	/**
	 * Get the logical breakpoint of which the given trace breakpoint is a part
	 * 
	 * <p>
	 * If the given trace breakpoint is not part of any logical breakpoint, e.g., because the trace
	 * is not opened in the tool or events are still being processed, then null is returned.
	 * 
	 * @param loc the trace breakpoint location
	 * @return the logical breakpoint, or null
	 */
	LogicalBreakpoint getBreakpoint(TraceBreakpointLocation loc);

	/**
	 * Get the collected logical breakpoints (at present) at the given location.
	 * 
	 * <p>
	 * The {@code program} field for the location may be either a program database (static image) or
	 * a view for a trace. If it is the latter, the view's snapshot is ignored in favor of the
	 * trace's primary view's snapshot.
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

	/**
	 * Get a future which completes after pending changes have been processed
	 * 
	 * <p>
	 * The returned future completes after all change listeners have been invoked
	 * 
	 * @return the future
	 */
	CompletableFuture<Void> changesSettled();

	/**
	 * Get the address most likely intended by the user for a given location
	 * 
	 * <p>
	 * Program locations always have addresses at the start of a code unit, no matter how the
	 * location was produced. This attempts to interpret the context a bit deeper to discern the
	 * user's intent. At the moment, it seems reasonable to check if the location includes a code
	 * unit. If so, take its min address, i.e., the location's address. If not, take the location's
	 * byte address.
	 * 
	 * @param loc the location
	 * @return the address
	 */
	static Address addressFromLocation(ProgramLocation loc) {
		if (loc instanceof CodeUnitLocation) {
			return loc.getAddress();
		}
		return loc.getByteAddress();
	}

	static <T> T programOrTrace(ProgramLocation loc,
			BiFunction<? super Program, ? super Address, ? extends T> progFunc,
			BiFunction<? super Trace, ? super Address, ? extends T> traceFunc) {
		Program progOrView = loc.getProgram();
		if (progOrView instanceof TraceProgramView view) {
			return traceFunc.apply(view.getTrace(), addressFromLocation(loc));
		}
		return progFunc.apply(progOrView, addressFromLocation(loc));
	}

	default State computeState(Collection<LogicalBreakpoint> col) {
		State state = State.NONE;
		for (LogicalBreakpoint lb : col) {
			state = state.sameAdddress(lb.computeState());
		}
		return state;
	}

	default State computeState(Collection<LogicalBreakpoint> col, Program program) {
		State state = State.NONE;
		for (LogicalBreakpoint lb : col) {
			state = state.sameAdddress(lb.computeStateForProgram(program));
		}
		return state;
	}

	default State computeState(Collection<LogicalBreakpoint> col, Trace trace) {
		State state = State.NONE;
		for (LogicalBreakpoint lb : col) {
			state = state.sameAdddress(lb.computeStateForTrace(trace));
		}
		return state;
	}

	default State computeState(Collection<LogicalBreakpoint> col, ProgramLocation loc) {
		return programOrTrace(loc,
			(p, a) -> computeState(col, p),
			(t, a) -> computeState(col, t));
	}

	/**
	 * Compute the state for a given address and program or trace view
	 * 
	 * @param loc the location
	 * @return the breakpoint state
	 */
	default State computeState(ProgramLocation loc) {
		Set<LogicalBreakpoint> col = getBreakpointsAt(loc);
		return computeState(col, loc);
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
	 * Create an enabled breakpoint at the given program location and each mapped trace location.
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
	 * @param name a name for the breakpoint. For no name, use the empty string
	 * @return a future which completes when all relevant breakpoints have been placed
	 */
	CompletableFuture<Void> placeBreakpointAt(Program program, Address address, long length,
			Collection<TraceBreakpointKind> kinds, String name);

	/**
	 * Create an enabled breakpoint at the given trace location and its mapped program location.
	 * 
	 * <p>
	 * If the breakpoint has no static location, then only the trace location is placed. Note, if
	 * this is the case, the breakpoint will have no name.
	 * 
	 * <p>
	 * Note for live targets, the debugger ultimately determines the placement behavior. If it is
	 * managing multiple targets, it is possible the breakpoint will be effective in another trace.
	 * This fact should be reflected correctly in the resulting logical markings once all resulting
	 * events have been processed.
	 * 
	 * @param trace the given trace
	 * @param address the address in the trace (as viewed in the present)
	 * @param length size of the breakpoint, may be ignored by debugger
	 * @param kinds the kinds of breakpoint
	 * @param name a name for the breakpoint
	 * @return a future which completes when the breakpoint has been placed
	 */
	CompletableFuture<Void> placeBreakpointAt(Trace trace, Address address, long length,
			Collection<TraceBreakpointKind> kinds, String name);

	/**
	 * Create an enabled breakpoint at the given location.
	 * 
	 * <p>
	 * If the given location refers to a static image, this behaves as in
	 * {@link #placeBreakpointAt(Program, Address, long, Collection, String)}. If it refers to a
	 * trace view, this behaves as in *
	 * {@link #placeBreakpointAt(Trace, Address, long, Collection, String)}, ignoring the view's
	 * current snapshot in favor of the present. The name is only saved for a program breakpoint.
	 * 
	 * @param loc the location
	 * @param length size of the breakpoint, may be ignored by debugger
	 * @param kinds the kinds of breakpoint
	 * @param name an optional name for the breakpoint (null becomes the empty string)
	 * @return a future which completes when the breakpoints have been placed
	 */
	CompletableFuture<Void> placeBreakpointAt(ProgramLocation loc, long length,
			Collection<TraceBreakpointKind> kinds, String name);

	/**
	 * Generate an informational status message when enabling the selected breakpoints
	 * 
	 * <p>
	 * Breakpoint enabling may fail for a variety of reasons. Some of those reasons deal with the
	 * trace database and GUI rather than with the target. When enabling will not likely behave in
	 * the manner expected by the user, this should provide a message explaining why. For example,
	 * if a breakpoint has no locations on a target, then we already know "enable" will not work.
	 * This should explain the situation to the user. If enabling is expected to work, then this
	 * should return null.
	 * 
	 * @param col the collection we're about to enable
	 * @param trace a trace, if the command will be limited to the given trace
	 * @return the status message, or null
	 */
	String generateStatusEnable(Collection<LogicalBreakpoint> col, Trace trace);

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
	 * @see #enableAll(Collection, Trace)
	 * @param col the collection
	 * @param trace a trace, if the command should be limited to the given trace
	 * @return a future which completes when all associated specifications have been disabled
	 */
	CompletableFuture<Void> disableAll(Collection<LogicalBreakpoint> col, Trace trace);

	/**
	 * Delete, if possible, a collection of logical breakpoints on target, if applicable
	 * 
	 * @see #enableAll(Collection, Trace)
	 * @param col the collection
	 * @param trace a trace, if the command should be limited to the given trace
	 * @return a future which completes when all associated specifications have been deleted
	 */
	CompletableFuture<Void> deleteAll(Collection<LogicalBreakpoint> col, Trace trace);

	/**
	 * Enable the given locations
	 * 
	 * @param col the trace breakpoints
	 * @return a future which completes when the command has been processed
	 */
	CompletableFuture<Void> enableLocs(Collection<TraceBreakpointLocation> col);

	/**
	 * Disable the given locations
	 * 
	 * @param col the trace breakpoints
	 * @return a future which completes when the command has been processed
	 */
	CompletableFuture<Void> disableLocs(Collection<TraceBreakpointLocation> col);

	/**
	 * Delete the given locations
	 * 
	 * @param col the trace breakpoints
	 * @return a future which completes when the command has been processed
	 */
	CompletableFuture<Void> deleteLocs(Collection<TraceBreakpointLocation> col);

	/**
	 * Generate an informational message when toggling the breakpoints
	 * 
	 * <p>
	 * This works in the same manner as {@link #generateStatusEnable(Collection, Trace)}, except it
	 * is for toggling breakpoints. If the breakpoint set is empty, this should return null, since
	 * the usual behavior in that case is to prompt to place a new breakpoint.
	 * 
	 * @see #generateStatusEnable(Collection, Trace)
	 * @param bs the set of logical breakpoints
	 * @param loc a representative location
	 * @return the status message, or null
	 */
	String generateStatusToggleAt(Set<LogicalBreakpoint> bs, ProgramLocation loc);

	/**
	 * Generate an informational message when toggling the breakpoints at the given location
	 * 
	 * <p>
	 * This works in the same manner as {@link #generateStatusEnable(Collection, Trace)}, except it
	 * is for toggling breakpoints at a given location. If there are no breakpoints at the location,
	 * this should return null, since the usual behavior in that case is to prompt to place a new
	 * breakpoint.
	 * 
	 * @see #generateStatusEnable(Collection, Trace)
	 * @param loc the location
	 * @return the status message, or null
	 */
	default String generateStatusToggleAt(ProgramLocation loc) {
		return generateStatusToggleAt(getBreakpointsAt(loc), loc);
	}

	/**
	 * Toggle the breakpoints at the given location
	 * 
	 * @param bs the set of breakpoints to toggle
	 * @param location the location
	 * @param placer if the breakpoint set is empty, a routine for placing a breakpoint
	 * @return a future which completes when the command has been processed
	 */
	CompletableFuture<Set<LogicalBreakpoint>> toggleBreakpointsAt(Set<LogicalBreakpoint> bs,
			ProgramLocation location, Supplier<CompletableFuture<Set<LogicalBreakpoint>>> placer);

	/**
	 * Toggle the breakpoints at the given location
	 * 
	 * @param location the location
	 * @param placer if there are no breakpoints, a routine for placing a breakpoint
	 * @return a future which completes when the command has been processed
	 */
	default CompletableFuture<Set<LogicalBreakpoint>> toggleBreakpointsAt(ProgramLocation location,
			Supplier<CompletableFuture<Set<LogicalBreakpoint>>> placer) {
		return toggleBreakpointsAt(getBreakpointsAt(location), location, placer);
	}
}
