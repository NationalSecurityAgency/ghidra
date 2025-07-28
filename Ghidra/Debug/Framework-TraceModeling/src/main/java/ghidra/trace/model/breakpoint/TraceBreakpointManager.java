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
package ghidra.trace.model.breakpoint;

import java.util.Collection;

import ghidra.program.model.address.*;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.exception.DuplicateNameException;

/**
 * A store for recording breakpoint placement over time in a trace
 */
public interface TraceBreakpointManager {

	/**
	 * Add a breakpoint to the trace
	 * 
	 * @param path the "full name" of the breakpoint
	 * @param lifespan the lifespan of the breakpoint
	 * @param range the address range of the breakpoint
	 * @param threads an optional set of threads to which the breakpoint applies. Empty for every
	 *            thread, i.e, the process.
	 * @param kinds the kinds of breakpoint
	 * @param enabled true if the breakpoint is enabled
	 * @param comment a user comment
	 * @return the new breakpoint.
	 * @throws DuplicateNameException if a breakpoint with the same path already exists within an
	 *             overlapping snap
	 */
	TraceBreakpointLocation addBreakpoint(String path, Lifespan lifespan, AddressRange range,
			Collection<TraceThread> threads, Collection<TraceBreakpointKind> kinds, boolean enabled,
			String comment) throws DuplicateNameException;

	/**
	 * Add a breakpoint to the trace at a single address
	 * 
	 * @see #addBreakpoint(String, Lifespan, AddressRange, Collection, Collection, boolean, String)
	 */
	default TraceBreakpointLocation addBreakpoint(String path, Lifespan lifespan, Address address,
			Collection<TraceThread> threads, Collection<TraceBreakpointKind> kinds, boolean enabled,
			String comment) throws DuplicateNameException {
		return addBreakpoint(path, lifespan, new AddressRangeImpl(address, address), threads, kinds,
			enabled, comment);
	}

	/**
	 * Add a breakpoint to the trace starting at a given snap
	 * 
	 * @see #addBreakpoint(String, Lifespan, AddressRange, Collection, Collection, boolean, String)
	 */
	default TraceBreakpointLocation placeBreakpoint(String path, long snap, AddressRange range,
			Collection<TraceThread> threads, Collection<TraceBreakpointKind> kinds, boolean enabled,
			String comment) throws DuplicateNameException {
		return addBreakpoint(path, Lifespan.nowOn(snap), range, threads, kinds, enabled,
			comment);
	}

	/**
	 * Add a breakpoint to the trace at a single address, starting at a given snap
	 * 
	 * @see #addBreakpoint(String, Lifespan, AddressRange, Collection, Collection, boolean, String)
	 */
	default TraceBreakpointLocation placeBreakpoint(String path, long snap, Address address,
			Collection<TraceThread> threads, Collection<TraceBreakpointKind> kinds, boolean enabled,
			String comment) throws DuplicateNameException {
		return addBreakpoint(path, Lifespan.nowOn(snap), new AddressRangeImpl(address, address),
			threads, kinds, enabled, comment);
	}

	/**
	 * Collect all breakpoint specifications in the trace
	 * 
	 * @return the specifications
	 */
	Collection<? extends TraceBreakpointSpec> getAllBreakpointSpecifications();

	/**
	 * Collect all breakpoint locations in the trace
	 * 
	 * @return the locations
	 */
	Collection<? extends TraceBreakpointLocation> getAllBreakpointLocations();

	/**
	 * Collect breakpoints specifications having the given "full name"
	 * 
	 * @param path the path
	 * @return the specifications
	 */
	Collection<? extends TraceBreakpointSpec> getBreakpointSpecificationsByPath(String path);

	/**
	 * Collect breakpoints locations having the given "full name"
	 * 
	 * @param path the path
	 * @return the locations
	 */
	Collection<? extends TraceBreakpointLocation> getBreakpointLocationsByPath(String path);

	/**
	 * Get the placed breakpoint at the given snap by the given path
	 * 
	 * @param snap the snap which the breakpoint's lifespan must contain
	 * @param path the path of the breakpoint
	 * @return the breakpoint, or {@code null} if no breakpoint matches
	 */
	TraceBreakpointLocation getPlacedBreakpointByPath(long snap, String path);

	/**
	 * Collect breakpoints containing the given snap and address
	 * 
	 * @param snap the time
	 * @param address the location
	 * @return the collection of breakpoints
	 */
	Collection<? extends TraceBreakpointLocation> getBreakpointsAt(long snap, Address address);

	/**
	 * Collect breakpoints intersecting the given span and address range
	 * 
	 * @param span the span
	 * @param range the address range
	 * @return the collection of breakpoints
	 */
	Collection<? extends TraceBreakpointLocation> getBreakpointsIntersecting(Lifespan span,
			AddressRange range);
}
