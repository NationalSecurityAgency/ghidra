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
package ghidra.debug.api.modules;

import java.net.URL;
import java.util.*;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.program.TraceProgramView;

/**
 * This interface provides a mechanism for translating static address to dynamic and vice versa,
 * with respect to each trace's "Static Mappings" table.
 */
public interface DebuggerAddressTranslator {

	/**
	 * Collect all the open destination programs relevant for the given trace and snap
	 * 
	 * @param trace the trace
	 * @param snap the snap
	 * @return the set of open destination programs
	 */
	Set<Program> getOpenMappedProgramsAtSnap(Trace trace, long snap);

	/**
	 * Map the given trace location to a program location, if the destination is open
	 * 
	 * @param loc the source location
	 * @return the destination location, or {@code null} if not mapped, or not open
	 */
	ProgramLocation getOpenMappedLocation(TraceLocation loc);

	/**
	 * Similar to {@link #getOpenMappedLocation(TraceLocation)} but preserves details
	 * <p>
	 * The given location's {@link ProgramLocation#getProgram()} method must return a
	 * {@link TraceProgramView}. It derives the trace and snap from that view. Additionally, this
	 * will attempt to map over other "location" details, e.g., field, row, column.
	 * 
	 * @param loc a location within a trace view
	 * @return a mapped location in a program, or {@code null}
	 */
	ProgramLocation getStaticLocationFromDynamic(ProgramLocation loc);

	/**
	 * Map the given program location back to open source trace locations
	 * 
	 * @param loc the program location
	 * @return the, possibly empty, set of trace locations
	 */
	Set<TraceLocation> getOpenMappedLocations(ProgramLocation loc);

	/**
	 * Map the given program location back to a source trace and snap
	 * 
	 * @param trace the source trace, to which we are mapping back
	 * @param loc the destination location, from which we are mapping back
	 * @param snap the source snap, to which we are mapping back
	 * @return the source of the found mapping, or {@code null} if not mapped
	 */
	TraceLocation getOpenMappedLocation(Trace trace, ProgramLocation loc, long snap);

	/**
	 * Similar to {@link #getOpenMappedLocation(Trace, ProgramLocation, long)} but preserves details
	 * <p>
	 * This method derives the source trace and snap from the given view. Additinoally, this will
	 * attempt to map over other "location" details, e.g., field, row, column.
	 * 
	 * @param view the view, specifying the source trace and snap, to which we are mapping back
	 * @param loc the destination location, from which we are mapping back.
	 * @return the destination of the found mapping, or {@code null} if not mapped
	 */
	ProgramLocation getDynamicLocationFromStatic(TraceProgramView view, ProgramLocation loc);

	/**
	 * Find/compute all destination address sets given a source trace address set
	 * 
	 * @param trace the source trace
	 * @param set the source address set
	 * @param snap the source snap
	 * @return a map of destination programs to corresponding computed destination address ranges
	 */
	Map<Program, Collection<MappedAddressRange>> getOpenMappedViews(Trace trace,
			AddressSetView set, long snap);

	/**
	 * Find/compute all source address sets given a destination program address set
	 * 
	 * @param program the destination program, from which we are mapping back
	 * @param set the destination address set, from which we are mapping back
	 * @return a map of source traces to corresponding computed source address ranges
	 */
	Map<TraceSpan, Collection<MappedAddressRange>> getOpenMappedViews(Program program,
			AddressSetView set);

	/**
	 * Get all destination program URLs in mappings intersecting the given source trace, address
	 * set, and snap
	 * 
	 * @param trace the source trace
	 * @param set the source address set
	 * @param snap the source snap
	 * @return the set of destination URLs
	 */
	Set<URL> getMappedProgramUrlsInView(Trace trace, AddressSetView set, long snap);
}
