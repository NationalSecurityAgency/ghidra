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
package ghidra.trace.model.modules;

import java.net.URL;
import java.util.Collection;

import com.google.common.collect.Range;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Program;

/**
 * Manages mappings from this trace into static images (Ghida {@link Program}s)
 * 
 * Most commonly, this is used to map sections listed by a connected debugger to those same sections
 * of programs already imported into the same Ghidra project. It is vitally important that the image
 * loaded by the target is an exact copy of the image imported by Ghidra, or else things may not be
 * aligned.
 * 
 * Note, to best handle mapping ranges to a variety of programs, and to validate the addition of new
 * entries, it is unlikely a client should consume mapping entries directly. Instead, a service
 * should track the mappings among all open traces and programs, permitting clients to mutate and
 * consume mappings more naturally, e.g., by passing in a {@link Program} and {@link Address} rather
 * than a URL and string-ized address.
 */
public interface TraceStaticMappingManager {

	/**
	 * Add a new mapping, if not already covered
	 * 
	 * A new mapping may overlap an existing mapping, so long as they agree in address shift.
	 * Furthermore, in such cases, the implementation may coalesce mappings to remove duplication.
	 * 
	 * @param range the range in the trace ("from")
	 * @param lifespan the span of time in the trace
	 * @param toProgramURL the (Ghidra) URL of the static image ("to")
	 * @param toAddress the starting address (in string form) in the static image ("to")
	 * @throws TraceConflictedMappingException if an existing mapping conflicts. See
	 *             {@link #isAnyConflicting(AddressRange, Range, URL, String)}
	 * @return the new entry, or any entry which subsumes the specified mapping
	 */
	TraceStaticMapping add(AddressRange range, Range<Long> lifespan, URL toProgramURL,
			String toAddress) throws TraceConflictedMappingException;

	/**
	 * Get all mappings in the manager
	 * 
	 * @return the collection of mappings
	 */
	Collection<? extends TraceStaticMapping> getAllEntries();

	/**
	 * Find any mapping applicable to the given snap and address
	 * 
	 * @param address the address
	 * @param snap the snap
	 * @return the mapping, or {@code null} if none exist at the given location
	 */
	TraceStaticMapping findContaining(Address address, long snap);

	/**
	 * Check if another mapping would conflict with the given prospective mapping
	 * 
	 * Mappings are allowed to overlap, but they must agree on the destination program and address
	 * throughout all overlapping portions.
	 * 
	 * TODO: It'd be nice if the manager automatically merged overlapping mappings in agreement or
	 * provided a "deduplicate" method which optimized the entries in the database. This gets
	 * complicated, since we're dealing with overlapping rectangles, not strict one-dimensional
	 * ranges. Look into existing research for optimizing coverage of shapes by rectangles. The same
	 * is needed for property maps in 2 dimensions.
	 * 
	 * @param range the range in the trace ("from")
	 * @param lifespan the span of time in the trace
	 * @param toProgramURL the (Ghidra) URL of the static image ("to")
	 * @param toAddress the starting address (in string form) in the static image ("to")
	 * @return a conflicting mapping, or {@code null} if none exist
	 */
	TraceStaticMapping findAnyConflicting(AddressRange range, Range<Long> lifespan,
			URL toProgramURL, String toAddress);

	/**
	 * Find all mappings which overlap the given adddress range and span of time
	 * 
	 * Note, this returns overlapping entries whether or not they conflict.
	 * 
	 * @param range the range in the trace ("from")
	 * @param lifespan the span of time in the trace
	 * @return an unmodifiable collection of overlapped entries
	 */
	Collection<? extends TraceStaticMapping> findAllOverlapping(AddressRange range,
			Range<Long> lifespan);
}
