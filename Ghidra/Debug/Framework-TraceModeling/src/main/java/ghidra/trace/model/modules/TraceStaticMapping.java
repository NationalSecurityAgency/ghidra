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

import com.google.common.collect.Range;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceObject;

/**
 * A mapped range from this trace to a Ghidra {@link Program}
 */
public interface TraceStaticMapping extends TraceObject {

	/**
	 * Get the "from" trace, i.e., the trace containing this mapping
	 * 
	 * @return the trace
	 */
	Trace getTrace();

	/**
	 * Get the "from" range
	 * 
	 * @return the range
	 */
	AddressRange getTraceAddressRange();

	/**
	 * Get the "from" range's minimum address
	 * 
	 * @return the minimum address
	 */
	Address getMinTraceAddress();

	/**
	 * Get the "from" range's maximum address
	 * 
	 * @return the maximum address
	 */
	Address getMaxTraceAddress();

	// TODO: Lifespan, start/end snap setters?
	// NOTE: Would need to add LIFESPAN_CHANGED event and process where applicable

	/**
	 * Get the length of the mapping, i.e., the length of the range
	 * 
	 * @return the length, where 0 indicates {@code 1 << 64}
	 */
	long getLength();

	/**
	 * Get the shift in offset from static program to dynamic trace
	 * 
	 * @return the shift
	 */
	long getShift();

	/**
	 * Get the span of time of the mapping
	 * 
	 * @return the lifespan
	 */
	Range<Long> getLifespan();

	/**
	 * Get the starting snap of the lifespan
	 * 
	 * @return the start snap
	 */
	long getStartSnap();

	/**
	 * Get the ending snap of the lifespan
	 * 
	 * @return the end snap
	 */
	long getEndSnap();

	/**
	 * Get the Ghidra URL of the "to" {@link Program}, i.e., static image
	 * 
	 * @return the program URL
	 */
	URL getStaticProgramURL();

	/**
	 * Get the "to" address range's minimum address, as a string
	 * 
	 * @return the address string
	 */
	String getStaticAddress();

	/**
	 * Remove this mapping from the "from" trace
	 */
	void delete();

	/**
	 * Check if this mapping would conflict with the given prospective mapping
	 * 
	 * @see TraceStaticMappingManager#isAnyConflicting(AddressRange, Range, URL, String)
	 * @param range the range in the trace ("from")
	 * @param lifespan the span of time in the trace
	 * @param toProgramURL the (Ghidra) URL of the static image ("to")
	 * @param toAddress the starting address (in string form) in the staic image ("to")
	 * @return true if this mapping conflicts.
	 */
	boolean conflictsWith(AddressRange range, Range<Long> lifespan, URL toProgramURL,
			String toAddress);
}
