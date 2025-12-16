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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.*;
import ghidra.trace.model.target.iface.TraceObjectInterface;
import ghidra.trace.model.target.info.TraceObjectInfo;
import ghidra.util.exception.DuplicateNameException;

/**
 * An allocated section of a binary module
 * 
 * <p>
 * Note that the model should only present those sections which are allocated in memory. Otherwise
 * strange things may happen, such as zero-length ranges (which AddressRange hates), or overlapping
 * ranges (which Trace hates).
 * 
 * <p>
 * LATER?: Present all sections, but include isAllocated
 */
@TraceObjectInfo(
	schemaName = "Section",
	shortName = "section",
	attributes = {
		TraceSection.KEY_MODULE,
		TraceSection.KEY_RANGE,
	},
	fixedKeys = {
		TraceSection.KEY_DISPLAY,
		TraceSection.KEY_RANGE
	})
public interface TraceSection extends TraceUniqueObject, TraceObjectInterface {
	String KEY_MODULE = "_module";
	String KEY_RANGE = "_range";

	/**
	 * Get the trace containing this section
	 * 
	 * @return the trace
	 */
	Trace getTrace();

	/**
	 * Get the module containing this section
	 * 
	 * @return the module
	 */
	TraceModule getModule();

	/**
	 * Get the "full name" of this section
	 * 
	 * <p>
	 * This is a unique key (within a snap) among all sections, and may not be suitable for display
	 * on the screen.
	 * 
	 * @return the path
	 */
	String getPath();

	/**
	 * Set the short name of this section
	 * 
	 * <p>
	 * The given name should be the section's name from its module's image, which is considered
	 * suitable for display on the screen.
	 * 
	 * @param lifespan the span of time
	 * @param name the name
	 */
	void setName(Lifespan lifespan, String name);

	/**
	 * Set the short name of this section
	 * 
	 * <p>
	 * The given name should be the section's name from its module's image, which is considered
	 * suitable for display on the screen.
	 * 
	 * @param snap the snap
	 * @param name the name
	 * @throws DuplicateNameException if the specified name would conflict with another section's in
	 *             this module
	 */
	void setName(long snap, String name) throws DuplicateNameException;

	/**
	 * Get the "short name" of this section
	 * 
	 * <p>
	 * This defaults to the "full name," but can be modified via {@link #setName(long, String)}
	 * 
	 * @param snap the snap
	 * @return the name
	 */
	String getName(long snap);

	/**
	 * Set the virtual memory address range of this section
	 * 
	 * @param lifespan the span of time
	 * @param range the span of addresses
	 */
	void setRange(Lifespan lifespan, AddressRange range);

	/**
	 * Get the virtual memory address range of this section
	 * 
	 * @param snap the snap
	 * @return the address range
	 */
	AddressRange getRange(long snap);

	/**
	 * @see #getRange(long)
	 * @param snap the snap
	 * @return the min address in the range
	 */
	default Address getStart(long snap) {
		AddressRange range = getRange(snap);
		return range == null ? null : range.getMinAddress();
	}

	/**
	 * @see #getRange(long)
	 * @param snap the snap
	 * @return the max address in the range
	 */
	default Address getEnd(long snap) {
		AddressRange range = getRange(snap);
		return range == null ? null : range.getMaxAddress();
	}

	/**
	 * Delete this section from the trace
	 */
	void delete();

	/**
	 * Remove this section from the given snap on
	 * 
	 * @param snap the snap
	 */
	void remove(long snap);

	/**
	 * Check if the section is valid at the given snapshot
	 * 
	 * @param snap the snapshot key
	 * @return true if valid, false if not
	 */
	boolean isValid(long snap);
}
