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

import java.util.Collection;

import com.google.common.collect.Range;

import ghidra.program.model.address.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceObject;
import ghidra.util.exception.DuplicateNameException;

/**
 * A module loaded in a target process
 * 
 * <p>
 * This also serves as a namespace for storing the module's sections.
 */
public interface TraceModule extends TraceObject {

	/**
	 * Get the trace containing this module
	 * 
	 * @return
	 */
	Trace getTrace();

	/**
	 * Add a section to this module
	 * 
	 * <p>
	 * Note while rare, it is permissible for sections to overlap. Module and section records are
	 * more informational and provide a means of recording module load and unload events, while
	 * noting the sections of which the debugger was aware. Typically each section, meeting certain
	 * criteria set by the target, is mapped into a memory region. Those regions cannot overlap.
	 * Furthermore, any overlapped mappings to static modules, which are usually derived from
	 * sections stored here, must agree on the address adjustment.
	 * 
	 * @param sectionPath the "full name" of the section
	 * @param sectionName the "short name" of the section
	 * @param range the range of memory into which the section is loaded
	 * @return the new section
	 * @throws DuplicateNameException if a section with the given name already exists in this module
	 */
	TraceSection addSection(String sectionPath, String sectionName, AddressRange range)
			throws DuplicateNameException;

	/**
	 * Add a section having the same full and short names
	 * 
	 * @see #addSection(String, String, AddressRange)
	 */
	default TraceSection addSection(String sectionPath, AddressRange range)
			throws DuplicateNameException {
		return addSection(sectionPath, sectionPath, range);
	}

	/**
	 * Get the "full name" of this module
	 * 
	 * <p>
	 * This is a unique key (within any snap) for retrieving the module, and may not be suitable for
	 * display on the screen. This is not likely the file system path of the module's image. Rather,
	 * it's typically the path of the module in the target debugger's object model.
	 * 
	 * @return
	 */
	String getPath();

	/**
	 * Set the "short name" of this module
	 * 
	 * <p>
	 * The given name is typically the file system path of the module's image, which is considered
	 * suitable for display on the screen.
	 * 
	 * @param name the name
	 */
	void setName(String name);

	/**
	 * Get the "short name" of this module
	 * 
	 * <p>
	 * This defaults to the "full name," but can be modified via {@link #setName(String)}
	 * 
	 * @return the name
	 */
	String getName();

	/**
	 * Set the address range of the module
	 * 
	 * <p>
	 * Typically, the minimum address in this range is the module's base address. If sections are
	 * given, this range should enclose all sections mapped into memory.
	 * 
	 * @param range the address range.
	 */
	void setRange(AddressRange range);

	/**
	 * Get the address range of the module
	 * 
	 * @see #setRange(AddressRange)
	 * @return the address range
	 */
	AddressRange getRange();

	/**
	 * Set the base (usually minimum) address of the module
	 * 
	 * <p>
	 * If not given by the target's debugger, the model or the recorder should endeavor to compute
	 * it from whatever information is provided. In general, this should be the virtual memory
	 * address mapped to file offset 0 of the module's image.
	 * 
	 * @param base the base address
	 */
	void setBase(Address base);

	/**
	 * Get the base address of the module
	 * 
	 * @return the base address
	 */
	Address getBase();

	/**
	 * Set the maximum address of the module
	 * 
	 * @see #setRange(AddressRange)
	 * @param max the maximum address
	 */
	void setMaxAddress(Address max);

	/**
	 * Get the maximum address of the module
	 * 
	 * @see #setRange(AddressRange)
	 * @return the maximum address
	 */
	Address getMaxAddress();

	/**
	 * Set the length of the range of the module
	 * 
	 * @see #setRange(AddressRange)
	 * @param length the length
	 * @throws AddressOverflowException if the length would cause the max address to overflow
	 */
	void setLength(long length) throws AddressOverflowException;

	/**
	 * Get the length of the range of the module
	 * 
	 * @see #setRange(AddressRange)
	 * @return the length
	 */
	long getLength();

	/**
	 * Set the lifespan of this module
	 * 
	 * @param lifespan the lifespan
	 * @throws DuplicateNameException if the specified lifespan would cause the full name of this
	 *             module or one of its sections to conflict with that of another whose lifespan
	 *             would intersect this module's
	 */
	void setLifespan(Range<Long> lifespan) throws DuplicateNameException;

	/**
	 * Get the lifespan of this module
	 * 
	 * @return
	 */
	Range<Long> getLifespan();

	/**
	 * @see #setLifespan(Range)
	 * 
	 * @param loadedSnap the loaded snap, or {@link Long#MIN_VALUE} for "since the beginning of
	 *            time"
	 */
	void setLoadedSnap(long loadedSnap) throws DuplicateNameException;

	/**
	 * Get the loaded snap of this module
	 * 
	 * @return the loaded snap, or {@link Long#MIN_VALUE} for "since the beginning of time"
	 */
	long getLoadedSnap();

	/**
	 * @see #setLifespan(Range)
	 * 
	 * @param unloadedSnap the unloaded snap, or {@link Long#MAX_VALUE} for "to the end of time"
	 */
	void setUnloadedSnap(long unloadedSnap) throws DuplicateNameException;

	/**
	 * Get the unloaded snap of this module
	 * 
	 * @return the unloaded snap, or {@link Long#MAX_VALUE} for "to the end of time"
	 */
	long getUnloadedSnap();

	/**
	 * Collect all sections contained within this module
	 * 
	 * @return the collection of sections
	 */
	Collection<? extends TraceSection> getSections();

	/**
	 * Get the section in this module having the given short name
	 * 
	 * @param sectionName the name
	 * @return the section, or {@code null} if no section has the given name
	 */
	TraceSection getSectionByName(String sectionName);

	/**
	 * Delete this module and its sections from the trace
	 */
	void delete();
}
