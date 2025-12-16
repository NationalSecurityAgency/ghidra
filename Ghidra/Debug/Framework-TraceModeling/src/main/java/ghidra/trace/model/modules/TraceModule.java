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

import ghidra.program.model.address.*;
import ghidra.trace.model.*;
import ghidra.trace.model.target.iface.TraceObjectInterface;
import ghidra.trace.model.target.info.TraceObjectInfo;
import ghidra.util.exception.DuplicateNameException;

/**
 * A binary module loaded by the target and/or debugger
 * 
 * <p>
 * This also serves as a namespace for storing the module's sections. If the debugger cares to parse
 * the modules for section information, those sections should be presented as successors to the
 * module.
 */
@TraceObjectInfo(
	schemaName = "Module",
	shortName = "module",
	attributes = {
		TraceModule.KEY_RANGE,
		TraceModule.KEY_MODULE_NAME,
	},
	fixedKeys = {
		TraceModule.KEY_DISPLAY,
		TraceModule.KEY_RANGE,
	})
public interface TraceModule extends TraceUniqueObject, TraceObjectInterface {
	String KEY_RANGE = "_range";
	String KEY_MODULE_NAME = "_module_name";

	/**
	 * Get the trace containing this module
	 * 
	 * @return the trace
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
	 * @param snap the "load" snap of the module
	 * @param sectionPath the "full name" of the section
	 * @param sectionName the "short name" of the section
	 * @param range the range of memory into which the section is loaded
	 * @return the new section
	 * @throws DuplicateNameException if a section with the given name already exists in this module
	 */
	TraceSection addSection(long snap, String sectionPath, String sectionName, AddressRange range)
			throws DuplicateNameException;

	/**
	 * Add a section having the same full and short names
	 * 
	 * @see #addSection(long, String, String, AddressRange)
	 * @param snap the "load" snap of the module
	 * @param sectionPath the "full name" of the section
	 * @param range the range of memory into which the section is loaded
	 * @return the new section
	 * @throws DuplicateNameException if a section with the given name already exists in this module
	 */
	default TraceSection addSection(long snap, String sectionPath, AddressRange range)
			throws DuplicateNameException {
		return addSection(snap, sectionPath, null, range);
	}

	/**
	 * Get the "full name" of this module
	 * 
	 * <p>
	 * This is a unique key (within any snap) for retrieving the module, and may not be suitable for
	 * display on the screen. This is not likely the file system path of the module's image. Rather,
	 * it's typically the path of the module in the target debugger's object model.
	 * 
	 * @return the path
	 */
	String getPath();

	/**
	 * Set the "short name" of this module
	 * 
	 * <p>
	 * The given name is typically the file system path of the module's image, which is considered
	 * suitable for display on the screen.
	 * 
	 * @param lifespan the span of time
	 * @param name the name
	 */
	void setName(Lifespan lifespan, String name);

	/**
	 * Set the "short name" of this module
	 * 
	 * <p>
	 * The given name is typically the file system path of the module's image, which is considered
	 * suitable for display on the screen.
	 * 
	 * @param snap the snap
	 * @param name the name
	 */
	void setName(long snap, String name);

	/**
	 * Get the "short name" of this module
	 * 
	 * <p>
	 * This defaults to the "full name," but can be modified via {@link #setName(long, String)}
	 * 
	 * @param snap the snap
	 * @return the name
	 */
	String getName(long snap);

	/**
	 * Set the address range of the module
	 * 
	 * <p>
	 * Typically, the minimum address in this range is the module's base address. If sections are
	 * given, this range should enclose all sections mapped into memory.
	 * 
	 * @param lifespan the span of time
	 * @param range the address range.
	 */
	void setRange(Lifespan lifespan, AddressRange range);

	/**
	 * Set the address range of the module
	 * 
	 * <p>
	 * Typically, the minimum address in this range is the module's base address. If sections are
	 * given, this range should enclose all sections mapped into memory.
	 * 
	 * @param snap the snap
	 * @param range the address range.
	 */
	void setRange(long snap, AddressRange range);

	/**
	 * Get the address range of the module
	 * 
	 * @see #setRange(long, AddressRange)
	 * @param snap the snap
	 * @return the address range
	 */
	AddressRange getRange(long snap);

	/**
	 * Set the base (usually minimum) address of the module
	 * 
	 * <p>
	 * If not given by the target's debugger, the model or the recorder should endeavor to compute
	 * it from whatever information is provided. In general, this should be the virtual memory
	 * address mapped to file offset 0 of the module's image.
	 * 
	 * <p>
	 * Note that this sets the range from the given snap on to the same range, no matter what
	 * changes may have occurred since.
	 * 
	 * @param snap the snap
	 * @param base the base address
	 */
	void setBase(long snap, Address base);

	/**
	 * Get the base address of the module
	 * 
	 * @param snap the snap
	 * @return the base address
	 */
	Address getBase(long snap);

	/**
	 * Set the maximum address of the module
	 * 
	 * <p>
	 * Note that this sets the range from the given snap on to the same range, no matter what
	 * changes may have occurred since.
	 * 
	 * @see #setRange(long, AddressRange)
	 * @param snap the snap
	 * @param max the maximum address
	 */
	void setMaxAddress(long snap, Address max);

	/**
	 * Get the maximum address of the module
	 * 
	 * @see #setRange(long, AddressRange)
	 * @param snap the snap
	 * @return the maximum address
	 */
	Address getMaxAddress(long snap);

	/**
	 * Set the length of the range of the module
	 * 
	 * <p>
	 * This adjusts the max address of the range so that its length becomes that given. Note that
	 * this sets the range from the given snap on to the same range, no matter what changes may have
	 * occurred since.
	 * 
	 * @see #setRange(long, AddressRange)
	 * @param snap the snap
	 * @param length the length
	 * @throws AddressOverflowException if the length would cause the max address to overflow
	 */
	void setLength(long snap, long length) throws AddressOverflowException;

	/**
	 * Get the length of the range of the module
	 * 
	 * @see #setRange(long, AddressRange)
	 * @param snap the snap
	 * @return the length
	 */
	long getLength(long snap);

	/**
	 * Collect all sections contained within this module at the given snap
	 * 
	 * @param snap the snap
	 * @return the collection of sections
	 */
	Collection<? extends TraceSection> getSections(long snap);

	/**
	 * Collect all sections contained within this module at any time
	 * 
	 * @return the collection of sections
	 */
	Collection<? extends TraceSection> getAllSections();

	/**
	 * Get the section in this module having the given short name
	 * 
	 * @param snap the snap
	 * @param sectionName the name
	 * @return the section, or {@code null} if no section has the given name
	 */
	TraceSection getSectionByName(long snap, String sectionName);

	/**
	 * Delete this module and its sections from the trace
	 */
	void delete();

	/**
	 * Remove this module from the given snap on
	 * 
	 * @param snap the snap
	 */
	void remove(long snap);

	/**
	 * Check if the module is valid at the given snapshot
	 * 
	 * @param snap the snapshot key
	 * @return true if valid, false if not
	 */
	boolean isValid(long snap);

	/**
	 * Check if the module is alive for any of the given span
	 * 
	 * @param span the span
	 * @return true if its life intersects the span
	 */
	boolean isAlive(Lifespan span);
}
