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
package ghidra.dbg.target;

import ghidra.dbg.DebuggerTargetObjectIface;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.program.model.address.AddressRange;

@DebuggerTargetObjectIface("MemoryRegion")
public interface TargetMemoryRegion extends TargetObject {
	String RANGE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "range";
	String READABLE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "readable";
	String WRITABLE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "writable";
	String EXECUTABLE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "executable";
	String MEMORY_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "memory";

	/**
	 * Get the address range representing this region
	 * 
	 * @return the range
	 */
	@TargetAttributeType(name = RANGE_ATTRIBUTE_NAME, required = true, hidden = true)
	public default AddressRange getRange() {
		return getTypedAttributeNowByName(RANGE_ATTRIBUTE_NAME, AddressRange.class, null);
	}

	/**
	 * Check if this region is readable
	 * 
	 * @return true if read is permitted
	 */
	@TargetAttributeType(name = READABLE_ATTRIBUTE_NAME, required = true, hidden = true)
	public default boolean isReadable() {
		return getTypedAttributeNowByName(READABLE_ATTRIBUTE_NAME, Boolean.class, false);
	}

	/**
	 * Check if this region is writable
	 * 
	 * @return true if write is permitted
	 */
	@TargetAttributeType(name = WRITABLE_ATTRIBUTE_NAME, required = true, hidden = true)

	public default boolean isWritable() {
		return getTypedAttributeNowByName(WRITABLE_ATTRIBUTE_NAME, Boolean.class, false);
	}

	/**
	 * Check if this region is executable
	 * 
	 * @return true if execute is permitted
	 */
	@TargetAttributeType(name = EXECUTABLE_ATTRIBUTE_NAME, required = true, hidden = true)

	public default boolean isExecutable() {
		return getTypedAttributeNowByName(EXECUTABLE_ATTRIBUTE_NAME, Boolean.class, false);
	}

	// TODO: Should probably just have getFlags() and "flags" attribute

	// TODO: Other flags? "committed", "reserved", etc?

	/**
	 * Get the memory for this region.
	 * 
	 * <p>
	 * While it is most common for a region to be an immediate child of its containing memory, that
	 * is not necessarily the case. This method is a reliable and type-safe means of obtaining that
	 * memory.
	 * 
	 * @return a reference to the memory
	 */
	@TargetAttributeType(name = MEMORY_ATTRIBUTE_NAME, required = true, fixed = true, hidden = true)
	public default TargetMemory getMemory() {
		return getTypedAttributeNowByName(MEMORY_ATTRIBUTE_NAME, TargetMemory.class, null);
	}
}
