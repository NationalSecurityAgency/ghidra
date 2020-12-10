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
import ghidra.dbg.attributes.TypedTargetObjectRef;
import ghidra.program.model.address.AddressRange;

@DebuggerTargetObjectIface("MemoryRegion")
public interface TargetMemoryRegion<T extends TargetMemoryRegion<T>> extends TypedTargetObject<T> {
	enum Private {
		;
		private abstract class Cls implements TargetMemoryRegion<Cls> {
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	Class<Private.Cls> tclass = (Class) TargetMemoryRegion.class;

	String RANGE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "range";
	String READABLE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "readable";
	String WRITABLE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "writable";
	String EXECUTABLE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "executable";
	String MEMORY_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "memory";

	public default AddressRange getRange() {
		return getTypedAttributeNowByName(RANGE_ATTRIBUTE_NAME, AddressRange.class, null);
	}

	public default boolean isReadable() {
		return getTypedAttributeNowByName(READABLE_ATTRIBUTE_NAME, Boolean.class, false);
	}

	public default boolean isWritable() {
		return getTypedAttributeNowByName(WRITABLE_ATTRIBUTE_NAME, Boolean.class, false);
	}

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
	public default TypedTargetObjectRef<? extends TargetMemory<?>> getMemory() {
		return getTypedRefAttributeNowByName(MEMORY_ATTRIBUTE_NAME, TargetMemory.tclass, null);
	}
}
