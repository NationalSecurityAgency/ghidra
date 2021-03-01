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
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;

/**
 * An allocated section of a binary module
 * 
 * <p>
 * Note that the model should only present those sections which are allocated in memory. Otherwise
 * strange things may happen, such as zero-length ranges (which AddressRange hates), or overlapping
 * ranges (which Trace hates).
 * 
 * <p>
 * TODO: Present all sections, but include isAllocated?
 */
@DebuggerTargetObjectIface("Section")
public interface TargetSection extends TargetObject {

	String MODULE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "module";
	String RANGE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "range";

	/**
	 * Get the module to which this section belongs
	 * 
	 * @return the owning module
	 */
	@TargetAttributeType(name = MODULE_ATTRIBUTE_NAME, required = true, fixed = true, hidden = true)
	public default TargetModule getModule() {
		return getTypedAttributeNowByName(MODULE_ATTRIBUTE_NAME, TargetModule.class, null);
	}

	// TODO: Should there be a getSectionName(), like getModuleName()
	// in case getIndex() isn't accurate?

	/**
	 * Get the range of addresses comprising the section
	 * 
	 * @return the range
	 */
	@TargetAttributeType(name = RANGE_ATTRIBUTE_NAME, required = true, fixed = true)
	public default AddressRange getRange() {
		return getTypedAttributeNowByName(RANGE_ATTRIBUTE_NAME, AddressRange.class, null);
	}

	/**
	 * Get the lowest address in the section
	 * 
	 * @return the start
	 */
	public default Address getStart() {
		return getRange().getMinAddress();
	}

	/**
	 * Get the highest address (inclusive) in the section
	 * 
	 * @return the end
	 */
	public default Address getEnd() {
		return getRange().getMaxAddress();
	}
}
