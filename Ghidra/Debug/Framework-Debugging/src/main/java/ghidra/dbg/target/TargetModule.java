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

/**
 * A binary module loaded by the target and/or debugger
 * 
 * <p>
 * If the debugger cares to parse the modules for section information, those sections should be
 * presented as successors to the module.
 */
@DebuggerTargetObjectIface("Module")
public interface TargetModule extends TargetObject {

	String RANGE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "range";
	String MODULE_NAME_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "module_name";

	/**
	 * Get the range containing all mapped sections of this module
	 * 
	 * <p>
	 * The minimum address should be the base address. The maximum address is the largest address
	 * mapped to any section belonging to this module. This attribute is especially important if
	 * sections are not given in the model. This attribute communicates the range which <em>may</em>
	 * belong to the module.
	 * 
	 * @return the base address, or {@code null}
	 */
	@TargetAttributeType(name = RANGE_ATTRIBUTE_NAME, required = true, hidden = true)
	public default AddressRange getRange() {
		return getTypedAttributeNowByName(RANGE_ATTRIBUTE_NAME, AddressRange.class, null);
	}

	/**
	 * Get the name of the module as defined by the target platform
	 * 
	 * @return the module name
	 */
	@TargetAttributeType(name = MODULE_NAME_ATTRIBUTE_NAME, required = true, hidden = true)
	public default String getModuleName() {
		return getTypedAttributeNowByName(MODULE_NAME_ATTRIBUTE_NAME, String.class, null);
	}
}
