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
 * The location of a breakpoint
 *
 * <p>
 * If the native debugger does not separate the concepts of specification and location, then
 * breakpoint objects should implement both the specification and location interfaces. If the
 * location is user-togglable independent of its specification, it should implement
 * {@link TargetTogglable} as well.
 */
@DebuggerTargetObjectIface("BreakpointLocation")
public interface TargetBreakpointLocation extends TargetObject {

	String RANGE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "range";
	String SPEC_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "spec";

	/**
	 * The range covered by this location
	 * 
	 * <p>
	 * Typically, watchpoints (or access breakpoints) have a length, so the range would cover all
	 * addresses in the variable being watched. Execution breakpoints likely have a "length" of 1,
	 * meaning they cover only the address of the trap.
	 * 
	 * @return the address range of the location
	 */
	@TargetAttributeType(name = RANGE_ATTRIBUTE_NAME, hidden = true)
	public default AddressRange getRange() {
		return getTypedAttributeNowByName(RANGE_ATTRIBUTE_NAME, AddressRange.class, null);
	}

	/**
	 * Get a reference to the specification which generated this breakpoint.
	 * 
	 * <p>
	 * If the debugger does not separate specifications from actual breakpoints, then the
	 * "specification" is this breakpoint. Otherwise, the specification is identified by an
	 * attribute, usually a link.
	 * 
	 * @return the reference to the specification
	 */
	@TargetAttributeType(name = SPEC_ATTRIBUTE_NAME, required = true, hidden = true)
	public default TargetBreakpointSpec getSpecification() {
		return getTypedAttributeNowByName(SPEC_ATTRIBUTE_NAME, TargetBreakpointSpec.class, null);
	}
}
