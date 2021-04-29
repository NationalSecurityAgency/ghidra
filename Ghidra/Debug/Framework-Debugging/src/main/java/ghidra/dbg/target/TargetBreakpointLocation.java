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

	String ADDRESS_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "address";
	// NOTE: address and length are treated separately (not using AddressRange)
	// On GDB, e.g., the length may not be offered immediately.
	String LENGTH_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "length";
	String SPEC_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "spec";

	/**
	 * The minimum address of this location
	 * 
	 * @return the address
	 */
	@TargetAttributeType(name = ADDRESS_ATTRIBUTE_NAME, required = true, hidden = true)
	public default Address getAddress() {
		return getTypedAttributeNowByName(ADDRESS_ATTRIBUTE_NAME, Address.class, null);
	}

	/**
	 * If available, get the length in bytes, of the range covered by the breakpoint.
	 * 
	 * <p>
	 * In most cases, where the length is not available, a length of 1 should be presumed.
	 * 
	 * <p>
	 * TODO: Should this be Long?
	 * 
	 * @return the length, or {@code null} if not known
	 */
	@TargetAttributeType(name = LENGTH_ATTRIBUTE_NAME, hidden = true)
	public default Integer getLength() {
		return getTypedAttributeNowByName(LENGTH_ATTRIBUTE_NAME, Integer.class, null);
	}

	public default int getLengthOrDefault(int fallback) {
		return getTypedAttributeNowByName(LENGTH_ATTRIBUTE_NAME, Integer.class, fallback);
	}

	/**
	 * Get a reference to the specification which generated this breakpoint.
	 * 
	 * <p>
	 * If the debugger does not separate specifications from actual breakpoints, then the
	 * "specification" is this breakpoint. Otherwise, the specification is the parent.
	 * 
	 * @return the reference to the specification
	 */
	@TargetAttributeType(name = SPEC_ATTRIBUTE_NAME, required = true, hidden = true)
	public default TargetBreakpointSpec getSpecification() {
		return getTypedAttributeNowByName(SPEC_ATTRIBUTE_NAME, TargetBreakpointSpec.class, null);
	}
}
