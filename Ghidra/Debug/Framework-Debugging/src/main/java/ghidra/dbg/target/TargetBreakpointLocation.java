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
import ghidra.dbg.attributes.TargetObjectRefList;
import ghidra.dbg.attributes.TypedTargetObjectRef;
import ghidra.program.model.address.Address;

@DebuggerTargetObjectIface("BreakpointLocation")
public interface TargetBreakpointLocation<T extends TargetBreakpointLocation<T>>
		extends TypedTargetObject<T> {
	enum Private {
		;
		private abstract class Cls implements TargetBreakpointLocation<Cls> {
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	Class<Private.Cls> tclass = (Class) TargetBreakpointLocation.class;

	String ADDRESS_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "address";
	String AFFECTS_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "affects";
	// NOTE: address and length are treated separately (not using AddressRange)
	// On GDB, e.g., the length may not be offered immediately.
	String LENGTH_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "length";
	String SPEC_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "spec";

	public default Address getAddress() {
		return getTypedAttributeNowByName(ADDRESS_ATTRIBUTE_NAME, Address.class, null);
	}

	public default TargetObjectRefList<?> getAffects() {
		return getTypedAttributeNowByName(AFFECTS_ATTRIBUTE_NAME, TargetObjectRefList.class,
			TargetObjectRefList.of());
	}

	/**
	 * If available, get the length in bytes, of the range covered by the
	 * breakpoint.
	 * 
	 * In most cases, where the length is not available, a length of 1 should be
	 * presumed.
	 * 
	 * TODO: Should this be Long?
	 * 
	 * @return the length, or {@code null} if not known
	 */
	public default Integer getLength() {
		return getTypedAttributeNowByName(LENGTH_ATTRIBUTE_NAME, Integer.class, null);
	}

	public default int getLengthOrDefault(int fallback) {
		return getTypedAttributeNowByName(LENGTH_ATTRIBUTE_NAME, Integer.class, fallback);
	}

	/**
	 * Get a reference to the specification which generated this breakpoint.
	 * 
	 * If the debugger does not separate specifications from actual breakpoints,
	 * then the "specification" is this breakpoint. Otherwise, this
	 * specification is the parent. The default implementation distinguishes the
	 * cases by examining the implemented interfaces. Implementors may slightly
	 * increase efficiency by overriding this method.
	 * 
	 * @return the reference to the specification
	 */
	public default TypedTargetObjectRef<? extends TargetBreakpointSpec<?>> getSpecification() {
		return getTypedRefAttributeNowByName(SPEC_ATTRIBUTE_NAME, TargetBreakpointSpec.tclass,
			null);
	}
}
