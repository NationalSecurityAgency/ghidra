/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.program.model.lang;

import ghidra.program.model.address.Address;
import ghidra.util.SystemUtilities;

public class InstructionBlockFlow implements Comparable<InstructionBlockFlow> {

	public enum Type { // ordered by disassembly priority
		/**
		 * <code>PRIORITY</code> is the highest priority flow start
		 */
		PRIORITY,
		/**
		 * <code>BRANCH</code> is a normal block branch flow within an InstructionSet 
		 */
		BRANCH,
		/**
		 * <code>CALL_FALLTHROUGH</code> is fall-through flow from a CALL instruction
		 * which must be deferred until all branch flows are processed.
		 */
		CALL_FALLTHROUGH,
		/**
		 * <code>CALL</code> is a call flow which always starts a new InstructionSet.
		 */
		CALL
	}

	final Address address;
	final Address flowFrom;
	final Type type;

	public InstructionBlockFlow(Address address, Address flowFrom, Type type) {
		this.address = address;
		this.flowFrom = flowFrom;
		this.type = type;
	}

	/**
	 * Get the flow destination address
	 * @return flow destination address
	 */
	public Address getDestinationAddress() {
		return address;
	}

	/**
	 * Get the flow from address
	 * @return flow from address (may be null)
	 */
	public Address getFlowFromAddress() {
		return flowFrom;
	}

	/**
	 * @return flow type
	 */
	public Type getType() {
		return type;
	}

	@Override
	public int hashCode() {
		return address != null ? address.hashCode() : 0; // address not expected to be null
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof InstructionBlockFlow)) {
			return false;
		}
		InstructionBlockFlow other = (InstructionBlockFlow) obj;
		return type == other.type && SystemUtilities.isEqual(address, other.address) &&
			SystemUtilities.isEqual(flowFrom, other.flowFrom);
	}

	@Override
	public int compareTo(InstructionBlockFlow o) {
		return SystemUtilities.compareTo(address, o.address);
	}

	@Override
	public String toString() {
		return type + " " + flowFrom + "->" + address;
	}

}
