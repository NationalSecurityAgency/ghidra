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
package ghidra.app.plugin.core.analysis;

import ghidra.program.model.address.Address;

public class ReferenceAddressPair {
	
	private Address source;
	private Address destination;
	
	public ReferenceAddressPair(Address source, Address destination) {
		if (source == null) {
			source = Address.NO_ADDRESS;
		}
		if (destination == null) {
			destination = Address.NO_ADDRESS;
		}
		this.source = source;
		this.destination = destination;
	}
	
	public Address getSource() {
		return source;
	}
	
	public Address getDestination() {
		return destination;
	}

	@Override
	public int hashCode() {
		int hash1 = source.hashCode();
		int hash2 = destination.hashCode();
		return hash1 ^ hash2;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof ReferenceAddressPair)) {
			return false;
		}
		ReferenceAddressPair otherPair = (ReferenceAddressPair) obj;
		return source.equals(otherPair.source) & destination.equals(otherPair.destination);
	}
}
