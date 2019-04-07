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
package ghidra.feature.vt.gui.provider;

import ghidra.feature.vt.api.main.VTAssociationType;
import ghidra.program.model.address.Address;

public class VTAssociationPair {

	private final Address sourceAddress;
	private final Address destinationAddress;
	private final VTAssociationType type;

	/**
	 * AssociationPair constructor
	 * @param sourceAddress {@code Address}
	 * @param destinationAddress {@code Address}
	 * @param assocType {@code VTAssociationType}
	 */
	VTAssociationPair(Address sourceAddress, Address destinationAddress,
			VTAssociationType assocType) {
		this.sourceAddress = sourceAddress;
		this.destinationAddress = destinationAddress;
		this.type = assocType;
	}

	Address getSource() {
		return sourceAddress;
	}

	Address getDestination() {
		return destinationAddress;
	}

	VTAssociationType getType() {
		return type;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result =
			prime * result + ((destinationAddress == null) ? 0 : destinationAddress.hashCode());
		result = prime * result + ((sourceAddress == null) ? 0 : sourceAddress.hashCode());
		result = prime * result + ((type == null) ? 0 : type.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		VTAssociationPair other = (VTAssociationPair) obj;
		if (destinationAddress == null) {
			if (other.destinationAddress != null) {
				return false;
			}
		}
		else if (!destinationAddress.equals(other.destinationAddress)) {
			return false;
		}
		if (sourceAddress == null) {
			if (other.sourceAddress != null) {
				return false;
			}
		}
		else if (!sourceAddress.equals(other.sourceAddress)) {
			return false;
		}
		if (type != other.type) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		//@formatter:off
		return "{\n" +
			"\tsource: " + sourceAddress + ",\n" +
			"\tdest: " + destinationAddress+ ",\n" +
			"\ttype: " + type + ",\n" + 
		"}";
		//@formatter:on			
	}
}
