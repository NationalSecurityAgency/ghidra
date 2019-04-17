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
package ghidra.app.plugin.core.functiongraph.graph.vertex;

import ghidra.program.model.address.Address;
import ghidra.util.SystemUtilities;

// TODO if we ever have AddressSet implement hashCode(), then we don't really need this class
class AddressHasher {

	private final Address startAddress;
	private final Address endAddress;

	AddressHasher(Address startAddress, Address endAddress) {
		this.startAddress = startAddress;
		this.endAddress = endAddress;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}

		if (obj == this) {
			return true;
		}

		if (getClass() != obj.getClass()) {
			return false;
		}
		AddressHasher other = (AddressHasher) obj;

		return SystemUtilities.isEqual(startAddress, other.startAddress) &&
			SystemUtilities.isEqual(endAddress, other.endAddress);
	}

	@Override
	public int hashCode() {
		return startAddress.hashCode() ^ endAddress.hashCode();
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + "[start=" + startAddress + ", end=" + endAddress + "]";
	}
}
