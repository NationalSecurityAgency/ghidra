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
package ghidra.trace.model;

import java.util.Objects;

import ghidra.program.model.address.Address;

public class DefaultAddressSnap implements AddressSnap {
	private final Address address;
	private final long snap;

	public DefaultAddressSnap(Address address, long snap) {
		this.address = address;
		this.snap = snap;
	}

	@Override
	public Address getAddress() {
		return address;
	}

	@Override
	public long getSnap() {
		return snap;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof DefaultAddressSnap)) {
			return false;
		}
		DefaultAddressSnap that = (DefaultAddressSnap) obj;
		if (!Objects.equals(this.address, that.address)) {
			return false;
		}
		if (this.snap != that.snap) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		return Objects.hash(address, snap);
	}

	@Override
	public int compareTo(AddressSnap that) {
		if (this == that) {
			return 0;
		}
		int result;
		result = this.address.compareTo(that.getAddress());
		if (result != 0) {
			return result;
		}
		result = Long.compareUnsigned(this.snap, that.getSnap());
		if (result != 0) {
			return result;
		}
		return 0;
	}
}
