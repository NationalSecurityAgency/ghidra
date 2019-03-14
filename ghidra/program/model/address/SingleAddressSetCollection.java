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
package ghidra.program.model.address;

/**
 * A simple implementation of AddressSetCollection that contains exactly one AddressSet.
 */
public class SingleAddressSetCollection implements AddressSetCollection {

	private AddressSetView set;

	public SingleAddressSetCollection(AddressSetView set) {
		this.set = (set == null) ? new AddressSet() : set;
	}

	@Override
	public boolean intersects(AddressSetView addrSet) {
		return set.intersects(addrSet);
	}

	@Override
	public boolean intersects(Address start, Address end) {
		return set.intersects(start, end);
	}

	@Override
	public boolean contains(Address address) {
		return set.contains(address);
	}

	@Override
	public boolean hasFewerRangesThan(int rangeThreshold) {
		return set.getNumAddressRanges() < rangeThreshold;
	}

	@Override
	public AddressSet getCombinedAddressSet() {
		return new AddressSet(set);
	}

	@Override
	public Address findFirstAddressInCommon(AddressSetView otherSet) {
		return set.findFirstAddressInCommon(otherSet);
	}

	@Override
	public boolean isEmpty() {
		return set.isEmpty();
	}

	@Override
	public Address getMinAddress() {
		return set.getMinAddress();
	}

	@Override
	public Address getMaxAddress() {
		return set.getMaxAddress();
	}

}
