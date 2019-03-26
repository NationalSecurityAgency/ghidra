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
package ghidra.program.util;

import java.util.Iterator;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Program;

public class AddressIteratorConverter implements AddressIterator {

	private Program iteratorsProgram;
	private AddressIterator iterator;
	private Program otherProgram;
	Address nextAddress;

	public AddressIteratorConverter(Program iteratorsProgram, AddressIterator iterator,
			Program otherProgram) {
		this.iteratorsProgram = iteratorsProgram;
		this.iterator = iterator;
		this.otherProgram = otherProgram;
	}

	@Override
	public boolean hasNext() {
		if (nextAddress != null) {
			return true;
		}
		while (iterator.hasNext()) {
			Address address = iterator.next();
			Address convertedAddress =
				SimpleDiffUtility.getCompatibleAddress(iteratorsProgram, address, otherProgram);
			if (convertedAddress != null) {
				nextAddress = convertedAddress;
				return true;
			}
		}
		return false;
	}

	@Override
	public Address next() {
		if (nextAddress != null) {
			Address convertedAddress = nextAddress;
			nextAddress = null;
			return convertedAddress;
		}
		if (hasNext()) {
			return nextAddress;
		}
		return null;
	}

	/**
	 * @see java.util.Iterator#remove()
	 */
	@Override
	public void remove() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Iterator<Address> iterator() {
		return this;
	}
}
