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
package ghidra.program.model;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;

import java.util.Collection;
import java.util.Iterator;

public class AddressIteratorTestStub implements AddressIterator {
	private Iterator<Address> iterator;

	public AddressIteratorTestStub(Collection<Address> addresses) {
		this.iterator = addresses.iterator();
	}

	@Override
	public void remove() {
		// do nothing for now
	}

	@Override
	public Iterator<Address> iterator() {
		return this;
	}

	@Override
	public Address next() {
		return iterator.next();
	}

	@Override
	public boolean hasNext() {
		return iterator.hasNext();
	}
}
