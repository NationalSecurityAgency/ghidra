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
package ghidra.program.database.register;

import java.util.Iterator;

import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.*;
import ghidra.util.datastruct.IndexRange;
import ghidra.util.datastruct.IndexRangeIterator;

public class IndexToAddressRangeIteratorAdapter implements AddressRangeIterator {
	private AddressMap map;
	private IndexRangeIterator it;

	/**
	 * Constructs a new IndexToAddressRangeIteratorAdapter given an AddressMap and 
	 * IndexRangeIterator
	 * @param addressMap the address map
	 * @param it the IndexRangeIterator
	 */
	public IndexToAddressRangeIteratorAdapter(AddressMap addressMap, IndexRangeIterator it) {
		this.map = addressMap;
		this.it = it;
	}

	public Iterator<AddressRange> iterator() {
		return this;
	}

	public void remove() {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.model.address.AddressRangeIterator#hasNext()
	 */
	public boolean hasNext() {
		return it.hasNext();
	}

	/**
	 * @see ghidra.program.model.address.AddressRangeIterator#next()
	 */
	public AddressRange next() {
		IndexRange indexRange = it.next();
		Address start = map.decodeAddress(indexRange.getStart());
		Address end = map.decodeAddress(indexRange.getEnd());
		return new AddressRangeImpl(start, end);
	}
}
