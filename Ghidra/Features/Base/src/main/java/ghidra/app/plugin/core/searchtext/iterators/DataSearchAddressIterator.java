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
package ghidra.app.plugin.core.searchtext.iterators;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;

import java.util.Iterator;

public class DataSearchAddressIterator implements AddressIterator {

	private DataIterator dataIterator;

	private Data currentData;
	private Iterator<Address> currentIterator;

	private boolean forward;

	public DataSearchAddressIterator(DataIterator dataIterator, boolean forward) {
		this.dataIterator = dataIterator;
		this.forward = forward;
	}

	@Override
	public boolean hasNext() {
		if (currentIterator != null) {
			if (currentIterator.hasNext()) {
				return true;
			}
		}

		return dataIterator.hasNext();
	}

	@Override
	public Address next() {
		if (currentIterator != null) {
			if (currentIterator.hasNext()) {
				return currentIterator.next();
			}
		}

		currentData = dataIterator.next();
		AddressSetView addresses =
			new AddressSet(currentData.getProgram(), currentData.getMinAddress(),
				currentData.getMaxAddress());
		currentIterator = addresses.getAddresses(forward);
		return currentIterator.next();
	}

	@Override
	public void remove() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Iterator<Address> iterator() {
		return this;
	}
}
