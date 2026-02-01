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

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;

public class AddressRangeIteratorConverter implements AddressRangeIterator {

	private AddressRangeIterator iterator;
	private Program program;
	AddressRange nextRange;

	public AddressRangeIteratorConverter(AddressRangeIterator iterator, Program program) {
		this.iterator = iterator;
		this.program = program;
	}

	@Override
	public Iterator<AddressRange> iterator() {
		return this;
	}

	@Override
	public void remove() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasNext() {
		if (nextRange != null) {
			return true;
		}
		while (iterator.hasNext()) {
			AddressRange range = iterator.next();
			// TODO Future change: May want to get as much of the range as you can if you can't get it all.
			AddressSet convertedRangeSet =
				DiffUtility.getCompatibleAddressSet(range, program, true);
			if (convertedRangeSet != null && !convertedRangeSet.isEmpty()) {
				nextRange = convertedRangeSet.getFirstRange();
				return true;
			}
		}
		return false;
	}

	@Override
	public AddressRange next() {
		if (nextRange != null) {
			AddressRange convertedRange = nextRange;
			nextRange = null;
			return convertedRange;
		}
		if (hasNext()) {
			return nextRange;
		}
		return null;
	}

}
