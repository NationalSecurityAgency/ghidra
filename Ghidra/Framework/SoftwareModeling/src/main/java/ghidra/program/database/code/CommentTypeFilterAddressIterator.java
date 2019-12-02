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
package ghidra.program.database.code;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

import java.util.Iterator;

/**
 * Filters the given address iterator to only return addresses that have a comment of the given type
 */
public class CommentTypeFilterAddressIterator implements AddressIterator {
	private AddressIterator it;
	private Listing listing;
	private int commentType;
	private Address nextAddr;

	/**
	 * Constructs a new CommentTypeFilterAddressIterator
	 * @param it an address iterator whose items are tested for the comment type.
	 * @param commentType the type of comment to search for.
	 */
	public CommentTypeFilterAddressIterator(Program program, AddressIterator it, int commentType) {
		this.listing = program.getListing();
		this.it = it;
		this.commentType = commentType;
	}

	@Override
	public void remove() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasNext() {
		if (nextAddr == null) {
			findNext();
		}
		return nextAddr != null;
	}

	@Override
	public Address next() {
		if (hasNext()) {
			Address ret = nextAddr;
			nextAddr = null;
			return ret;
		}
		return null;
	}

	private void findNext() {
		while (it.hasNext()) {
			Address addr = it.next();
			if (listing.getComment(commentType, addr) != null) {
				nextAddr = addr;
				break;
			}
		}
	}

	@Override
	public Iterator<Address> iterator() {
		return this;
	}
}
