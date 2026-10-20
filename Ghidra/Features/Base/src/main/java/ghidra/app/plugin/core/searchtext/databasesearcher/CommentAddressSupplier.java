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
package ghidra.app.plugin.core.searchtext.databasesearcher;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

/**
 * Shared supplier of comments at addresses as they are traversed in address order (or reverse
 * address order). 
 * <p>
 * This object is used as a part of a larger search operation and is shared by the various comment
 * searchers for efficiency since all comment types are actually stored in the same database
 * record.
 * <p>
 * At any given time, this supplier has a current address, which represents the next address at
 * or beyond the overall search operation's address. When asked to advance, a current search
 * address is passed, which is the last address that has been fully searched. So if our current
 * address is at that address, we need to advance our current address to the next comment address.
 * Otherwise, we simply return our current address which the higher level search can use
 * to determine the next overall search address.
 */
public class CommentAddressSupplier {

	private Address currentAddress;
	private CodeUnitComments currentComments;
	private AddressIterator iterator;
	private Listing listing;

	public CommentAddressSupplier(Program program, AddressSetView addresses, boolean forward) {
		listing = program.getListing();
		iterator = listing.getCommentAddressIterator(addresses, forward);
		doAdvance();
	}

	/**
	 * {@return the address of the currently available comments}
	 */
	public Address getCurrentAddress() {
		return currentAddress;
	}

	/**
	 * Returns the comment of the specified type at the current address or null if no comment of
	 * that type exists at the current address.
	 * @param type the type of comment to retrieve
	 * @return the comment of the specified type at the current address
	 */
	public String getCurrentComment(CommentType type) {
		if (currentComments != null) {
			return currentComments.getComment(type);
		}
		return null;
	}

	/**
	 * Advance the current address to the next address that contains any type of comment if the 
	 * passed in address is null or equal to the current address. The idea is that we are part
	 * of a larger search operation that is marching through the address space. We only want to 
	 * advance our current address if the overall address of the search matches our address.
	 * (meaning we have already served up comments for the given address so we can advance to the
	 * next address that has comments, but may not be the next address of the overall search
	 * operation is considering.)
	 * @param address the address that has been already processed, so we need to make sure our
	 * current address is past this address.
	 * @return an address that is past the given address. Could be our current address our 
	 * address hasn't been reached yet, or we search forward to the next address containing a
	 * comment.
	 */
	public Address advance(Address address) {
		if (address != null && address.equals(currentAddress)) {
			doAdvance();
		}
		return currentAddress;
	}

	private void doAdvance() {
		if (iterator.hasNext()) {
			currentAddress = iterator.next();
			currentComments = listing.getAllComments(currentAddress);
		}
		else {
			currentAddress = null;
			currentComments = null;
		}
	}
}
