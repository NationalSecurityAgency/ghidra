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
package ghidra.program.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;

/**
 * <CODE>MultiAddressIterator</CODE> is a class for iterating through multiple
 * address iterators simultaneously. The next() method returns the next address
 * as determined from all the iterators.
 */
public class MultiAddressIterator {
	/** the code unit iterators */
	AddressIterator	iters[];
	/** the current code units */
	Address			addrs[];
	boolean			forward;

	/**
	 * Constructor of a multi address iterator for multiple forward address iterators.
	 * @param iters the address iterators.
	 */
	public MultiAddressIterator(final AddressIterator[] iters) {
		this.iters = iters;
		addrs = new Address[iters.length];
		forward = true;
	}

	/**
	 * Constructor of a multi address iterator.
	 * <br>Note: all iterators must iterate in the same direction (forwards or backwards).
	 * @param iters the address iterators. All must iterate in the direction indicated
	 * by the "forward" parameter.
	 * @param forward true indicates that forward iterators are in the array.
	 * false indicates backward iterators are in the array.
	 */
	public MultiAddressIterator(final AddressIterator[] iters, boolean forward) {
		this.iters = iters;
		addrs = new Address[iters.length];
		this.forward = forward;
	}

	/** Determines whether or not any of the original iterators has a
	 *  next address.
	 * @return true if a next address can be obtained from any of
	 * the address iterators.
	 */
	public boolean hasNext() {
		for (int i = 0; i < iters.length; i++) {
			if ((addrs[i] != null) || ((iters[i] != null) && (iters[i].hasNext()))) {
				return true;
			}
		}
		return false;
	}

	/** Returns the next address. The next address could be from any 
	 * one of the iterators.
	 * @return the next address.
	 */
	public Address next() {
		// Get a next value from each iterator
		for (int i = 0; i < iters.length; i++) {
			if (addrs[i] == null) {
				if (((iters[i] != null) && (iters[i].hasNext()))) {
					addrs[i] = iters[i].next();
				}
			}
		}

		// Find next address.
		Address addrNext = null;
		boolean next[] = new boolean[iters.length];
		for (int i = 0; i < iters.length; i++) {
			if (addrs[i] == null) {
				continue;
			}
			if (addrNext == null) {
				addrNext = addrs[i];
				next[i] = true;
			}
			else {
				int result = addrNext.compareTo(addrs[i]);
				if (result == 0) {
					next[i] = true;
				}
				else if ((forward && (result > 0)) || (!forward && (result < 0))) {
					addrNext = addrs[i];
					for (int n = 0; n < i; n++) {
						next[n] = false;
					}
					next[i] = true;
				}
			}
		}

		// Return next address or null if none.
		for (int i = 0; i < iters.length; i++) {
			if (next[i]) {
				addrs[i] = null;
			}
		}
		return addrNext;
	}

	/** Returns the next address(es). The next address could be from any 
	 * one or more of the iterators.
	 * @return an array with the next address(es). Each element in this array 
	 * corresponds to each iterator passed to the constructor. 
	 * Null is returned in an element if the next overall address is not the 
	 * next address from the corresponding iterator.
	 */
	public Address[] nextAddresses() {
		// Get a next value from each iterator
		for (int i = 0; i < iters.length; i++) {
			if (addrs[i] == null) {
				if (iters[i].hasNext()) {
					addrs[i] = iters[i].next();
				}
			}
		}

		// Find next address.
		Address addrNext = null;
		boolean next[] = new boolean[iters.length];
		for (int i = 0; i < iters.length; i++) {
			if (addrs[i] == null) {
				continue;
			}
			if (addrNext == null) {
				addrNext = addrs[i];
				next[i] = true;
			}
			else {
				int result = addrNext.compareTo(addrs[i]);
				if (result == 0) {
					next[i] = true;
				}
				else if ((forward && (result > 0)) || (!forward && (result < 0))) {
					addrNext = addrs[i];
					for (int n = 0; n < i; n++) {
						next[n] = false;
					}
					next[i] = true;
				}
			}
		}

		// Load array with all addresses that have same address as next. Others are null.
		Address nextAddr[] = new Address[iters.length];
		for (int i = 0; i < iters.length; i++) {
			if (next[i]) {
				nextAddr[i] = addrs[i];
				addrs[i] = null;
			}
		}
		return nextAddr;
	}

}
