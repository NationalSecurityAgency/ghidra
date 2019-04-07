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
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;

/**
 * <CODE>MultiCodeUnitIterator</CODE> is a class for iterating through multiple
 * code unit iterators simultaneously. The next() method returns an array 
 * of code units, since a code unit can be obtained from neither, either, or
 * both of the original code unit iterators.
 */
public class MultiCodeUnitIterator {
	/** the code unit iterators */
	CodeUnitIterator	iter[];
	/** the current code units */
	CodeUnit			cu[];
	boolean				forward;

	/**
	 * Constructor of a multi-code unit iterator.
	 * @param listings an array of the program listings whose code units are to be iterated.
	 * @param addr the address where the iterator should start.
	 * @param forward true indicates a forward iterator.  false indicates a backwards iterator.
	 */
	public MultiCodeUnitIterator(Listing[] listings, Address addr, boolean forward) {
		this.forward = forward;
		iter = new CodeUnitIterator[listings.length];
		for (int i=0; i < listings.length; i++) {
			iter[i] = listings[i].getCodeUnits(addr, forward);
		}
		cu = new CodeUnit[iter.length];
	}

	/**
	 * Constructor of a multi-code unit iterator.
	 * @param listings an array of the program listings whose code units are to be iterated.
	 * @param addrs the address set over which the code units should be iterated.
	 * @param forward true indicates a forward iterator.  false indicates a backwards iterator.
	 */
	public MultiCodeUnitIterator(Listing[] listings, AddressSetView addrs, boolean forward) {
		this.forward = forward;
		iter = new CodeUnitIterator[listings.length];
		for (int i=0; i < listings.length; i++) {
			iter[i] = listings[i].getCodeUnits(addrs, forward);
		}
		cu = new CodeUnit[iter.length];
	}

	/** Determines whether or not any of the iterators have a
	 *  next code unit.
	 * @return true if the next code unit can be obtained from any of
	 * the code unit iterators.
	 */
	public boolean hasNext() {
		for (int i = 0; i < iter.length; i++) {
			if ((cu[i] != null) || iter[i].hasNext()) {
				return true;
			}
		}
		return false;
	}

	/** Returns the next code unit(s). The next code unit could be from any one 
	 * or more of the iterators. The array returns a code unit for each listing
	 * that has a code unit with a minimum address at the next iterator address.
	 * The code units in the array match up to the listings in the array passed 
	 * to this classes constructor. The code unit will be null in the array if
	 * no code unit started at the next code unit address for that listing.
	 * @return an array with the next code unit(s).
	 */
	public CodeUnit[] next() {
		// Get a next value from each iterator
		for (int i = 0; i < iter.length; i++) {
			if (cu[i] == null) {
				if (iter[i].hasNext()) {
					cu[i] = iter[i].next();
				}
			}
		}

		// Find next code unit.
		CodeUnit cuNext = null;
		boolean next[] = new boolean[iter.length];
		for (int i = 0; i < iter.length; i++) {
			if (cu[i] == null) {
				continue;
			}
			if (cuNext == null) {
				cuNext = cu[i];
				next[i] = true;
			}
			else {
				int result = compareAddress(cuNext, cu[i]);
				if (result == 0) {
					next[i] = true;
				}
				else if ((forward && (result > 0)) || (!forward && (result < 0))) {
					cuNext = cu[i];
					for (int n = 0; n < i; n++) {
						next[n] = false;
					}
					next[i] = true;
				}
			}
		}

		// Load array with all code units that have same address as next. Others are null.
		CodeUnit nextCU[] = new CodeUnit[iter.length];
		for (int i = 0; i < iter.length; i++) {
			if (next[i]) {
				nextCU[i] = cu[i];
				cu[i] = null;
			}
		}
		return nextCU;
	}

	/** Determines whether the first code unit's minimum address is less 
	 *  than, equal to, or greater than the second's.
	 * @param cu1 the first code unit.
	 * @param cu2 the second code unit.
	 * @return -1 if less than, 0 if equal to, or 1 if greater than.
	 */
	private int compareAddress(CodeUnit cu1, CodeUnit cu2) {
		Address addr1 = cu1.getMinAddress();
		Address addr2 = cu2.getMinAddress();
		return addr1.compareTo(addr2);
	}

}
