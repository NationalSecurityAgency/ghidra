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

import ghidra.program.model.address.*;

/**
 * <CODE>MultiAddressRangeIterator</CODE> is a class for iterating through multiple
 * address range iterators simultaneously. The next() method returns the next address range
 * as determined from all the iterators.
 */
public class MultiAddressRangeIterator {
	AddressRangeIterator	iters[];
	AddressRange			addrRanges[];
	boolean			forward;
	Address min = null;
	Address max = null;

	/**
	 * Constructor of a multi address iterator for multiple forward address iterators.
	 * @param iters the address iterators.
	 */
	public MultiAddressRangeIterator(final AddressRangeIterator[] iters) {
		this.iters = iters;
		addrRanges = new AddressRange[iters.length];
		forward = true;
	}

	/**
	 * Constructor of a multi address range iterator.
	 * <br>Note: all iterators must iterate in the same direction (forwards or backwards).
	 * @param iters the address iterators. All must iterate in the direction indicated
	 * by the "forward" parameter.
	 * @param forward true indicates that forward iterators are in the array.
	 * false indicates backward iterators are in the array.
	 */
	public MultiAddressRangeIterator(final AddressRangeIterator[] iters, boolean forward) {
		this.iters = iters;
		addrRanges = new AddressRange[iters.length];
		this.forward = forward;
	}

	/**
	 * Determines whether or not any of the original iterators has a
	 * next address.
	 * @return true if a next address can be obtained from any of
	 * the address iterators.
	 */
	public boolean hasNext() {
		for (int i = 0; i < iters.length; i++) {
			if ((addrRanges[i] != null) || ((iters[i] != null) && (iters[i].hasNext()))) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns the next address. The next address could be from any 
	 * one of the iterators.
	 * @return the next address.
	 */
	public AddressRange next() {
		return (forward ? forwardNext() : backwardNext());
	}
		
	/**
	 * Returns the next address for forward iterators. The next address could be from any 
	 * one of the iterators.
	 * @return the next address.
	 */
	public AddressRange forwardNext() {
		
		// Get a next value from each iterator where we don't already have a range.
		for (int i = 0; i < iters.length; i++) {
			if (addrRanges[i] == null) {
				if (((iters[i] != null) && (iters[i].hasNext()))) {
					addrRanges[i] = iters[i].next();
				}
			}
		}
		
		// We don't yet know the next minimum value so get the min of the address ranges.
		if (min == null) {
			for (int i = 0; i < addrRanges.length; i++) {
				if (addrRanges[i] != null) {
					Address checkMinAddr = addrRanges[i].getMinAddress();
					if ((min == null) || (min.compareTo(checkMinAddr) > 0)) {
						min = checkMinAddr;
					}
				}
			}
		}
		
		// Determine the max value for the current range.
		max = null;
		for (int i = 0; i < addrRanges.length; i++) {
			if (addrRanges[i] != null) {
				Address checkMinAddr = addrRanges[i].getMinAddress();
				Address checkMaxAddr = addrRanges[i].getMaxAddress();
				if (addrRanges[i].contains(min)) {
					if ((max == null) || (max.compareTo(checkMaxAddr) > 0)) {
						max = checkMaxAddr;
					}
				}
				else if (min.compareTo(checkMinAddr) < 0) {
					Address previous = checkMinAddr.previous();
					if ((max == null) || (max.compareTo(previous) > 0)) {
						max = previous;
					}
				}
			}
		}
		
		// Save the range to return.
		AddressRange nextRange = new AddressRangeImpl(min, max);
		
		// Determine the next minimum.
		Address nextMin = (max != null) ? max.next() : null;
		
		// Adjust min to be the next minimum and 
		// null out ranges where we need the next range from its iterator.
		min = null;
		for (int i = 0; i < addrRanges.length; i++) {
			if (addrRanges[i] != null) {
				Address checkMaxAddr = addrRanges[i].getMaxAddress();
				if ((nextMin == null) || nextMin.compareTo(checkMaxAddr) > 0){
					addrRanges[i] = null;
				}
				else if (addrRanges[i].contains(nextMin)) {
					if (min == null) {
						min = nextMin;
					}
				}
			}
		}
		
		return nextRange;
	}
	
	/**
	 * Returns the next address for backward iterators. The next address could be from any 
	 * one of the iterators.
	 * @return the next address.
	 */
	public AddressRange backwardNext() {
		
		// Get a next value from each iterator where we don't already have a range.
		for (int i = 0; i < iters.length; i++) {
			if (addrRanges[i] == null) {
				if (((iters[i] != null) && (iters[i].hasNext()))) {
					addrRanges[i] = iters[i].next();
				}
			}
		}
		
		// We don't yet know the next maximum value so get the max of the address ranges.
		if (max == null) {
			for (int i = 0; i < addrRanges.length; i++) {
				if (addrRanges[i] != null) {
					Address checkMaxAddr = addrRanges[i].getMaxAddress();
					if ((max == null) || (max.compareTo(checkMaxAddr) < 0)) {
						max = checkMaxAddr;
					}
				}
			}
		}
		
		// Determine the min value for the current range.
		min = null;
		for (int i = 0; i < addrRanges.length; i++) {
			if (addrRanges[i] != null) {
				Address checkMinAddr = addrRanges[i].getMinAddress();
				Address checkMaxAddr = addrRanges[i].getMaxAddress();
				if (addrRanges[i].contains(max)) {
					if ((min == null) || (min.compareTo(checkMinAddr) < 0)) {
						min = checkMinAddr;
					}
				}
				else if (max.compareTo(checkMaxAddr) > 0) {
					Address next = checkMaxAddr.next();
					if ((min == null) || (min.compareTo(next) < 0)) {
						min = next;
					}
				}
			}
		}
		
		// Save the range to return.
		AddressRange nextRange = new AddressRangeImpl(min, max);
		
		// Determine the next minimum.
		Address nextMax = (min != null) ? min.previous() : null;
		
		// Adjust min to be the next minimum and 
		// null out ranges where we need the next range from its iterator.
		max = null;
		for (int i = 0; i < addrRanges.length; i++) {
			if (addrRanges[i] != null) {
				Address checkMinAddr = addrRanges[i].getMinAddress();
				if ((nextMax == null) || nextMax.compareTo(checkMinAddr) < 0){
					addrRanges[i] = null;
				}
				else if (addrRanges[i].contains(nextMax)) {
					if (max == null) {
						max = nextMax;
					}
				}
			}
		}
		
		return nextRange;
	}

}
