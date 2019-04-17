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
package ghidra.app.merge.util;

import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;

/**
 * <code>MergeUtilities</code> provides generic static methods for use by the 
 * multi-user program merge managers.
 */
public class MergeUtilities {

	/**
	 * Adds addresses to autoChanges where there are changes in the myDiffs set,
	 * but none in the latestDiffs set.
	 * Adds addresses to conflictChanges where there are changes in the myDiffs 
	 * set and also some changes in the latestDiffs set.
	 * @param latestDiffs the address set of the changes in LATEST.
	 * @param myDiffs the address set of the changes in MY.
	 * @param autoChanges address set for the myDiffs non-conflicting changes.
	 * @param conflictChanges address set for the myDiffs conflicting changes
	 */
	public static void adjustSets(AddressSetView latestDiffs, AddressSetView myDiffs,
			AddressSet autoChanges, AddressSet conflictChanges) {
		AddressSet diffAutoChanges = new AddressSet(myDiffs);
		diffAutoChanges.delete(latestDiffs);
		AddressSet diffConflictChanges = new AddressSet(myDiffs);
		diffConflictChanges = diffConflictChanges.intersect(latestDiffs);
		autoChanges.add(diffAutoChanges);
		conflictChanges.add(diffConflictChanges);
	}

//	/** Creates an address set that contains the entire code units within the
//	 *  listing that are part of the address set that is passed in.
//	 * <br>Note: This method will not remove any addresses from the address set even
//	 * if they are not part of code units in the listing.
//	 * @param addrSet The original address set that may contain portions of
//	 * code units.
//	 * @param listing the program listing which has the code units.
//	 * @return the address set that contains addresses for whole code units.
//	 */
//	public static AddressSet getCodeUnitSet(AddressSetView addrSet, Listing listing) {
//		AddressSet addrs = new AddressSet(addrSet);
//		AddressRangeIterator iter = addrSet.getAddressRanges();
//		while (iter.hasNext()) {
//			AddressRange range = iter.next();
//			Address rangeMin = range.getMinAddress();
//			Address rangeMax = range.getMaxAddress();
//			CodeUnit minCu = listing.getCodeUnitContaining(rangeMin);
//			if (minCu != null) {
//				Address minCuMinAddr = minCu.getMinAddress();
//				if (minCuMinAddr.compareTo(rangeMin) != 0) {
//					addrs.addRange(minCuMinAddr, minCu.getMaxAddress());
//				}
//			}
//			CodeUnit maxCu = listing.getCodeUnitContaining(rangeMax);
//			if (maxCu != null) {
//				Address maxCuMaxAddr = maxCu.getMaxAddress();
//				if (maxCuMaxAddr.compareTo(rangeMax) != 0) {
//					addrs.addRange(maxCu.getMinAddress(), maxCuMaxAddr);
//				}
//			}
//		}
//		return addrs;
//	}
//    
//	/**
//	 * Returns whether or not the two indicated objects are equal. It allows
//	 * either or both of the specified objects to be null.
//	 * @param o1 the first object or null
//	 * @param o2 the second object or null
//	 * @return true if the objects are equal.
//	 */
//	public static boolean same(Object o1, Object o2) {
//		if (o1 == null) {
//			return (o2 == null);
//		}
//		else {
//			return o1.equals(o2);
//		}
//	}
//
//    /**
//     * Returns the signed hex string representing the int value. 
//     * Positive values are represented beginning with 0x. (i.e. value of 12 would be 0xc)
//     * Negative values are represented beginning with -0x. (i.e. value of -12 would be -0xc)
//     * @param value the value
//     * @return the signed hex string
//     */
//	public static String toSignedHexString(int value) {
//		return (value >= 0 ? "0x"+Integer.toHexString(value) :
//		                    "-0x"+Integer.toHexString(-value) );
//	}
//	
//    /**
//     * Returns the signed hex string representing the long value. 
//     * Positive values are represented beginning with 0x. (i.e. value of 12 would be 0xc)
//     * Negative values are represented beginning with -0x. (i.e. value of -12 would be -0xc)
//     * @param value the value
//     * @return the signed hex string
//     */
//	public static String toSignedHexString(long value) {
//		return (value >= 0 ? "0x"+Long.toHexString(value) :
//		                    "-0x"+Long.toHexString(-value) );
//	}
}
