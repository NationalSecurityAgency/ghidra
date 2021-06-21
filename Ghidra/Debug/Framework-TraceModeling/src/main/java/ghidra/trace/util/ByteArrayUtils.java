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
package ghidra.trace.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;

public enum ByteArrayUtils {
	;

	/**
	 * Compute the address set where two byte arrays differ, given a start address
	 * 
	 * @param start the address of the first byte in each array
	 * @param a the first array
	 * @param b the second array
	 * @return the address set where the arrays differ
	 */
	public static AddressSet computeDiffsAddressSet(Address start, byte[] a, byte[] b) {
		if (a.length != b.length) {
			throw new IllegalArgumentException("Arrays must be the same length");
		}
		// A means of early parameter checking, and I'll need it later
		Address end = start.add(a.length - 1);

		AddressSet result = new AddressSet();

		Address diffStart = null;
		for (int i = 0; i < a.length; i++) {
			if (a[i] == b[i]) {
				if (diffStart != null) {
					result.add(diffStart, start.add(i - 1));
				}
			}
			else {
				if (diffStart == null) {
					diffStart = start.add(i);
				}
			}
		}
		if (diffStart != null) {
			result.add(diffStart, end);
		}
		return result;
	}
}
