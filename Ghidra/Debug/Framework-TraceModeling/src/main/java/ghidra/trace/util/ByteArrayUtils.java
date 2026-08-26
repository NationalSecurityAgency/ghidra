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

import java.nio.ByteBuffer;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;

public enum ByteArrayUtils {
	;

	/**
	 * Compute the address set where two byte buffers differ, given a start address
	 * 
	 * @param start the address of the byte at each buffer's current position
	 * @param a the first buffer
	 * @param b the second buffer
	 * @return the address set where the buffers differ
	 * @throws IllegalArgumentException if the two buffers have different amounts remaining
	 */
	public static AddressSet computeDiffsAddressSet(Address start, ByteBuffer a, ByteBuffer b) {
		int length = a.remaining();
		if (length != b.remaining()) {
			throw new IllegalArgumentException("Buffers must have the same remaining count");
		}
		// A means of early parameter checking, and I'll need it later
		Address end = start.add(length - 1);

		AddressSet result = new AddressSet();

		Address diffStart = null;
		int aPos = a.position();
		int bPos = b.position();
		for (int i = 0; i < length; i++) {
			if (a.get(aPos + i) == b.get(bPos + i)) {
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

	/**
	 * Get or copy a byte buffer's backing array.
	 * <p>
	 * If the buffer's position and array offset is 0, then this returns the backing array.
	 * Otherwise, this copies the remaining contents of the buffer into a new array, without
	 * affecting the buffer's position.
	 * 
	 * @param buf the buffer
	 * @return the backing array or a new array with the buffer's remaining contents
	 */
	public static byte[] arrayOrGet(ByteBuffer buf) {
		if (buf.hasArray() && buf.arrayOffset() == 0 && buf.position() == 0) {
			return buf.array();
		}
		byte[] arr = new byte[buf.remaining()];
		buf.get(buf.position(), arr);
		return arr;
	}
}
