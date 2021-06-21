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
package ghidra.util;

import java.nio.ByteBuffer;

/**
 * Some utilities for manipulating a {@link ByteBuffer}
 */
public interface ByteBufferUtils {
	/**
	 * Resize a write-mode buffer
	 * 
	 * <p>
	 * This preserves the buffer contents
	 * 
	 * @param buf the buffer
	 * @param capacity the new capacity, greater or equal to the buffer's limit
	 * @return the new buffer
	 */
	public static ByteBuffer resize(ByteBuffer buf, int capacity) {
		if (capacity < buf.limit()) {
			throw new IllegalArgumentException("New capacity must fit current contents");
		}
		buf.flip();
		ByteBuffer resized = ByteBuffer.allocate(capacity);
		resized.put(buf);
		return resized;
	}

	/**
	 * Resize a write-mode buffer to twice its current capacity
	 * 
	 * <p>
	 * This preserves the buffer contents
	 * 
	 * @param buf the buffer
	 * @return the new buffer
	 */
	public static ByteBuffer upsize(ByteBuffer buf) {
		return resize(buf, buf.capacity() * 2);
	}

	/**
	 * Checks for equality, with a mask applied
	 * 
	 * <p>
	 * This considers the entire contents of both buffers without regard for position or limit. Both
	 * buffers must have equal capacities to be considered equal. The mask, if given, must have
	 * capacity equal to that of the first buffer {@code a} or an exception is thrown.
	 * 
	 * @param mask a buffer containing the mask, or null to match all bytes exactly
	 * @param a the first buffer
	 * @param b the second buffer
	 * @return true if matches, false otherwise
	 * @throws IllegalArgumentException if {@code mask} and {@code a} have unequal capacities
	 */
	public static boolean maskedEquals(ByteBuffer mask, ByteBuffer a, ByteBuffer b) {
		int len = a.capacity();
		if (mask != null && mask.capacity() != len) {
			throw new IllegalArgumentException("mask and a must have equal capacities");
		}
		if (len != a.capacity()) {
			return false;
		}
		if (mask != null) {
			for (int i = 0; i < len; i++) {
				if ((a.get(i) & mask.get(i)) != (b.get(i) & mask.get(i))) {
					return false;
				}
			}
			return true;
		}
		for (int i = 0; i < len; i++) {
			if (a.get(i) != b.get(i)) {
				return false;
			}
		}
		return true;
	}
}
