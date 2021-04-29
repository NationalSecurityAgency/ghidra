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
package ghidra.comm.util;

import java.nio.ByteBuffer;

/**
 * Some utilities for manipulating a {@link ByteBuffer}
 */
public interface ByteBufferUtils {
	/**
	 * Resize a write-mode buffer
	 * 
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
	 * This preserves the buffer contents
	 * 
	 * @param buf the buffer
	 * @return the new buffer
	 */
	public static ByteBuffer upsize(ByteBuffer buf) {
		return resize(buf, buf.capacity() * 2);
	}
}
