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
package ghidra.program.model.mem;

import java.io.IOException;
import java.io.InputStream;

/**
 * Adapter between {@link MemBuffer membuffers} and {@link InputStream inputstreams}.
 */
public class MemBufferInputStream extends InputStream {

	private MemBuffer membuf;
	private int currentPosition;
	private long maxPosition; // exclusive

	/**
	 * Creates a new instance, starting a offset 0 of the membuffer, limited to the first 2Gb
	 * of the membuffer.
	 * 
	 * @param membuf {@link MemBuffer} to wrap as an inputstream
	 */
	public MemBufferInputStream(MemBuffer membuf) {
		this(membuf, 0, Integer.MAX_VALUE);
	}

	/**
	 * Creates a new instance of {@link MemBufferInputStream}, starting at the specified offset,
	 * limited to the first {@code length} bytes.
	 * 
	 * @param membuf {@link MemBuffer} to wrap as an inputstream
	 * @param initialPosition starting position in the membuffer
	 * @param length number of bytes to limit this inputstream to.  The sum of 
	 * {@code initialPosition} and {@code length} must not exceed {@link Integer#MAX_VALUE}+1
	 */
	public MemBufferInputStream(MemBuffer membuf, int initialPosition, int length) {
		this.maxPosition = initialPosition + length;
		if (initialPosition < 0 || length < 0 || maxPosition > (long) Integer.MAX_VALUE + 1) {
			throw new IllegalArgumentException();
		}
		this.membuf = membuf;
		this.currentPosition = initialPosition;
	}

	@Override
	public void close() throws IOException {
		this.maxPosition = 0;
	}

	@Override
	public int available() throws IOException {
		return currentPosition >= 0 && currentPosition < maxPosition
				? (int) (maxPosition - currentPosition)
				: 0;
	}

	@Override
	public int read() throws IOException {
		try {
			if (currentPosition < 0 || currentPosition >= maxPosition) {
				return -1;
			}
			int result = Byte.toUnsignedInt(membuf.getByte(currentPosition));
			currentPosition++;
			return result;
		}
		catch (MemoryAccessException e) {
			throw new IOException(e);
		}
	}

}
