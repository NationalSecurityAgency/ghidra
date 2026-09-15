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
package ghidra.util.bytesearch;

import java.io.IOException;
import java.io.InputStream;

/**
 * ByteSequence that buffers an {@link InputStream}
 */
public class InputStreamBufferByteSequence implements ByteSequence {
	private byte[] bytes;
	private int validDataLength;

	public InputStreamBufferByteSequence(int bufferSize) {
		bytes = new byte[bufferSize];
	}

	/**
	 * Loads data into this byte sequence from the given input stream
	 * @param is the input stream to read bytes from
	 * @param amount the number of bytes to read from the stream
	 * @throws IOException if an error occurs reading from the stream
	 */
	public void load(InputStream is, int amount) throws IOException {
		if (amount > bytes.length) {
			throw new IllegalArgumentException("Attempted to read greater that buffer size!");
		}
		int numRead = is.read(bytes, 0, amount);
		validDataLength = numRead >= 0 ? numRead : 0;
	}

	@Override
	public int getLength() {
		return validDataLength;
	}

	@Override
	public byte getByte(int index) {
		return bytes[index];
	}

	@Override
	public boolean hasAvailableBytes(int index, int length) {
		return index >= 0 && index + length <= validDataLength;
	}

	@Override
	public byte[] getBytes(int index, int length) {
		if (index < 0 || index + length > validDataLength) {
			throw new IndexOutOfBoundsException();
		}
		byte[] results = new byte[length];
		System.arraycopy(bytes, index, results, 0, length);
		return results;
	}

}
