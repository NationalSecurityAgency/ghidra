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
package ghidra.app.util.bin;

import java.io.*;

/**
 * A {@link ByteProvider} implementation that wraps an {@link InputStream}, allowing
 * data to be read, as long as there are no operations that request data from a previous
 * offset.
 * <p>
 * In other words, this {@link ByteProvider} can only be used to read data at ever increasing 
 * offsets.
 * <p>
 */
public class InputStreamByteProvider implements ByteProvider {
	private InputStream inputStream;
	private long length;
	private long currentIndex;

	/**
	 * Constructs a {@link InputStreamByteProvider} from the specified {@link InputStream}
	 * 
	 * @param inputStream the underlying {@link InputStream}
	 * @param length the length of the {@link InputStreamByteProvider}
	 */
	public InputStreamByteProvider(InputStream inputStream, long length) {
		this.inputStream = inputStream;
		this.length = length;
	}

	@Override
	public void close() {
		// don't do anything for now
	}

	@Override
	public File getFile() {
		return null;
	}

	public InputStream getUnderlyingInputStream() {
		return inputStream;
	}

	@Override
	public InputStream getInputStream(long index) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getName() {
		return "InputStreamByteProvider Index=0x" + Long.toHexString(currentIndex) + " Length=0x" +
				Long.toHexString(length);
	}

	@Override
	public String getAbsolutePath() {
		return getName();
	}

	@Override
	public long length() throws IOException {
		return length;
	}

	@Override
	public boolean isValidIndex(long index) {
		return (index >= 0L) && (index < length);
	}

	@Override
	public byte readByte(long index) throws IOException {
		if (index < currentIndex) {
			throw new IOException("Attempted to read byte that was already read.");
		}
		else if (index > currentIndex) {
			currentIndex += inputStream.skip(index - currentIndex);
			if (currentIndex != index) {
				throw new IOException("Not enough bytes were skipped.");
			}
		}

		int value = inputStream.read();
		if (value == -1) {
			throw new EOFException();
		}
		currentIndex += 1L;
		return (byte) value;
	}

	@Override
	public byte[] readBytes(long index, long len) throws IOException {
		if (index < currentIndex) {
			throw new IOException("Attempted to read bytes that were already read.");
		}
		else if (index > currentIndex) {
			currentIndex += inputStream.skip(index - currentIndex);
			if (currentIndex != index) {
				throw new IOException("Not enough bytes were skipped.");
			}
		}

		byte[] values = new byte[(int) len];
		int nRead = inputStream.read(values);
		if (nRead != len) {
			throw new EOFException();
		}
		currentIndex += len;
		return values;
	}
}
