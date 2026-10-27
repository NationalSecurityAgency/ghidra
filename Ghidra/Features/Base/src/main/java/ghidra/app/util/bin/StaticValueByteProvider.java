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

import java.io.File;
import java.io.IOException;
import java.util.Arrays;

import ghidra.formats.gfilesystem.FSRL;

/**
 * A {@link ByteProvider} that only has a single value for its entire length
 */
public class StaticValueByteProvider implements ByteProvider {

	private final FSRL fsrl;
	private long length;
	private byte value;

	/**
	 * Create an instance with the specified {@link FSRL} identity.
	 * @param length provider length
	 * @param value byte value of entire provider
	 * 
	 * @param fsrl {@link FSRL} identity for this instance
	 */
	public StaticValueByteProvider(long length, byte value, FSRL fsrl) {
		this.length = length;
		this.value = value;
		this.fsrl = fsrl;
	}

	@Override
	public void close() {
		// nothing
	}

	@Override
	public FSRL getFSRL() {
		return fsrl;
	}

	@Override
	public File getFile() {
		return null;
	}

	@Override
	public String getName() {
		return fsrl != null ? fsrl.getName() : null;
	}

	@Override
	public String getAbsolutePath() {
		return fsrl != null ? fsrl.getPath() : "";
	}

	@Override
	public long length() {
		return length;
	}

	/**
	 * Throws {@link IOException} if index is not a valid position in the buffer
	 *
	 * @param index position in buffer to test
	 * @param inclusiveMax allow buffer.length as index
	 * @throws IOException if index is out of bounds
	 */
	private void assertValidIndex(long index, boolean inclusiveMax) throws IOException {
		if (index < 0 || index > length || (inclusiveMax == false && index == length)) {
			throw new IOException("Invalid position, index: " + index + ", max is: " + length);
		}
	}

	@Override
	public byte readByte(long index) throws IOException {
		assertValidIndex(index, false);
		return value;
	}

	@Override
	public byte[] readBytes(long index, long readLength) throws IOException {
		assertValidIndex(index, true);
		if (index + readLength > length) {
			throw new IOException("Attempt to read beyond end of byte data");
		}
		byte[] destBytes = new byte[(int) readLength];
		Arrays.fill(destBytes, value);
		return destBytes;
	}
}
