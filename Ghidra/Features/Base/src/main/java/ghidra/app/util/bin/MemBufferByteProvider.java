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

import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * <code>MemBufferByteProvider</code> provide a {@link ByteProvider} backed by
 * a {@link MemBuffer}.
 */
public class MemBufferByteProvider implements ByteProvider {

	private MemBuffer buffer;

	/**
	 * Constructor
	 * @param buffer memory buffer
	 */
	public MemBufferByteProvider(MemBuffer buffer) {
		this.buffer = buffer;
	}

	@Override
	public File getFile() {
		return null;
	}

	@Override
	public String getName() {
		return null;
	}

	@Override
	public String getAbsolutePath() {
		return null;
	}

	/**
	 * Return maximum length since actual length is unknown
	 * @return maximum possible length
	 */
	@Override
	public long length() {
		return Integer.MAX_VALUE;
	}

	@Override
	public boolean isValidIndex(long index) {
		if (index < 0 || index > Integer.MAX_VALUE) {
			return false;
		}
		try {
			buffer.getByte((int) index);
			return true;
		}
		catch (MemoryAccessException e) {
			return false;
		}
	}

	@Override
	public void close() throws IOException {
		// not applicable
	}

	@Override
	public byte readByte(long index) throws IOException {
		if (index < 0 || index > Integer.MAX_VALUE) {
			throw new IOException("index out of range");
		}
		try {
			return buffer.getByte((int) index);
		}
		catch (MemoryAccessException e) {
			throw new IOException("index out of range");
		}
	}

	@Override
	public byte[] readBytes(long index, long length) throws IOException {
		if (index < 0 || (index + length - 1) > Integer.MAX_VALUE) {
			throw new IOException("index/length of range");
		}
		int len = (int) length;
		byte[] bytes = new byte[len];
		if (buffer.getBytes(bytes, (int) index) != len) {
			throw new IOException("index/length of range");
		}
		return bytes;
	}

	@Override
	public InputStream getInputStream(long index) throws IOException {
		if (index < 0 || index > Integer.MAX_VALUE) {
			throw new IOException("index out of range");
		}
		return new MemBufferProviderInputStream((int) index);
	}

	private class MemBufferProviderInputStream extends InputStream {

		private int initialOffset;
		private int offset;

		MemBufferProviderInputStream(int offset) {
			this.offset = offset;
			this.initialOffset = offset;
		}

		@Override
		public int read() throws IOException {
			byte b = readByte(offset++);
			return b & 0xff;
		}

		@Override
		public int read(byte[] b, int off, int len) {
			byte[] bytes = new byte[len];
			int count = buffer.getBytes(bytes, offset);
			System.arraycopy(bytes, 0, b, off, count);
			offset += count;
			return count;
		}

		@Override
		public int available() {
			return (int) length() - offset;
		}

		@Override
		public synchronized void reset() throws IOException {
			offset = initialOffset;
		}

		@Override
		public void close() throws IOException {
			// not applicable
		}
	}

}
