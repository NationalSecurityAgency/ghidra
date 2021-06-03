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

import ghidra.program.database.mem.FileBytes;

/**
 * <code>FileBytesProvider</code> provides a {@link ByteProvider} implementation 
 * for {@link FileBytes} object.
 */
public class FileBytesProvider implements ByteProvider {

	private final FileBytes fileBytes;

	/**
	 * Construct byte provider from original file bytes
	 * @param fileBytes original file bytes
	 */
	public FileBytesProvider(FileBytes fileBytes) {
		this.fileBytes = fileBytes;
	}

	@Override
	public File getFile() {
		return null;
	}

	@Override
	public String getName() {
		return fileBytes.getFilename();
	}

	@Override
	public String getAbsolutePath() {
		return null;
	}

	@Override
	public long length() {
		return fileBytes.getSize();
	}

	@Override
	public boolean isValidIndex(long index) {
		return 0 <= index && index < length();
	}

	@Override
	public void close() throws IOException {
		// do nothing
	}

	@Override
	public byte readByte(long index) throws IOException {
		return fileBytes.getOriginalByte(index);
	}

	@Override
	public byte[] readBytes(long index, long length) throws IOException {
		if (length < 0 || length > Integer.MAX_VALUE) {
			throw new IllegalArgumentException("unsupported length");
		}
		if (index < 0) {
			throw new IllegalArgumentException("invalid index");
		}
		long len = length();
		long lastIndex = index + length - 1;
		if (index >= len || lastIndex >= length()) {
			throw new EOFException();
		}
		byte[] bytes = new byte[(int) length];
		fileBytes.getOriginalBytes(index, bytes);
		return bytes;
	}

	@Override
	public InputStream getInputStream(long index) throws IOException {
		if (index < 0) {
			throw new IllegalArgumentException("invalid index");
		}
		if (index >= length()) {
			throw new EOFException();
		}
		return new FileBytesProviderInputStream(index);
	}

	private class FileBytesProviderInputStream extends InputStream {

		private long initialOffset;
		private long offset;

		FileBytesProviderInputStream(long offset) {
			this.offset = offset;
			this.initialOffset = offset;
		}

		@Override
		public int read() throws IOException {
			byte b = readByte(offset++);
			return b & 0xff;
		}

		@Override
		public int read(byte[] b, int off, int len) throws IOException {
			byte[] bytes = new byte[len];
			int count = fileBytes.getOriginalBytes(offset, bytes);
			System.arraycopy(bytes, 0, b, off, count);
			offset += count;
			return count;
		}

		@Override
		public int available() {
			long avail = length() - offset;
			return avail > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) avail;
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
