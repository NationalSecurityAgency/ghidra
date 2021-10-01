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

import java.io.IOException;
import java.io.InputStream;

/**
 * An {@link InputStream} that reads from a {@link ByteProvider}.
 * <p>
 * Does not close the underlying ByteProvider when closed itself.
 * 
 */
public class ByteProviderInputStream extends InputStream {

	/**
	 * An {@link InputStream} that reads from a {@link ByteProvider}, and <b>DOES</b>
	 * {@link ByteProvider#close() close()} the underlying ByteProvider when
	 * closed itself.
	 * <p> 
	 */
	public static class ClosingInputStream extends ByteProviderInputStream {
		/**
		 * Creates an {@link InputStream} that reads from a {@link ByteProvider}, that
		 * <b>DOES</b> {@link ByteProvider#close() close()} the underlying ByteProvider when
		 * closed itself.
		 * <p>
		 * @param provider the {@link ByteProvider} to read from (and close)
		 */
		public ClosingInputStream(ByteProvider provider) {
			super(provider);
		}

		@Override
		public void close() throws IOException {
			super.close();
			if (provider != null) {
				provider.close();
				provider = null;
			}
		}
	}

	protected ByteProvider provider;
	private long currentPosition;
	private long markPosition;

	/**
	 * Creates an InputStream that uses a ByteProvider as its source of bytes.
	 *  
	 * @param provider the {@link ByteProvider} to wrap
	 */
	public ByteProviderInputStream(ByteProvider provider) {
		this(provider, 0);
	}

	/**
	 * Creates an InputStream that uses a ByteProvider as its source of bytes.
	 *  
	 * @param provider the {@link ByteProvider} to wrap
	 * @param startPosition starting position in the provider
	 */
	public ByteProviderInputStream(ByteProvider provider, long startPosition) {
		this.provider = provider;
		this.markPosition = startPosition;
		this.currentPosition = startPosition;
	}

	@Override
	public void close() throws IOException {
		// nothing to do here
	}

	@Override
	public int available() throws IOException {
		return (int) Math.min(provider.length() - currentPosition, Integer.MAX_VALUE);
	}

	@Override
	public boolean markSupported() {
		return true;
	}

	@Override
	public synchronized void mark(int readlimit) {
		this.markPosition = currentPosition;
	}

	@Override
	public synchronized void reset() throws IOException {
		// synchronized because the base class's method is synchronized.
		this.currentPosition = markPosition;
	}

	@Override
	public long skip(long n) throws IOException {
		if (n <= 0) {
			return 0;
		}
		long newPosition = Math.min(provider.length(), currentPosition + n);
		long skipped = newPosition - currentPosition;
		currentPosition = newPosition;
		return skipped;
	}

	@Override
	public int read() throws IOException {
		return (currentPosition < provider.length())
				? Byte.toUnsignedInt(provider.readByte(currentPosition++))
				: -1;
	}

	@Override
	public int read(byte[] b, int bufferOffset, int len) throws IOException {
		long eof = provider.length();
		if (currentPosition >= eof) {
			return -1;
		}
		len = (int) Math.min(len, eof - currentPosition);
		byte[] bytes = provider.readBytes(currentPosition, len);
		System.arraycopy(bytes, 0, b, bufferOffset, len);
		currentPosition += len;
		return len;
	}

}
