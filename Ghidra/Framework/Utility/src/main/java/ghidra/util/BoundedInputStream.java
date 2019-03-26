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

import java.io.IOException;
import java.io.InputStream;

/**
 * {@link InputStream} wrapper that limits itself to a portion of the wrapped stream.
 */
public class BoundedInputStream extends InputStream {

	private final InputStream wrappedInputStream;
	private final long limit;
	private long position;

	/**
	 * Creates a new instance.
	 *
	 * @param wrappedInputStream {@link InputStream} to wrap, already positioned to the desired
	 * starting position.
	 * @param size number of bytes to allow this wrapper to read.
	 */
	public BoundedInputStream(InputStream wrappedInputStream, long size) {
		this.wrappedInputStream = wrappedInputStream;
		this.limit = size;
	}

	@Override
	public int read() throws IOException {
		if (position >= limit) {
			return -1;
		}
		position++;
		return wrappedInputStream.read();
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		if (position >= limit) {
			return -1;
		}
		int bytesLeft = (int) Math.min(limit - position, Integer.MAX_VALUE);
		int bytesToRead = Math.min(len, bytesLeft);
		int bytesRead = wrappedInputStream.read(b, off, bytesToRead);
		if (bytesRead >= 0) {
			position += bytesRead;
		}
		return bytesRead;
	}

	@Override
	public void close() throws IOException {
		wrappedInputStream.close();
	}

	@Override
	public long skip(long n) throws IOException {
		long bytesLeft = limit - position;
		long toSkip = Math.min(bytesLeft, n);

		long skipped = wrappedInputStream.skip(toSkip);
		position += skipped;
		return skipped;
	}
}
