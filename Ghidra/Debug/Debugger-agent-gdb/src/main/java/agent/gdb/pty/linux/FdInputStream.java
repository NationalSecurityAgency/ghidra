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
package agent.gdb.pty.linux;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

import jnr.posix.POSIX;
import jnr.posix.POSIXFactory;

/**
 * An input stream that wraps a native POSIX file descriptor
 * 
 * <p>
 * <b>WARNING:</b> This class makes use of jnr-ffi to invoke native functions. An invalid file
 * descriptor is generally detected, but an incorrect, but valid file descriptor may cause undefined
 * behavior.
 */
public class FdInputStream extends InputStream {
	private static final POSIX LIB_POSIX = POSIXFactory.getNativePOSIX();

	private final int fd;
	private boolean closed = false;

	/**
	 * Wrap the given file descriptor in an {@link InputStream}
	 * 
	 * @param fd the file descriptor
	 */
	FdInputStream(int fd) {
		this.fd = fd;
	}

	@Override
	public synchronized int read() throws IOException {
		if (closed) {
			throw new IOException("Stream closed");
		}
		byte[] buf = new byte[1];
		if (0 == read(buf)) {
			return -1;
		}
		return buf[0] & 0x0FF;
	}

	@Override
	public synchronized int read(byte[] b) throws IOException {
		return read(b, 0, b.length);
	}

	@Override
	public synchronized int read(byte[] b, int off, int len) throws IOException {
		if (closed) {
			throw new IOException("Stream closed");
		}
		ByteBuffer buf = ByteBuffer.wrap(b, off, len);
		int ret = LIB_POSIX.read(fd, buf, len);
		if (ret < 0) {
			throw new IOException(LIB_POSIX.strerror(LIB_POSIX.errno()));
		}
		return ret;
	}

	@Override
	public synchronized void close() throws IOException {
		closed = true;
	}
}
