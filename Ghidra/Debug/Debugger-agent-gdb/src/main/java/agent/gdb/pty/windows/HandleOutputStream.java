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
package agent.gdb.pty.windows;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

import com.sun.jna.LastErrorException;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.ptr.IntByReference;

public class HandleOutputStream extends OutputStream {
	private final Handle handle;
	private boolean closed = false;

	public HandleOutputStream(Handle handle) {
		this.handle = handle;
	}

	@Override
	public synchronized void write(int b) throws IOException {
		write(new byte[] { (byte) b });
	}

	@Override
	public synchronized void write(byte[] b) throws IOException {
		if (closed) {
			throw new IOException("Stream closed");
		}

		int total = 0;
		do {
			IntByReference dwWritten = new IntByReference();
			if (!Kernel32.INSTANCE.WriteFile(handle.getNative(), b, b.length, dwWritten, null)) {
				throw new IOException("Could not write",
					new LastErrorException(Kernel32.INSTANCE.GetLastError()));
			}
			total += dwWritten.getValue();
		}
		while (total < b.length);
	}

	@Override
	public synchronized void write(byte[] b, int off, int len) throws IOException {
		// Abstraction of Windows API given by JNA doesn't have offset
		// In C, could add offset to lpBuffer, but not here :(
		write(Arrays.copyOfRange(b, off, off + len));
	}

	@Override
	public synchronized void close() throws IOException {
		closed = true;
	}

	/**
	 * Check whether this handle has buffered output
	 * 
	 * <p>
	 * Windows can get touchy when trying to flush handles that are not actually buffered. If the
	 * wrapped handle is not buffered, then this method must return false, otherwise, any attempt to
	 * flush this stream will result in {@code ERROR_INVALID_HANDLE}.
	 * 
	 * @return
	 */
	protected boolean isBuffered() {
		return true;
	}

	@Override
	public void flush() throws IOException {
		if (!isBuffered()) {
			return;
		}
		if (!(Kernel32.INSTANCE.FlushFileBuffers(handle.getNative()))) {
			throw new LastErrorException(Kernel32.INSTANCE.GetLastError());
		}
	}
}
