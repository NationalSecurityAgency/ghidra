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
package ghidra.pty.windows;

import java.io.IOException;
import java.io.InputStream;
import java.lang.foreign.*;

import com.microsoft.win32.win32_h;

import ghidra.pty.windows.Win32Err.LastErrorException;

public class HandleInputStream extends InputStream {
	private final Handle handle;
	private volatile boolean closed = false;

	HandleInputStream(Handle handle) {
		this.handle = handle;
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

	protected void waitPipeConnected(MemorySegment cs) {
		try {
			Win32Err.checkFalse(
				win32_h.ConnectNamedPipe(cs, handle.asSegment(), MemorySegment.NULL), cs);
			return; // We waited, and now we're connected
		}
		catch (LastErrorException e) {
			if (e.getLastError() == win32_h.ERROR_PIPE_CONNECTED()) {
				return; // We got the connection before we waited. OK.
			}
			throw e;
		}
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
		if (len == 0) {
			return 0;
		}
		try (Arena arena = Arena.ofConfined()) {
			MemorySegment cs = arena.allocate(Win32Err.LAYOUT);
			MemorySegment buf = arena.allocate(len);
			MemorySegment dwRead = arena.allocate(win32_h.DWORD);
			while (true) {
				try {
					Win32Err.checkFalse(win32_h.ReadFile(cs, handle.asSegment(), buf, len, dwRead,
						MemorySegment.NULL), cs);
					int ret = dwRead.get(win32_h.DWORD, 0);
					MemorySegment.copy(buf, ValueLayout.JAVA_BYTE, 0, b, off, ret);
					return ret;
				}
				catch (LastErrorException e) {
					if (e.getLastError() == win32_h.ERROR_BROKEN_PIPE()) {
						return -1;
					}
					if (e.getLastError() == win32_h.ERROR_PIPE_LISTENING()) {
						waitPipeConnected(cs);
						continue;
					}
					throw new IOException("Could not read", e);
				}
			}
		}
	}

	@Override
	public void close() throws IOException {
		closed = true;
		handle.close();
	}
}
