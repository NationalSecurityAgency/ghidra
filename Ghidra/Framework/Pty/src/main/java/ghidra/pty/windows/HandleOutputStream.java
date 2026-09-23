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
import java.io.OutputStream;
import java.lang.foreign.*;

import com.microsoft.win32.win32_h;

import ghidra.pty.windows.Win32Err.LastErrorException;

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
		write(b, 0, b.length);
	}

	@Override
	public synchronized void write(byte[] b, int off, int len) throws IOException {
		if (closed) {
			throw new IOException("Stream closed");
		}
		if (len == 0) {
			return;
		}
		try (Arena arena = Arena.ofConfined()) {
			MemorySegment cs = arena.allocate(Win32Err.LAYOUT);
			MemorySegment buf = arena.allocate(len);
			MemorySegment.copy(b, off, buf, ValueLayout.JAVA_BYTE, 0, len);
			MemorySegment dwWritten = arena.allocate(win32_h.DWORD);
			int total = 0;
			do {
				MemorySegment slice = buf.asSlice(total);
				Win32Err.checkFalse(win32_h.WriteFile(cs, handle.asSegment(), slice, len - total,
					dwWritten, MemorySegment.NULL), cs);
				total += dwWritten.get(win32_h.DWORD, 0);
			}
			while (total < len);
		}
		catch (LastErrorException e) {
			// LATER: Should select specific error numbers?
			throw new IOException(e);
		}
	}

	@Override
	public synchronized void close() throws IOException {
		closed = true;
	}

	/**
	 * {@return true if this handle has buffered output}
	 * <p>
	 * Windows can get touchy when trying to flush handles that are not actually buffered. If the
	 * wrapped handle is not buffered, then this method must return false, otherwise, any attempt to
	 * flush this stream will result in {@code ERROR_INVALID_HANDLE}. 
	 */
	protected boolean isBuffered() {
		return true;
	}

	@Override
	public void flush() throws IOException {
		if (!isBuffered()) {
			return;
		}
		try (Arena arena = Arena.ofConfined()) {
			MemorySegment cs = arena.allocate(Win32Err.LAYOUT);
			Win32Err.checkFalse(win32_h.FlushFileBuffers(cs, handle.asSegment()), cs);
		}
	}
}
