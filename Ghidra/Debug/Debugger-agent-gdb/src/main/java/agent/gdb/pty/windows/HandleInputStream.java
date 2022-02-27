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
import java.io.InputStream;

import com.sun.jna.LastErrorException;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.ptr.IntByReference;

public class HandleInputStream extends InputStream {
	private final Handle handle;
	private boolean closed = false;

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

	protected void waitPipeConnected() {
		if (Kernel32.INSTANCE.ConnectNamedPipe(handle.getNative(), null)) {
			return; // We waited, and now we're connected
		}
		int error = Kernel32.INSTANCE.GetLastError();
		if (error == Kernel32.ERROR_PIPE_CONNECTED) {
			return; // We got the connection before we waited. OK
		}
		throw new LastErrorException(error);
	}

	@Override
	public synchronized int read(byte[] b) throws IOException {
		if (closed) {
			throw new IOException("Stream closed");
		}
		IntByReference dwRead = new IntByReference();

		while (!Kernel32.INSTANCE.ReadFile(handle.getNative(), b, b.length, dwRead, null)) {
			int error = Kernel32.INSTANCE.GetLastError();
			switch (error) {
				case Kernel32.ERROR_BROKEN_PIPE:
					return -1;
				case Kernel32.ERROR_PIPE_LISTENING:
					/**
					 * Well, we know we're dealing with a listening pipe, now. Wait for a client,
					 * then try reading again.
					 */
					waitPipeConnected();
					continue;
			}
			throw new IOException("Could not read",
				new LastErrorException(error));
		}
		return dwRead.getValue();
	}

	@Override
	public synchronized int read(byte[] b, int off, int len) throws IOException {
		byte[] temp = new byte[len];
		int read = read(temp);
		System.arraycopy(temp, 0, b, off, read);
		return read;
	}

	@Override
	public synchronized void close() throws IOException {
		closed = true;
	}
}
