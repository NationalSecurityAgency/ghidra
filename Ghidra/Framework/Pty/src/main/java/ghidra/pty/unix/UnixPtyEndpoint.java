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
package ghidra.pty.unix;

import java.io.*;

import ghidra.pty.PtyEndpoint;
import ghidra.pty.unix.PosixC.Ioctls;

public class UnixPtyEndpoint implements PtyEndpoint {
	protected final Ioctls ioctls;
	protected final int fd;
	private final FdOutputStream outputStream;
	private final FdInputStream inputStream;

	UnixPtyEndpoint(Ioctls ioctls, int fd) {
		this.ioctls = ioctls;
		this.fd = fd;
		this.outputStream = new FdOutputStream(fd);
		this.inputStream = new FdInputStream(fd);
	}

	@Override
	public OutputStream getOutputStream() {
		return outputStream;
	}

	@Override
	public InputStream getInputStream() {
		return inputStream;
	}

	protected void closeStreams() throws IOException {
		outputStream.close();
		inputStream.close();
	}
}
