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
package agent.gdb.ffi.linux;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * A base class for either end of a pseudo-terminal
 * 
 * This provides the input and output streams
 */
public class PtyEndpoint {
	private final int fd;

	PtyEndpoint(int fd) {
		this.fd = fd;
	}

	/**
	 * Get the output stream for this end of the pty
	 * 
	 * Writes to this stream arrive on the input stream for the opposite end, subject to the
	 * terminal's line discipline.
	 * 
	 * @return the output stream
	 */
	public OutputStream getOutputStream() {
		return new FdOutputStream(fd);
	}

	/**
	 * Get the input stream for this end of the pty
	 * 
	 * Writes to the output stream of the opposite end arrive here, subject to the terminal's line
	 * discipline.
	 * 
	 * @return the input stream
	 */
	public InputStream getInputStream() {
		return new FdInputStream(fd);
	}
}
