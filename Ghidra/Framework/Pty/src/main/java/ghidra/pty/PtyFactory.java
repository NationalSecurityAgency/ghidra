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
package ghidra.pty;

import java.io.IOException;

import ghidra.framework.OperatingSystem;
import ghidra.pty.linux.LinuxPtyFactory;
import ghidra.pty.macos.MacosPtyFactory;
import ghidra.pty.windows.ConPtyFactory;

/**
 * A mechanism for opening pseudo-terminals
 */
public interface PtyFactory {
	short DEFAULT_COLS = 80;
	short DEFAULT_ROWS = 25;

	/**
	 * Choose a factory of local pty's for the host operating system
	 * 
	 * @return the factory
	 */
	static PtyFactory local() {
		switch (OperatingSystem.CURRENT_OPERATING_SYSTEM) {
			case MAC_OS_X:
				return MacosPtyFactory.INSTANCE;
			case LINUX:
				return LinuxPtyFactory.INSTANCE;
			case WINDOWS:
				return ConPtyFactory.INSTANCE;
			default:
				throw new UnsupportedOperationException();
		}
	}

	/**
	 * Open a new pseudo-terminal
	 * 
	 * @param cols the initial width in characters, or 0 to let the system decide both dimensions
	 * @param rows the initial height in characters, or 0 to let the system decide both dimensions
	 * @return new new Pty
	 * @throws IOException for an I/O error, including cancellation
	 */
	Pty openpty(short cols, short rows) throws IOException;

	/**
	 * Open a new pseudo-terminal of the default size ({@value #DEFAULT_COLS} x
	 * {@value #DEFAULT_ROWS})
	 * 
	 * @return new new Pty
	 * @throws IOException for an I/O error, including cancellation
	 */
	default Pty openpty() throws IOException {
		return openpty(DEFAULT_COLS, DEFAULT_ROWS);
	}

	/**
	 * Open a new pseudo-terminal
	 * 
	 * @param cols the initial width in characters, or 0 to let the system decide both dimensions
	 * @param rows the initial height in characters, or 0 to let the system decide both dimensions
	 * @return new new Pty
	 * @throws IOException for an I/O error, including cancellation
	 */
	default Pty openpty(int cols, int rows) throws IOException {
		return openpty((short) cols, (short) rows);
	}

	/**
	 * Get a human-readable description of the factory
	 * 
	 * @return the description
	 */
	String getDescription();
}
