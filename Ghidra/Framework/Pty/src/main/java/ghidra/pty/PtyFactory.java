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

	/**
	 * Choose a factory of local pty's for the host operating system
	 * 
	 * @return the factory
	 */
	static PtyFactory local() {
		switch (OperatingSystem.CURRENT_OPERATING_SYSTEM) {
			case MAC_OS_X:
				return new MacosPtyFactory();
			case LINUX:
				return new LinuxPtyFactory();
			case WINDOWS:
				return new ConPtyFactory();
			default:
				throw new UnsupportedOperationException();
		}
	}

	/**
	 * Open a new pseudo-terminal
	 * 
	 * @return new new Pty
	 * @throws IOException for an I/O error, including cancellation
	 */
	Pty openpty() throws IOException;

	String getDescription();
}
