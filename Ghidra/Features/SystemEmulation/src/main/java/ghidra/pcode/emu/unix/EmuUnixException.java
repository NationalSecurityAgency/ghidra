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
package ghidra.pcode.emu.unix;

import java.util.Objects;

import ghidra.pcode.emu.sys.EmuSystemException;
import ghidra.pcode.emu.unix.AbstractEmuUnixSyscallUseropLibrary.Errno;

/**
 * An exception for errors within UNIX sytem call libraries
 */
public class EmuUnixException extends EmuSystemException {

	private final Errno errno;

	public EmuUnixException(String message, Errno errno) {
		this(message, errno, null);
	}

	@Override
	public String toString() {
		return "UnixErr [%s] %s".formatted(errno, getMessage());
	}

	/**
	 * Construct a new exception with an optional errno
	 * 
	 * <p>
	 * Providing an errno allows the system call dispatcher to automatically communicate errno to
	 * the target program. If provided, the exception will not interrupt the emulator, because the
	 * target program is expected to handle it. If omitted, the dispatcher simply allows the
	 * exception to interrupt the emulator.
	 * 
	 * @param message the message
	 * @param errno the errno, or {@code null}
	 * @param e the cause of this exception, or {@code null}
	 */
	public EmuUnixException(String message, Errno errno, Throwable e) {
		super(message, null, e);
		this.errno = Objects.requireNonNull(errno);
	}

	/**
	 * Get the errno associated with this exception
	 * 
	 * @return the errno
	 */
	public Errno getErrno() {
		return errno;
	}
}
