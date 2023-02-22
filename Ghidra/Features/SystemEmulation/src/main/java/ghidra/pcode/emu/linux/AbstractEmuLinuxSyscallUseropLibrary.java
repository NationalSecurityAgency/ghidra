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
package ghidra.pcode.emu.linux;

import java.util.*;

import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.emu.unix.*;
import ghidra.pcode.emu.unix.EmuUnixFileSystem.OpenFlag;
import ghidra.program.model.listing.Program;

/**
 * An abstract library of Linux system calls, suitable for use with any processor
 * 
 * @param <T> the type of values processed by the library
 */
public abstract class AbstractEmuLinuxSyscallUseropLibrary<T>
		extends AbstractEmuUnixSyscallUseropLibrary<T> {
	public static final int O_MASK_RDWR = 0x3;
	public static final int O_RDONLY = 0x0;
	public static final int O_WRONLY = 0x1;
	public static final int O_RDWR = 0x2;
	public static final int O_CREAT = 0x40;
	public static final int O_TRUNC = 0x200;
	public static final int O_APPEND = 0x400;

	/**
	 * TODO: A map from simulator-defined errno to Linux-defined errno
	 * 
	 * <p>
	 * TODO: These may be applicable to all Linux, not just amd64....
	 */
	protected static final Map<Errno, Integer> ERRNOS = Map.ofEntries(
		Map.entry(Errno.EBADF, 9));

	/**
	 * Construct a new library
	 * 
	 * @param machine the machine emulating the hardware
	 * @param fs the file system to export to the user-space program
	 * @param program a program containing the syscall definitions and conventions, likely the
	 *            target program
	 */
	public AbstractEmuLinuxSyscallUseropLibrary(PcodeMachine<T> machine, EmuUnixFileSystem<T> fs,
			Program program) {
		super(machine, fs, program);
	}

	/**
	 * Construct a new library
	 * 
	 * @param machine the machine emulating the hardware
	 * @param fs the file system to export to the user-space program
	 * @param program a program containing the syscall definitions and conventions, likely the
	 *            target program
	 * @param user the "current user" to simulate
	 */
	public AbstractEmuLinuxSyscallUseropLibrary(PcodeMachine<T> machine, EmuUnixFileSystem<T> fs,
			Program program, EmuUnixUser user) {
		super(machine, fs, program, user);
	}

	@Override
	protected Set<OpenFlag> convertFlags(int flags) {
		EnumSet<OpenFlag> result = EnumSet.noneOf(OpenFlag.class);
		int rdwr = flags & O_MASK_RDWR;
		if (rdwr == O_RDONLY) {
			result.add(OpenFlag.O_RDONLY);
		}
		if (rdwr == O_WRONLY) {
			result.add(OpenFlag.O_WRONLY);
		}
		if (rdwr == O_RDWR) {
			result.add(OpenFlag.O_RDWR);
		}
		if ((flags & O_CREAT) != 0) {
			result.add(OpenFlag.O_CREAT);
		}
		if ((flags & O_TRUNC) != 0) {
			result.add(OpenFlag.O_TRUNC);
		}
		if ((flags & O_APPEND) != 0) {
			result.add(OpenFlag.O_APPEND);
		}
		return result;
	}

	@Override
	protected int getErrno(Errno err) {
		Integer errno = ERRNOS.get(err);
		if (errno == null) {
			throw new AssertionError("Do not know errno value for " + err);
		}
		return errno;
	}
}
