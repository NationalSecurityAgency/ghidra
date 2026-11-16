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

import java.util.EnumSet;
import java.util.Set;

import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.emu.unix.*;
import ghidra.pcode.emu.unix.EmuUnixFileSystem.AModeFlag;
import ghidra.pcode.emu.unix.EmuUnixFileSystem.OpenFlag;
import ghidra.program.model.listing.Program;

/**
 * An abstract library of Linux system calls, suitable for use with any processor
 * 
 * @param <T> the type of values processed by the library
 */
public abstract class AbstractEmuLinuxSyscallUseropLibrary<T>
		extends AbstractEmuUnixSyscallUseropLibrary<T> {
	public static final int ENOENT = 2;
	public static final int EIO = 5;
	public static final int EBADF = 9;
	public static final int ENOMEM = 12;
	public static final int EACCES = 13;
	public static final int EINVAL = 22;
	public static final int ESPIPE = 29;
	public static final int ENOSYS = 38;
	public static final int EOVERFLOW = 75;

	public static final int PROT_NONE = 0x0;
	public static final int PROT_READ = 0x1;
	public static final int PROT_WRITE = 0x2;
	public static final int PROT_EXEC = 0x4;

	public static final int F_OK = 0x0;
	public static final int R_OK = 0x4;
	public static final int W_OK = 0x2;
	public static final int X_OK = 0x1;

	// LATER: Gemini warns these may differ by architecture (esp, Alpha, MIPS, PPC)
	public static final int MAP_SHARED = 0x01;
	public static final int MAP_PRIVATE = 0x02;
	public static final int MAP_FILE = 0x0; // Deprecated
	public static final int MAP_FIXED = 0x10;
	public static final int MAP_ANONYMOUS = 0x20;
	public static final int MAP_ANON = 0x20;
	public static final int MAP_32BIT = 0x40;
	public static final int MAP_GROWSDOWN = 0x100;
	public static final int MAP_DENYWRITE = 0x800;
	public static final int MAP_EXECUTABLE = 0x1000;
	public static final int MAP_LOCKED = 0x2000;
	public static final int MAP_NORESERVE = 0x4000;
	public static final int MAP_POPULATE = 0x8000;
	public static final int MAP_NONBLOCK = 0x10000;
	public static final int MAP_STACK = 0x20000;
	public static final int MAP_HUGETLB = 0x40000;
	public static final int MAP_SYNC = 0x80000;
	public static final int MAP_FIXED_NOREPLACE = 0x100000;
	public static final int MAP_UNINITIALIZED = 0x4000000;

	public static final int O_MASK_RDWR = 0x3;
	public static final int O_RDONLY = 0x0;
	public static final int O_WRONLY = 0x1;
	public static final int O_RDWR = 0x2;
	public static final int O_CREAT = 0x40;
	public static final int O_TRUNC = 0x200;
	public static final int O_APPEND = 0x400;
	private long robustFutexListHead;

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
	protected Set<OpenFlag> convertOpenFlags(int flags) {
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
		try {
			return OpenFlag.set(result);
		}
		catch (IllegalArgumentException e) {
			throw new EmuUnixException(e.getMessage(), Errno.EINVAL, e);
		}
	}

	@Override
	protected int getErrno(Errno err) {
		return switch (err) {
			case EACCES -> EACCES;
			case ENOENT -> ENOENT;
			case EIO -> EIO;
			case EBADF -> EBADF;
			case ENOMEM -> ENOMEM;
			case EINVAL -> EINVAL;
			case ESPIPE -> ESPIPE;
			case ENOSYS -> ENOSYS;
			case EOVERFLOW -> EOVERFLOW;
		};
	}

	@Override
	protected int getAModeFlag(AModeFlag flag) {
		return switch (flag) {
			case R_OK -> R_OK;
			case W_OK -> W_OK;
			case X_OK -> X_OK;
		};
	}

	@Override
	protected int getMapFlag(MapFlag flag) {
		return switch (flag) {
			case MAP_SHARED -> MAP_SHARED;
			case MAP_PRIVATE -> MAP_PRIVATE;
			case MAP_32BIT -> MAP_32BIT;
			case MAP_ANON -> MAP_ANON;
			case MAP_ANONYMOUS -> MAP_ANONYMOUS;
			case MAP_DENYWRITE -> MAP_DENYWRITE;
			case MAP_EXECUTABLE -> MAP_EXECUTABLE;
			case MAP_FILE -> MAP_FILE;
			case MAP_FIXED -> MAP_FIXED;
			case MAP_GROWSDOWN -> MAP_GROWSDOWN;
			case MAP_HUGETLB -> MAP_HUGETLB;
			case MAP_LOCKED -> MAP_LOCKED;
			case MAP_NONBLOCK -> MAP_NONBLOCK;
			case MAP_NORESERVE -> MAP_NORESERVE;
			case MAP_POPULATE -> MAP_POPULATE;
			case MAP_STACK -> MAP_STACK;
			case MAP_UNINITIALIZED -> MAP_UNINITIALIZED;
		};
	}

	@Override
	protected int getProtFlag(ProtFlag flag) {
		return switch (flag) {
			case PROT_NONE -> PROT_NONE;
			case PROT_READ -> PROT_READ;
			case PROT_WRITE -> PROT_WRITE;
			case PROT_EXEC -> PROT_EXEC;
		};
	}

	@Override
	protected String getOperatingSystemName() {
		return "Linux";
	}

	@Override
	protected String getRelease() {
		return "";
	}

	@Override
	protected String getVersion() {
		return "5.14.0";
	}

	@PcodeUserop(functional = true, signed = true)
	@EmuSyscall("set_tid_address")
	public int linux_set_tid_address(long tidptr) {
		return 7; // As good a tid as any
	}

	@PcodeUserop(functional = true, signed = true)
	@EmuSyscall("set_robust_list")
	public int linux_set_robust_list(long headPtr, int len) {
		robustFutexListHead = headPtr;
		return 0;
	}

	@PcodeUserop(functional = true, signed = true)
	@EmuSyscall("rseq")
	public int linux_rseq() {
		return -getErrno(Errno.ENOSYS);
	}
}
