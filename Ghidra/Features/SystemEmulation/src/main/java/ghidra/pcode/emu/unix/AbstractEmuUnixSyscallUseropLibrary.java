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

import java.util.*;

import ghidra.docking.settings.SettingsImpl;
import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.emu.sys.AnnotatedEmuSyscallUseropLibrary;
import ghidra.pcode.emu.sys.EmuProcessExitedException;
import ghidra.pcode.emu.unix.EmuUnixFileSystem.OpenFlag;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;

/**
 * An abstract library of UNIX system calls, suitable for use with any processor
 * <p>
 * See the UNIX manual pages for more information about each specific system call, error numbers,
 * etc.
 * <p>
 * TODO: The rest of the system calls common to UNIX.
 * 
 * @param <T> the type of values processed by the library
 */
public abstract class AbstractEmuUnixSyscallUseropLibrary<T>
		extends AnnotatedEmuSyscallUseropLibrary<T> {

	/**
	 * The errno values as defined by the OS simulator
	 */
	public enum Errno {
		EBADF;
	}

	protected final EmuUnixFileSystem<T> fs;
	protected EmuUnixUser user;

	protected final int intSize;
	protected final NavigableSet<Integer> closedFds = new TreeSet<>();
	protected final Map<Integer, EmuUnixFileDescriptor<T>> descriptors = new HashMap<>();

	/**
	 * Construct a new library
	 * 
	 * @param machine the machine emulating the hardware
	 * @param fs the file system to export to the user-space program
	 * @param program a program containing the syscall definitions and conventions, likely the
	 *            target program
	 */
	public AbstractEmuUnixSyscallUseropLibrary(PcodeMachine<T> machine, EmuUnixFileSystem<T> fs,
			Program program) {
		this(machine, fs, program, EmuUnixUser.DEFAULT_USER);
	}

	/**
	 * Construct a new library
	 * 
	 * @param machine the machine emulating the hardware
	 * @param fs a file system to export to the user-space program
	 * @param program a program containing the syscall definitions and conventions, likely the
	 *            target program
	 * @param user the "current user" to simulate
	 */
	public AbstractEmuUnixSyscallUseropLibrary(PcodeMachine<T> machine, EmuUnixFileSystem<T> fs,
			Program program, EmuUnixUser user) {
		super(machine, program);
		this.fs = fs;
		this.user = user;
		this.intSize = program.getCompilerSpec().getDataOrganization().getIntegerSize();
	}

	/**
	 * Get the first available file descriptor
	 * 
	 * @return the lowest available descriptor
	 */
	protected int lowestFd() {
		Integer lowest = closedFds.pollFirst();
		if (lowest != null) {
			return lowest;
		}
		return descriptors.size();
	}

	/**
	 * Claim the lowest available file descriptor number for the given descriptor object
	 * <p>
	 * The descriptor will be added to the descriptor table for the claimed number
	 * 
	 * @param desc the descriptor object
	 * @return the descriptor number
	 */
	protected int claimFd(EmuUnixFileDescriptor<T> desc) {
		synchronized (descriptors) {
			int fd = lowestFd();
			putDescriptor(fd, desc);
			return fd;
		}
	}

	/**
	 * Get the file descriptor object for the given file descriptor number
	 * 
	 * @param fd the descriptor number
	 * @return the descriptor object
	 * @throws EmuUnixException with {@link Errno#EBADF} if the file descriptor is invalid
	 */
	protected EmuUnixFileDescriptor<T> findFd(int fd) {
		synchronized (descriptors) {
			EmuUnixFileDescriptor<T> desc = descriptors.get(fd);
			if (desc == null) {
				throw new EmuUnixException("Invalid descriptor: " + fd, getErrno(Errno.EBADF));
			}
			return desc;
		}
	}

	/**
	 * Release/invalidate the given file descriptor number
	 * 
	 * @param fd the file descriptor number
	 * @return the removed descriptor object
	 * @throws EmuUnixException with {@link Errno#EBADF} if the file descriptor is invalid
	 */
	protected EmuUnixFileDescriptor<T> releaseFd(int fd) {
		synchronized (descriptors) {
			if (descriptors.size() + closedFds.size() - 1 == fd) {
				return descriptors.remove(fd);
			}
			EmuUnixFileDescriptor<T> removed = descriptors.remove(fd);
			if (removed == null) {
				throw new EmuUnixException("Invalid descriptor: " + fd, getErrno(Errno.EBADF));
			}
			closedFds.add(fd);
			return removed;
		}
	}

	/**
	 * Plug our Sleigh-defined syscalls in
	 */
	@Override
	protected StructuredPart newStructuredPart() {
		return new UnixStructuredPart();
	}

	/**
	 * Convert the flags as defined for this platform to flags understood by the simulator
	 * 
	 * @param flags the platform-defined flags
	 * @return the simulator-defined flags
	 */
	protected abstract Set<OpenFlag> convertFlags(int flags);

	/**
	 * A factory method for creating an open file handle
	 * 
	 * @param file the file opened by the handle
	 * @param flags the open flags, as specified by the user, as defined by the platform
	 * @return the handle
	 */
	protected EmuUnixFileDescriptor<T> createHandle(EmuUnixFile<T> file, int flags) {
		return new DefaultEmuUnixFileHandle<>(machine, cSpec, file, convertFlags(flags), user);
	}

	/**
	 * Get the platform-specific errno value for the given simulator-defined errno
	 * 
	 * @param err the simulator-defined errno
	 * @return the platform-defined errno
	 */
	protected abstract int getErrno(Errno err);

	/**
	 * Put a descriptor into the process' open file handles
	 * 
	 * @param fd the file descriptor value
	 * @param desc the simulated descriptor (handle, console, etc.)
	 * @return the previous descriptor, which probably ought to be {@code null}
	 */
	public EmuUnixFileDescriptor<T> putDescriptor(int fd, EmuUnixFileDescriptor<T> desc) {
		synchronized (descriptors) {
			return descriptors.put(fd, desc);
		}
	}

	/**
	 * The UNIX {@code exit} system call
	 * <p>
	 * This just throws an exception, which the overall simulator or script should catch.
	 * 
	 * @param status the status code
	 * @throws EmuProcessExitedException always
	 */
	@PcodeUserop(functional = true)
	@EmuSyscall("exit")
	public void unix_exit(long status) {
		throw new EmuProcessExitedException(status);
	}

	protected T abstract_unix_read(PcodeExecutorState<T> state, T fd, T bufPtr, T count) {
		PcodeArithmetic<T> arithmetic = machine.getArithmetic();
		try {
			int ifd = (int) arithmetic.toLong(fd, Purpose.OTHER);
			EmuUnixFileDescriptor<T> desc = findFd(ifd);
			AddressSpace space = machine.getLanguage().getAddressFactory().getDefaultAddressSpace();
			int icount = (int) arithmetic.toLong(count, Purpose.OTHER);
			T buf = arithmetic.fromConst(0, icount);
			int result = desc.read(buf);
			machine.getSharedState().setVar(space, bufPtr, result, true, buf);
			return arithmetic.fromConst((long) result, intSize);
		}
		catch (EmuUnixException e) {
			// TODO: Does this generalize to all UNIX, or just Linux x86/amd64?
			return arithmetic.fromConst((long) -e.getErrno(), intSize);
		}
	}

	/**
	 * The UNIX {@code read} system call
	 * 
	 * @param fd the file descriptor
	 * @param bufPtr the pointer to the buffer to receive the data
	 * @param count the number of bytes to read
	 * @return the number of bytes successfully read
	 */
	@PcodeUserop(functional = true, signed = true)
	@EmuSyscall("read")
	public int unix_read(int fd, long bufPtr, int count) {
		PcodeArithmetic<T> arithmetic = machine.getArithmetic();
		try {
			EmuUnixFileDescriptor<T> desc = findFd(fd);
			AddressSpace space = machine.getLanguage().getAddressFactory().getDefaultAddressSpace();
			T buf = arithmetic.fromConst(0, count);
			int result = desc.read(buf);
			machine.getSharedState().setVar(space, bufPtr, result, true, buf);
			return result;
		}
		catch (EmuUnixException e) {
			// TODO: Does this generalize to all UNIX, or just Linux x86/amd64?
			return -e.getErrno();
		}
	}

	/**
	 * The UNIX {@code write} system call
	 * 
	 * @param fd the file descriptor
	 * @param bufPtr the pointer to the buffer of data to write
	 * @param count the number of bytes to write
	 * @return the number of bytes successfully written
	 */
	@PcodeUserop(functional = true, signed = true)
	@EmuSyscall("write")
	public int unix_write(int fd, long bufPtr, int count) {
		try {
			EmuUnixFileDescriptor<T> desc = findFd(fd);
			AddressSpace space = machine.getLanguage().getAddressFactory().getDefaultAddressSpace();
			T buf =
				machine.getSharedState().getVar(space, bufPtr, count, true, Reason.EXECUTE_READ);
			return desc.write(buf);
		}
		catch (EmuUnixException e) {
			return -e.getErrno();
		}
	}

	/**
	 * The UNIX {@code open} system call
	 * 
	 * @param pathnamePtr the file's path (pointer to character string)
	 * @param flags the flags
	 * @param mode the mode
	 * @return the file descriptor
	 */
	@PcodeUserop(functional = true, signed = true)
	@EmuSyscall("open")
	public int unix_open(long pathnamePtr, int flags, int mode) {
		try {
			AddressSpace space = machine.getLanguage().getAddressFactory().getDefaultAddressSpace();
			SettingsImpl settings = new SettingsImpl();
			MemBuffer buffer = machine.getSharedState()
					.getConcreteBuffer(space.getAddress(pathnamePtr), Purpose.OTHER);
			StringDataInstance sdi =
				new StringDataInstance(StringDataType.dataType, settings, buffer, -1);
			sdi = new StringDataInstance(StringDataType.dataType, settings, buffer,
				sdi.getStringLength());
			// TODO: Can NPE here be mapped to a unix error
			String pathname = Objects.requireNonNull(sdi.getStringValue());
			EmuUnixFile<T> file = fs.open(pathname, convertFlags(flags), user, mode);
			return claimFd(createHandle(file, flags));
		}
		catch (EmuUnixException e) {
			return -e.getErrno();
		}
	}

	/**
	 * The UNIX {@code close} system call
	 * 
	 * @param fd the file descriptor
	 * @return 0 for success
	 */
	@PcodeUserop(functional = true, signed = true)
	@EmuSyscall("close")
	public int unix_close(int fd) {
		try {
			// TODO: Some fs.close or file.close, when all handles have released it?
			EmuUnixFileDescriptor<T> desc = releaseFd(fd);
			desc.close();
			return 0;
		}
		catch (EmuUnixException e) {
			return -e.getErrno();
		}
	}

	/**
	 * The UNIX {@code group_exit} system call
	 * <p>
	 * This just throws an exception, which the overall simulator or script should catch.
	 * 
	 * @param status the status code
	 * @throws EmuProcessExitedException always
	 */
	@PcodeUserop(functional = true)
	@EmuSyscall("group_exit")
	public void unix_group_exit(long status) {
		throw new EmuProcessExitedException(status);
	}

	/**
	 * System calls defined using Structured Sleigh
	 */
	protected class UnixStructuredPart extends StructuredPart {
		/** "Extern" declaration of {@code unix_read} */
		final UseropDecl unix_read = userop(type("size_t"), "unix_read",
			types("int", "void *", "size_t"));
		/** "Extern" declaration of {@code unix_write} */
		final UseropDecl unix_write = userop(type("size_t"), "unix_write",
			types("int", "void *", "size_t"));

		/**
		 * Inline the gather or scatter pattern for an iovec syscall
		 * <p>
		 * This is essentially a macro by virtue of the host (Java) language. Note that
		 * {@link #_result(RVal)} from here will cause the whole userop to return, not just from
		 * {@link #gatherScatterIovec(Var, Var, Var, UseropDecl)}.
		 */
		protected void gatherScatterIovec(Var in_fd, Var in_iovec, Var in_iovcnt,
				UseropDecl subOp) {
			Var tmp_i = local("tmp_i", type("size_t"));
			Var tmp_total = local("tmp_total", type("size_t"));
			Var tmp_ret = local("tmp_ret", type("size_t"));

			_for(tmp_i.set(0), tmp_i.ltiu(in_iovcnt), tmp_i.inc(), () -> {
				Var tmp_io = local("tmp_io", in_iovec.index(tmp_i));
				Var tmp_base = local("tmp_base", tmp_io.field("iov_base").deref());
				Var tmp_len = local("tmp_len", tmp_io.field("iov_len").deref());
				tmp_ret.set(subOp.call(in_fd, tmp_base, tmp_len));
				_if(tmp_ret.ltis(0), () -> _result(tmp_ret));
				tmp_total.addiTo(tmp_ret);
				_if(tmp_ret.ltiu(tmp_len), () -> _break()); // We got less than this buffer
			});
			_result(tmp_total);
		}

		/**
		 * The UNIX {@code readv} system call
		 * 
		 * @param in_fd the file descriptor
		 * @param in_iovec pointer to the vector of buffers
		 * @param in_iovcnt the number of buffers
		 */
		@StructuredUserop(type = "size_t")
		@EmuSyscall("readv")
		public void unix_readv(@Param(type = "int", name = "in_fd") Var in_fd,
				@Param(type = "iovec *", name = "in_iovec") Var in_iovec,
				@Param(type = "size_t", name = "in_iovcnt") Var in_iovcnt) {
			gatherScatterIovec(in_fd, in_iovec, in_iovcnt, unix_read);
		}

		/**
		 * The UNIX {@code writev} system call
		 * 
		 * @param in_fd the file descriptor
		 * @param in_iovec pointer to the vector of buffers
		 * @param in_iovcnt the number of buffers
		 */
		@StructuredUserop(type = "size_t")
		@EmuSyscall("writev")
		public void unix_writev(@Param(type = "int", name = "in_fd") Var in_fd,
				@Param(type = "iovec *", name = "in_iovec") Var in_iovec,
				@Param(type = "size_t", name = "in_iovcnt") Var in_iovcnt) {
			gatherScatterIovec(in_fd, in_iovec, in_iovcnt, unix_write);
		}
	}
}
