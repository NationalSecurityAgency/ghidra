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
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;

/**
 * An abstract library of UNIX system calls, suitable for use with any processor
 * 
 * <p>
 * See the UNIX manual pages for more information about each specific system call, error numbers,
 * etc.
 * 
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
	 * 
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
	 * Place the errno into the machine as expected by the simulated platform's ABI
	 * 
	 * @param executor the executor for the thread running this system call
	 * @param errno the error number
	 * @return true if the errno was successfully placed
	 */
	protected abstract boolean returnErrno(PcodeExecutor<T> executor, int errno);

	@Override
	public boolean handleError(PcodeExecutor<T> executor, PcodeExecutionException err) {
		if (err instanceof EmuUnixException) {
			Integer errno = ((EmuUnixException) err).getErrno();
			if (errno == null) {
				return false;
			}
			return returnErrno(executor, errno);
		}
		return false;
	}

	/**
	 * The UNIX {@code exit} system call
	 * 
	 * <p>
	 * This just throws an exception, which the overall simulator or script should catch.
	 * 
	 * @param status the status code
	 * @return never
	 * @throws EmuProcessExitedException always
	 */
	@PcodeUserop
	@EmuSyscall("exit")
	public T unix_exit(T status) {
		throw new EmuProcessExitedException(machine.getArithmetic(), status);
	}

	/**
	 * The UNIX {@code read} system call
	 * 
	 * @param state to receive the thread's state
	 * @param fd the file descriptor
	 * @param bufPtr the pointer to the buffer to receive the data
	 * @param count the number of bytes to read
	 * @return the number of bytes successfully read
	 */
	@PcodeUserop
	@EmuSyscall("read")
	public T unix_read(@OpState PcodeExecutorState<T> state, T fd, T bufPtr, T count) {
		PcodeArithmetic<T> arithmetic = machine.getArithmetic();
		int ifd = (int) arithmetic.toLong(fd, Purpose.OTHER);
		EmuUnixFileDescriptor<T> desc = findFd(ifd);
		AddressSpace space = machine.getLanguage().getAddressFactory().getDefaultAddressSpace();
		// TODO: Not ideal to require concrete size, but gets unwieldy to leave it abstract
		int size = (int) arithmetic.toLong(count, Purpose.OTHER);
		T buf = arithmetic.fromConst(0, size);
		T result = desc.read(buf);
		int iresult = (int) arithmetic.toLong(result, Purpose.OTHER);
		state.setVar(space, bufPtr, iresult, true, buf);
		return result;
	}

	/**
	 * The UNIX {@code write} system call
	 * 
	 * @param state to receive the thread's state
	 * @param fd the file descriptor
	 * @param bufPtr the pointer to the buffer of data to write
	 * @param count the number of bytes to write
	 * @return the number of bytes successfully written
	 */
	@PcodeUserop
	@EmuSyscall("write")
	public T unix_write(@OpState PcodeExecutorState<T> state, T fd, T bufPtr, T count) {
		PcodeArithmetic<T> arithmetic = machine.getArithmetic();
		int ifd = (int) arithmetic.toLong(fd, Purpose.OTHER);
		EmuUnixFileDescriptor<T> desc = findFd(ifd);
		AddressSpace space = machine.getLanguage().getAddressFactory().getDefaultAddressSpace();
		// TODO: Not ideal to require concrete size. What are the alternatives, though?
		// TODO: size should actually be long (size_t)
		int size = (int) arithmetic.toLong(count, Purpose.OTHER);
		T buf = state.getVar(space, bufPtr, size, true, Reason.EXECUTE_READ);
		// TODO: Write back into state? "write" shouldn't touch the buffer....
		return desc.write(buf);
	}

	/**
	 * The UNIX {@code open} system call
	 * 
	 * @param state to receive the thread's state
	 * @param pathnamePtr the file's path (pointer to character string)
	 * @param flags the flags
	 * @param mode the mode
	 * @return the file descriptor
	 */
	@PcodeUserop
	@EmuSyscall("open")
	public T unix_open(@OpState PcodeExecutorState<T> state, T pathnamePtr, T flags, T mode) {
		PcodeArithmetic<T> arithmetic = machine.getArithmetic();
		int iflags = (int) arithmetic.toLong(flags, Purpose.OTHER);
		int imode = (int) arithmetic.toLong(mode, Purpose.OTHER);
		long pathnameOff = arithmetic.toLong(pathnamePtr, Purpose.OTHER);
		AddressSpace space = machine.getLanguage().getAddressFactory().getDefaultAddressSpace();

		SettingsImpl settings = new SettingsImpl();
		MemBuffer buffer = state.getConcreteBuffer(space.getAddress(pathnameOff), Purpose.OTHER);
		StringDataInstance sdi =
			new StringDataInstance(StringDataType.dataType, settings, buffer, -1);
		sdi = new StringDataInstance(StringDataType.dataType, settings, buffer,
			sdi.getStringLength());
		// TODO: Can NPE here be mapped to a unix error
		String pathname = Objects.requireNonNull(sdi.getStringValue());
		EmuUnixFile<T> file = fs.open(pathname, convertFlags(iflags), user, imode);
		int ifd = claimFd(createHandle(file, iflags));
		return arithmetic.fromConst(ifd, intSize);
	}

	/**
	 * The UNIX {@code close} system call
	 * 
	 * @param fd the file descriptor
	 * @return 0 for success
	 */
	@PcodeUserop
	@EmuSyscall("close")
	public T unix_close(T fd) {
		PcodeArithmetic<T> arithmetic = machine.getArithmetic();
		int ifd = (int) arithmetic.toLong(fd, Purpose.OTHER);
		// TODO: Some fs.close or file.close, when all handles have released it?
		EmuUnixFileDescriptor<T> desc = releaseFd(ifd);
		desc.close();
		return arithmetic.fromConst(0, intSize);
	}

	/**
	 * The UNIX {@code group_exit} system call
	 * 
	 * <p>
	 * This just throws an exception, which the overall simulator or script should catch.
	 * 
	 * @param status the status code
	 * @return never
	 * @throws EmuProcessExitedException always
	 */
	@PcodeUserop
	@EmuSyscall("group_exit")
	public void unix_group_exit(T status) {
		throw new EmuProcessExitedException(machine.getArithmetic(), status);
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
			types("int", "void *", "size_t"));;

		/**
		 * Inline the gather or scatter pattern for an iovec syscall
		 * 
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
