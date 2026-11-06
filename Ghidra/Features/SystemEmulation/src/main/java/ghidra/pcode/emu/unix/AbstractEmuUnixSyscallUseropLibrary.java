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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.*;

import generic.ULongSpan;
import generic.ULongSpan.DefaultULongSpanSet;
import generic.ULongSpan.MutableULongSpanSet;
import ghidra.docking.settings.SettingsImpl;
import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.emu.sys.AnnotatedEmuSyscallUseropLibrary;
import ghidra.pcode.emu.sys.EmuProcessExitedException;
import ghidra.pcode.emu.unix.EmuUnixFileSystem.AModeFlag;
import ghidra.pcode.emu.unix.EmuUnixFileSystem.OpenFlag;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.*;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.pcode.PcodeOp;

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
	// LATER: Should this be configurable?
	// I think there are syscalls to disable ASLR
	public static final int ALLOC_RAND_TRIES = 5;
	public static final int PAGE_BITS = 12;
	public static final long PAGE_MASK = -1L << PAGE_BITS;
	public static final long PAGE_INVMASK = ~PAGE_MASK;
	public static final int PAGE_SIZE = 1 << PAGE_BITS;
	public static final long RND_ADDR_PREFIX = 0x7fff_f600_0000_0000L;
	public static final long RND_ADDR_MASK = 0x0000_00ff_ffff_ffffL;

	public static final int DEFAULT_PID = 7; // As good as any

	/**
	 * The errno values as defined by the OS simulator
	 */
	public enum Errno {
		EACCES,
		EBADF,
		EINVAL,
		EIO,
		ENOENT,
		ENOMEM,
		ENOSYS,
		EOVERFLOW,
		ESPIPE,
		;
	}

	public enum ProtFlag {
		PROT_EXEC,
		PROT_READ,
		PROT_WRITE,
		PROT_NONE,
		;

		public final static List<ProtFlag> ALL = List.of(ProtFlag.values());

		public static Set<ProtFlag> set(ProtFlag... flags) {
			return set(Arrays.asList(flags));
		}

		public static Set<ProtFlag> set(Collection<ProtFlag> flags) {
			return Collections.unmodifiableSet(flags instanceof EnumSet<ProtFlag> es
					? es
					: flags.isEmpty() ? EnumSet.noneOf(ProtFlag.class) : EnumSet.copyOf(flags));
		}
	}

	/**
	 * Memory mapping flags as defined by the simulator
	 * <p>
	 * See a UNIX manual for the exact meaning of each.
	 */
	public enum MapFlag {
		MAP_SHARED,
		MAP_PRIVATE,
		MAP_32BIT,
		MAP_ANON,
		MAP_ANONYMOUS,
		MAP_DENYWRITE,
		MAP_EXECUTABLE,
		MAP_FILE,
		MAP_FIXED,
		MAP_GROWSDOWN,
		MAP_HUGETLB,
		MAP_LOCKED,
		MAP_NONBLOCK,
		MAP_NORESERVE,
		MAP_POPULATE,
		MAP_STACK,
		MAP_UNINITIALIZED,
		;

		public final static List<MapFlag> ALL = List.of(MapFlag.values());

		public static Set<MapFlag> set(MapFlag... flags) {
			return set(Arrays.asList(flags));
		}

		public static Set<MapFlag> set(Collection<MapFlag> flags) {
			return Collections.unmodifiableSet(flags instanceof EnumSet<MapFlag> es
					? es
					: flags.isEmpty() ? EnumSet.noneOf(MapFlag.class) : EnumSet.copyOf(flags));
		}
	}

	protected final Random random = new SecureRandom();
	// LATER: Probably a more rich memory map
	protected final MutableULongSpanSet allocatedMemory = new DefaultULongSpanSet();
	protected final EmuUnixFileSystem<T> fs;
	protected EmuUnixUser user;

	protected final int intSize;
	protected final NavigableSet<Integer> closedFds = new TreeSet<>();
	protected final Map<Integer, EmuUnixFileDescriptor<T>> descriptors = new HashMap<>();
	protected long break_; // end of heap segment

	protected int pid = DEFAULT_PID;

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
				throw new EmuUnixException("Invalid descriptor: " + fd, Errno.EBADF);
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
				throw new EmuUnixException("Invalid descriptor: " + fd, Errno.EBADF);
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
	protected abstract Set<OpenFlag> convertOpenFlags(int flags);

	protected Set<AModeFlag> convertAModeFlags(int flags) {
		return AModeFlag.set(AModeFlag.ALL.stream()
				.filter(f -> (getAModeFlag(f) & flags) != 0)
				.toList());
	}

	/**
	 * Convert the flags as defined for this platform to flags understood by the simulator
	 * 
	 * @param flags the platform-defined flags
	 * @return the simulator-defined flags
	 */
	protected Set<MapFlag> convertMapFlags(int flags) {
		return MapFlag.set(MapFlag.ALL.stream().filter(f -> (getMapFlag(f) & flags) != 0).toList());
	}

	protected Set<ProtFlag> convertProtFlags(int flags) {
		return ProtFlag.set(ProtFlag.ALL.stream()
				.filter(f -> (getProtFlag(f) & flags) != 0)
				.toList());
	}

	/**
	 * A factory method for creating an open file handle
	 * 
	 * @param file the file opened by the handle
	 * @param flags the open flags, as specified by the user, as defined by the platform
	 * @return the handle
	 */
	protected EmuUnixFileDescriptor<T> createHandle(EmuUnixFile<T> file, int flags) {
		return new DefaultEmuUnixFileHandle<>(machine, cSpec, file, convertOpenFlags(flags), user);
	}

	/**
	 * Get the platform-specific errno value for the given simulator-defined errno
	 * 
	 * @param err the simulator-defined errno
	 * @return the platform-defined errno
	 */
	protected abstract int getErrno(Errno err);

	protected int getErrno(EmuUnixException e) {
		return getErrno(e.getErrno());
	}

	/**
	 * LATER: I'm pretty sure this is standardized across UNIX.
	 * 
	 * @param flag the simulator-defined flag
	 * @return the platform-defined flag
	 */
	protected abstract int getAModeFlag(AModeFlag flag);

	protected abstract int getMapFlag(MapFlag flag);

	protected abstract int getProtFlag(ProtFlag flag);

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
			return arithmetic.fromConst((long) -getErrno(e), intSize);
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
		System.err.println("read(fd=%d, bufPtr=0x%x, count=%d)".formatted(fd, bufPtr, count));
		PcodeArithmetic<T> arithmetic = machine.getArithmetic();
		try {
			EmuUnixFileDescriptor<T> desc = findFd(fd);
			System.err.println("  desc=%s".formatted(desc));
			AddressSpace space = machine.getLanguage().getAddressFactory().getDefaultAddressSpace();
			T buf = arithmetic.fromConst(0, count);
			int result = desc.read(buf);
			machine.getSharedState().setVar(space, bufPtr, result, true, buf);
			System.err.println("  <ret>len=%d (0x%x)".formatted(result, result));
			return result;
		}
		catch (EmuUnixException e) {
			// TODO: Does this generalize to all UNIX, or just Linux x86/amd64?
			System.err.println("  <ret>err=%s".formatted(e));
			return -getErrno(e);
		}
	}

	@PcodeUserop(functional = true, signed = true)
	@EmuSyscall("pread64")
	public int unix_pread(int fd, long bufPtr, int count, long offset) {
		System.err.println("pread(fd=%d, bufPtr=0x%x, count=%d, offset=0x%x)".formatted(fd, bufPtr,
			count, offset));
		PcodeArithmetic<T> arithmetic = machine.getArithmetic();
		try {
			EmuUnixFileDescriptor<T> desc = findFd(fd);
			System.err.println("  desc=%s".formatted(desc));
			AddressSpace space = machine.getLanguage().getAddressFactory().getDefaultAddressSpace();
			T buf = arithmetic.fromConst(0, count);
			int result = desc.pread(buf, offset);
			machine.getSharedState().setVar(space, bufPtr, result, true, buf);
			System.err.println("  <ret>len=%d (0x%x)".formatted(result, result));
			return result;
		}
		catch (EmuUnixException e) {
			System.err.println("  <ret>err=%s".formatted(e));
			return -getErrno(e);
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
		System.err.println("write(fd=%d, bufPtr=0x%x, count=%d)".formatted(fd, bufPtr, count));
		try {
			EmuUnixFileDescriptor<T> desc = findFd(fd);
			AddressSpace space = machine.getLanguage().getAddressFactory().getDefaultAddressSpace();
			T buf =
				machine.getSharedState().getVar(space, bufPtr, count, true, Reason.EXECUTE_READ);
			int result = desc.write(buf);
			System.err.println("  <ret>len=%d (0x%x)".formatted(result, result));
			return result;
		}
		catch (EmuUnixException e) {
			System.err.println("  <ret>err=%s".formatted(e));
			return -getErrno(e);
		}
	}

	protected String readStringAt(long ptr) {
		AddressSpace space = machine.getLanguage().getDefaultDataSpace();
		SettingsImpl settings = new SettingsImpl();
		MemBuffer buffer =
			machine.getSharedState().getConcreteBuffer(space.getAddress(ptr), Purpose.OTHER);
		StringDataInstance sdi =
			new StringDataInstance(StringDataType.dataType, settings, buffer, -1);
		sdi = new StringDataInstance(StringDataType.dataType, settings, buffer,
			sdi.getStringLength());
		// LATER: Can NPE here be mapped to a unix error
		return Objects.requireNonNull(sdi.getStringValue());
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
		System.err.println(
			"open(pathnamePtr=0x%s, flags=0x%x, mode=0x%x)".formatted(pathnamePtr, flags, mode));
		try {
			String pathname = readStringAt(pathnamePtr);
			System.err.println("  pathname=%s".formatted(pathname));
			EmuUnixFile<T> file = fs.open(pathname, convertOpenFlags(flags), user, mode);
			int fd = claimFd(createHandle(file, flags));
			System.err.println("  <ret>fd=%d".formatted(fd));
			return fd;
		}
		catch (EmuUnixException e) {
			System.err.println("  <ret>err=%s".formatted(e));
			return -getErrno(e);
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
		System.err.println("close(fd=%d)".formatted(fd));
		try {
			// LATER: Some fs.close or file.close, when all handles have released it?
			EmuUnixFileDescriptor<T> desc = releaseFd(fd);
			desc.close();
			System.err.println("  <ret>0");
			return 0;
		}
		catch (EmuUnixException e) {
			System.err.println("  <ret>err=%s".formatted(e));
			return -getErrno(e);
		}
	}

	protected void copyIntoMemory(EmuUnixFileDescriptor<T> desc, long addr, long len, long offset) {
		// LATER: For Harvard arch, would we know which space based on flags?
		AddressSpace space = machine.getLanguage().getDefaultDataSpace();
		AddressRange rng;
		try {
			rng = new AddressRangeImpl(space.getAddress(addr), len);
		}
		catch (AddressOverflowException | AddressOutOfBoundsException e) {
			// LATER: I don't think this is entirely correct....
			throw new EmuUnixException("Length goes past end of space", Errno.EOVERFLOW);
		}
		PcodeArithmetic<T> arithmetic = machine.getArithmetic();
		long fileOffset = offset;
		T page = arithmetic.fromConst(new byte[PAGE_SIZE]);
		for (AddressRange sub : new AddressRangeChunker(rng, PAGE_SIZE)) {
			int read = desc.pread(page, fileOffset);
			if (read > 0) {
				T toWrite = read == PAGE_SIZE ? page
						: arithmetic.binaryOp(PcodeOp.SUBPIECE, read, PAGE_SIZE, page, 4,
							arithmetic.fromConst(0, 4));
				machine.getSharedState().setVar(sub.getMinAddress(), read, false, toWrite);
			}
			fileOffset += sub.getLength();
		}
	}

	@PcodeUserop(functional = true, signed = true)
	@EmuSyscall("mmap")
	public long unix_mmap(long addr, long len, int prot, int flags, int fd, long offset) {
		System.err.println(
			"mmap(addr=0x%x, len=0x%x, prot=0x%x, flags=0x%x, fd=%d, offset=0x%x)".formatted(
				addr, len, prot, flags, fd, offset));
		try {
			// LATER: Actually map, but we probably need an MMU
			// For now, just copy the range of bytes in. For SHARED, we'll wait to copy them
			// back out until msync or munmap
			EmuUnixFileDescriptor<T> desc = fd == -1 ? null : findFd(fd);
			System.err.println("  desc = %s".formatted(desc));
			Set<ProtFlag> pf = convertProtFlags(prot);
			Set<MapFlag> mf = convertMapFlags(flags);
			if (mf.contains(MapFlag.MAP_SHARED) && mf.contains(MapFlag.MAP_PRIVATE)) {
				throw new EmuUnixException("Canot be both shared and private", Errno.EINVAL);
			}
			long result = findAvailableMemory(addr, len);
			if (result == -1) {
				throw new EmuUnixException("Out of memory, or requested address not available",
					Errno.ENOMEM);
			}
			if (desc != null) {
				// TODO: desc should save what mode(s) it was opened
				// Check those modes against prot and maybe throw EACCES
				// TODO: Check PROT_EXEC and maybe throw EPERM
				copyIntoMemory(desc, result, len, offset);
			}
			claimMemory(result, len);
			System.err.println("  <ret>addr=0x%x".formatted(result));
			return result;
		}
		catch (EmuUnixException e) {
			System.err.println("  <ret>err=%s".formatted(e));
			return -getErrno(e);
		}
	}

	@PcodeUserop(functional = true, signed = true)
	@EmuSyscall("access")
	public long unix_access(long ptrName, int amode) {
		System.err.println("access(ptrName=0x%x, amode=0x%x)".formatted(ptrName, amode));
		try {
			String name = readStringAt(ptrName);
			System.err.println("  name = %s".formatted(name));
			EmuUnixFile<T> file = fs.requireFile(name);
			System.err.println("  file = %s".formatted(file));
			Set<AModeFlag> amf = convertAModeFlags(amode);
			if (amf.contains(AModeFlag.R_OK)) {
				file.checkReadable(user);
			}
			if (amf.contains(AModeFlag.W_OK)) {
				file.checkWritable(user);
			}
			if (amf.contains(AModeFlag.X_OK)) {
				file.checkExecutable(user);
			}
			System.err.println("  <ret>0");
			return 0;
		}
		catch (EmuUnixException e) {
			System.err.println("  <ret>err=%s".formatted(e));
			return -getErrno(e);
		}
	}

	public Path resolveAt(Path path, int dirfd) {
		EmuUnixFileDescriptor<T> desc = findFd(dirfd);
		throw new EmuUnixException("Directory file descriptors not yet supported", Errno.EBADF);
		/**
		 * TODO: dirfd == AT_FDCWD ? TODO: File handles to directories
		 * 
		 * TODO: Resolve the relative path against the absolute path of the descriptor, which must
		 * be a directory.
		 */
	}

	@PcodeUserop(functional = true, signed = true)
	@EmuSyscall("openat")
	public long unix_openat(int dirfd, long pathnamePtr, int flags, int mode) {
		System.err.println(
			"openat(dirfd=0x%x, pathnamePtr=0x%x, flags=0x%x, mode=0x%x)".formatted(
				dirfd, pathnamePtr, flags, mode));
		try {
			String pathname = readStringAt(pathnamePtr);
			System.err.println("  pathname=%s".formatted(pathname));
			Path path = Paths.get(pathname);
			EmuUnixFile<T> file;
			Set<OpenFlag> openFlags = convertOpenFlags(flags);
			System.err.println("  openFlags=%s".formatted(openFlags));
			Set<AModeFlag> modeFlags = convertAModeFlags(flags);
			System.err.println("  modeFlags=%s".formatted(modeFlags));
			if (path.isAbsolute()) {
				file = fs.open(pathname, openFlags, user, mode);
			}
			else {
				file =
					fs.open(resolveAt(path, dirfd).toString(), openFlags, user, mode);
			}
			int fd = claimFd(createHandle(file, flags));
			System.err.println("  <ret>fd=%d".formatted(fd));
			return fd;
		}
		catch (EmuUnixException e) {
			System.err.println("  <ret>err=%s".formatted(e));
			return -getErrno(e);
		}
	}

	@PcodeUserop(functional = true, signed = true, hasSideEffects = false)
	@EmuSyscall("getpid")
	public int unix_getpid() {
		System.err.println("getpid()");
		System.err.println("  <ret>pid=%d".formatted(pid));
		return pid;
	}

	protected void writeStat(EmuUnixFileStat stat, long bufPtr) {
		PcodeExecutorState<T> state = this.machine.getSharedState();
		AddressSpace space = state.getLanguage().getDefaultDataSpace();
		PcodeArithmetic<T> arithmetic = state.getArithmetic();

		// LATER: Derive offsets from struct stat, and/or use structured sleigh
		ByteBuffer buf = ByteBuffer.allocate(0x90)
				.order(state.getLanguage().isBigEndian() ? ByteOrder.BIG_ENDIAN
						: ByteOrder.LITTLE_ENDIAN);
		buf.putLong(stat.st_dev);
		buf.putLong(stat.st_ino);
		buf.putLong(stat.st_nlink);
		buf.putInt(stat.st_mode);
		buf.putInt(stat.st_uid);
		buf.putInt(stat.st_gid);
		buf.putInt(0); // __pad0
		buf.putLong(stat.st_rdev);
		buf.putLong(stat.st_size);
		buf.putLong(stat.st_blksize);
		buf.putLong(stat.st_blocks);
		buf.putLong(stat.st_atim_sec);
		buf.putLong(stat.st_atim_nsec);
		buf.putLong(stat.st_mtim_sec);
		buf.putLong(stat.st_mtim_nsec);
		buf.putLong(stat.st_ctim_sec);
		buf.putLong(stat.st_ctim_nsec);
		buf.putLong(0); // __unused[0]
		buf.putLong(0); // __unused[1]
		buf.putLong(0); // __unused[2]

		state.setVar(space, bufPtr, 0x90, false, arithmetic.fromConst(buf.array()));
	}

	@PcodeUserop(functional = true, signed = true)
	@EmuSyscall("fstat")
	public long unix_fstat(int fd, long bufPtr) {
		System.err.println("fstat(fd=%d, bufPtr=0x%x)".formatted(fd, bufPtr));
		try {
			EmuUnixFileDescriptor<T> desc = findFd(fd);
			System.err.println("  desc=%s".formatted(desc));
			writeStat(desc.stat(), bufPtr);
			System.err.println("  <ret>0");
			return 0;
		}
		catch (EmuUnixException e) {
			System.err.println("  <ret>err=%s".formatted(e));
			return -getErrno(e);
		}
	}

	@PcodeUserop(functional = true, signed = true)
	@EmuSyscall("newfstatat")
	public long unix_newfstatat(int dirfd, long pathnamePtr, long bufPtr, int flags) {
		System.err.println("newfstat(dirfd=%d, pathnamePtr=0x%x, bufPtr=0x%x, flags=0x%x)"
				.formatted(dirfd, pathnamePtr, bufPtr, flags));
		// TODO: flags: AT_EMPTY_PATH, AT_NO_AUTOMOUNT, AT_SYMLINK_NOFOLLOW
		try {
			String pathname = readStringAt(pathnamePtr);
			System.err.println("  pathname=%s".formatted(pathname));
			Path path = Paths.get(pathname);
			EmuUnixFile<T> file;
			if (path.isAbsolute()) {
				file = fs.requireFile(pathname);
			}
			else {
				file = fs.requireFile(resolveAt(path, dirfd).toString());
			}
			System.err.println("  file=%s".formatted(file));
			writeStat(file.getStat(), bufPtr);
			System.err.println("  <ret>0");
			return 0;
		}
		catch (EmuUnixException e) {
			System.err.println("  <ret>err=%s".formatted(e));
			return -getErrno(e);
		}
	}

	protected abstract String getOperatingSystemName();

	protected abstract String getRelease();

	protected abstract String getVersion();

	protected abstract String getMachine();

	@PcodeUserop(functional = true, signed = true)
	@EmuSyscall("uname")
	public int unix_uname(long ptrName) {
		System.err.println("uname(ptrName=0x%x)".formatted(ptrName));
		Charset utf8 = Charset.forName("utf8");
		byte[] sysname = getOperatingSystemName().getBytes(utf8);
		byte[] nodename = "localhost".getBytes(utf8);
		byte[] release = getRelease().getBytes(utf8);
		byte[] version = getVersion().getBytes(utf8);
		byte[] machine = getMachine().getBytes(utf8);
		byte[] domain = "localdomain".getBytes(utf8);

		PcodeExecutorState<T> state = this.machine.getSharedState();
		AddressSpace space = state.getLanguage().getDefaultDataSpace();
		PcodeArithmetic<T> arithmetic = state.getArithmetic();

		// LATER: Derive offsets from utsname type, and/or use structured sleigh
		state.setVar(space, ptrName, sysname.length, false, arithmetic.fromConst(sysname));
		state.setVar(space, ptrName + 0x41, nodename.length, false, arithmetic.fromConst(nodename));
		state.setVar(space, ptrName + 0x82, release.length, false, arithmetic.fromConst(release));
		state.setVar(space, ptrName + 0xc3, version.length, false, arithmetic.fromConst(version));
		state.setVar(space, ptrName + 0x104, machine.length, false, arithmetic.fromConst(machine));
		state.setVar(space, ptrName + 0x145, domain.length, false, arithmetic.fromConst(domain));

		System.err.println("  <ret>0");
		return 0;
	}

	/**
	 * The UNIX {@code exit_group} system call
	 * <p>
	 * This just throws an exception, which the overall simulator or script should catch.
	 * 
	 * @param status the status code
	 * @throws EmuProcessExitedException always
	 */
	@PcodeUserop(functional = true)
	@EmuSyscall("exit_group")
	public void unix_exit_group(long status) {
		throw new EmuProcessExitedException(status);
	}

	/**
	 * The UNIX {@code sys_brk} system call
	 * 
	 * @param break_ the requested break (end of heap segment)
	 * @return the new break
	 */
	@PcodeUserop(functional = true, hasSideEffects = true)
	@EmuSyscall("sys_brk")
	public long unix_sys_brk(long break_) {
		this.break_ = break_;
		return break_;
	}

	/**
	 * Find or validate the requested memory allocation
	 * <p>
	 * addr and len must be on page boundaries, or this throws an {@link Errno#EINVAL}
	 * {@link EmuUnixException}.
	 * 
	 * @param addr the requested address or 0 to pick an address
	 * @param len the length in bytes
	 * @return the found or validated address, or -1 to indicate it's not available
	 */
	protected long findAvailableMemory(long addr, long len) {
		if ((addr & PAGE_INVMASK) != 0 || (len & PAGE_INVMASK) != 0 || len == 0) {
			throw new EmuUnixException("Invalid addr/len parameters", Errno.EINVAL);
		}
		if (addr != 0) {
			if (allocatedMemory.intersects(ULongSpan.extent(addr, len))) {
				return -1;
			}
			return addr;
		}
		AddressSpace space = machine.getLanguage().getDefaultDataSpace();

		// The likelihood of immediate success depends on the size of the space, and how memory
		// hungry the application is. If that fails after a few tries, fall back to a linear search.
		// If that fails, report OOM

		for (int i = 0; i < ALLOC_RAND_TRIES; i++) {
			long rnd = (space.getSize() == 64
					? random.nextLong()
					: random.nextLong(1 << space.getSize())) &
				PAGE_MASK & RND_ADDR_MASK | RND_ADDR_PREFIX;
			if (!allocatedMemory.intersects(ULongSpan.extent(rnd, len))) {
				return rnd;
			}
		}

		for (ULongSpan gap : allocatedMemory.complement(ULongSpan.ALL)) {
			if (gap.length() < len) {
				return gap.min();
			}
		}

		return -1;
	}

	/**
	 * Allocate memory
	 * <p>
	 * These should probably be on page boundaries
	 * 
	 * @param addr the starting address
	 * @param len the length in bytesF
	 */
	protected void claimMemory(long addr, long len) {
		putClaimedMemory(addr, len);
	}

	public void putClaimedMemory(long addr, long len) {
		allocatedMemory.add(ULongSpan.extent(addr, len));
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
