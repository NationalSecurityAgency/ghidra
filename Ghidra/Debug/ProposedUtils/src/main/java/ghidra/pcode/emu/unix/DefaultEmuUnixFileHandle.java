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

import java.util.Set;

import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.emu.sys.EmuIOException;
import ghidra.pcode.emu.unix.EmuUnixFileSystem.OpenFlag;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.opbehavior.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.pcode.PcodeOp;

/**
 * A file descriptor associated with a file on a simulated UNIX file system
 *
 * @param <T> the type of values stored by the file
 */
public class DefaultEmuUnixFileHandle<T> implements EmuUnixFileDescriptor<T> {

	protected final PcodeArithmetic<T> arithmetic;
	protected final EmuUnixFile<T> file;
	// TODO: T flags? Meh.
	protected final Set<OpenFlag> flags;
	protected final EmuUnixUser user;
	protected final int offsetBytes;

	private T offset;

	/**
	 * Construct a new handle on the given file
	 * 
	 * @see AbstractEmuUnixSyscallUseropLibrary#createHandle(int, EmuUnixFile, int)
	 * @param machine the machine emulating the hardware
	 * @param cSpec the ABI of the target platform
	 * @param file the file opened by this handle
	 * @param flags the user-specified flags, as defined by the simulator
	 * @param user the user that opened the file
	 */
	public DefaultEmuUnixFileHandle(PcodeMachine<T> machine, CompilerSpec cSpec,
			EmuUnixFile<T> file, Set<OpenFlag> flags, EmuUnixUser user) {
		this.arithmetic = machine.getArithmetic();
		this.file = file;
		this.flags = flags;
		this.user = user;
		this.offsetBytes = cSpec.getDataOrganization().getLongSize(); // off_t's fundamental type

		this.offset = arithmetic.fromConst(0, offsetBytes);
	}

	/**
	 * Check if the file is readable, throwing {@link EmuIOException} if not
	 */
	public void checkReadable() {
		if (!OpenFlag.isRead(flags)) {
			throw new EmuIOException("File not opened for reading");
		}
	}

	/**
	 * Check if the file is writable, throwing {@link EmuIOException} if not
	 */
	public void checkWritable() {
		if (!OpenFlag.isWrite(flags)) {
			throw new EmuIOException("File not opened for writing");
		}
	}

	/**
	 * Advance the handle's offset (negative to rewind)
	 * 
	 * @param len the number of bytes to advance
	 */
	protected void advanceOffset(T len) {
		int sizeofLen = arithmetic.toConcrete(arithmetic.sizeOf(len)).intValue();
		offset = arithmetic.binaryOp(PcodeArithmetic.INT_ADD, offsetBytes, offsetBytes, offset,
			sizeofLen, len);
	}

	@Override
	public T getOffset() {
		return offset;
	}

	@Override
	public void seek(T offset) throws EmuIOException {
		// TODO: Where does bounds check happen?
		this.offset = offset;
	}

	@Override
	public T read(T buf) throws EmuIOException {
		checkReadable();
		T len = file.read(arithmetic, offset, buf);
		advanceOffset(len);
		return len;
	}

	@Override
	public T write(T buf) throws EmuIOException {
		checkWritable();
		if (flags.contains(OpenFlag.O_APPEND)) {
			offset = arithmetic.fromConst(file.getStat().st_size, offsetBytes);
		}
		T len = file.write(arithmetic, offset, buf);
		advanceOffset(len);
		return len;
	}

	@Override
	public EmuUnixFileStat stat() {
		return file.getStat();
	}

	@Override
	public void close() {
		// TODO: Let the file know a handle was closed?
	}
}
