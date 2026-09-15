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
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.program.model.lang.CompilerSpec;

/**
 * A concrete file descriptor
 * 
 * @param <T> the type of values stored in the file
 */
public class DefaultEmuUnixFileHandle<T> extends AbstractEmuUnixFileHandle<T> {
	long offset;

	/**
	 * Construct a new handle on the given file
	 * 
	 * @see AbstractEmuUnixSyscallUseropLibrary#createHandle(EmuUnixFile, int)
	 * @param machine the machine emulating the hardware
	 * @param cSpec the ABI of the target platform
	 * @param file the file opened by this handle
	 * @param flags the user-specified flags, as defined by the simulator
	 * @param user the user that opened the file
	 */
	public DefaultEmuUnixFileHandle(PcodeMachine<T> machine, CompilerSpec cSpec,
			EmuUnixFile<T> file, Set<OpenFlag> flags, EmuUnixUser user) {
		super(machine, cSpec, file, flags, user);
		this.offset = flags.contains(OpenFlag.O_APPEND) ? file.getStat().st_size : 0;
	}

	@Override
	public long getOffset() {
		return offset;
	}

	@Override
	public T getAbstractOffset() {
		return arithmetic.fromConst(offset, offsetBytes);
	}

	@Override
	public void seek(T offset) throws EmuIOException {
		seek(arithmetic.toLong(offset, Purpose.OTHER));
	}

	@Override
	public void seek(long offset) throws EmuIOException {
		// TODO: Where does bounds check happen?
		this.offset = offset;
	}

	@Override
	public int read(T buf) throws EmuIOException {
		checkReadable();
		int len = file.read(offset, buf);
		if (len > 0) {
			offset += len;
		}
		return len;
	}

	@Override
	public T readAbstract(T buf) throws EmuIOException {
		return arithmetic.fromConst(read(buf), offsetBytes);
	}

	@Override
	public int write(T buf) throws EmuIOException {
		checkWritable();
		int len = file.write(offset, buf);
		if (len > 0) {
			offset += len;
		}
		return len;
	}

	@Override
	public T writeAbstract(T buf) throws EmuIOException {
		return arithmetic.fromConst(write(buf), offsetBytes);
	}
}
