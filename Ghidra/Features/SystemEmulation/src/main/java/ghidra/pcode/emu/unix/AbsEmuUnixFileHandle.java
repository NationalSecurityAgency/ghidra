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
import ghidra.program.model.pcode.PcodeOp;

/**
 * A file descriptor for non-concrete types
 * 
 * @param <T> the type
 */
public class AbsEmuUnixFileHandle<T> extends AbstractEmuUnixFileHandle<T> {
	private T offset;

	public AbsEmuUnixFileHandle(PcodeMachine<T> machine, CompilerSpec cSpec, EmuUnixFile<T> file,
			Set<OpenFlag> flags, EmuUnixUser user) {
		super(machine, cSpec, file, flags, user);
		long off = flags.contains(OpenFlag.O_APPEND) ? file.getStat().st_size : 0;
		this.offset = arithmetic.fromConst(off, offsetBytes);
	}

	/**
	 * Advance the handle's offset (negative to rewind)
	 * 
	 * @param len the number of bytes to advance
	 */
	protected void advanceOffset(T len) {
		int sizeofLen = (int) arithmetic.sizeOf(len);
		offset =
			arithmetic.binaryOp(PcodeOp.INT_ADD, offsetBytes, offsetBytes, offset, sizeofLen, len);
	}

	protected boolean isPositive(T len) {
		int sizeofLen = (int) arithmetic.sizeOf(len);
		return arithmetic.isTrue(
			arithmetic.binaryOp(PcodeOp.INT_SLESS, 1, sizeofLen, arithmetic.fromConst(0, sizeofLen),
				sizeofLen, len),
			Purpose.OTHER);
	}

	@Override
	public T getAbstractOffset() {
		return offset;
	}

	@Override
	public long getOffset() {
		return arithmetic.toLong(offset, Purpose.OTHER);
	}

	@Override
	public void seek(T offset) throws EmuIOException {
		// TODO: Bounds check?
		this.offset = offset;
	}

	@Override
	public void seek(long offset) throws EmuIOException {
		seek(arithmetic.fromConst(offset, offsetBytes));
	}

	@Override
	public T readAbstract(T buf) throws EmuIOException {
		checkReadable();
		T len = file.read(arithmetic, offset, buf);
		if (isPositive(len)) {
			advanceOffset(len);
		}
		return len;
	}

	@Override
	public int read(T buf) throws EmuIOException {
		return (int) arithmetic.toLong(readAbstract(buf), Purpose.OTHER);
	}

	@Override
	public T writeAbstract(T buf) throws EmuIOException {
		checkWritable();
		T len = file.write(arithmetic, offset, buf);
		if (isPositive(len)) {
			advanceOffset(len);
		}
		return len;
	}

	@Override
	public int write(T buf) throws EmuIOException {
		return (int) arithmetic.toLong(writeAbstract(buf), Purpose.OTHER);
	}
}
