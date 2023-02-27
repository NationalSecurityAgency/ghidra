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

import ghidra.lifecycle.Unfinished;
import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.emu.sys.EmuIOException;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.program.model.lang.CompilerSpec;

/**
 * An abstract file descriptor having no "offset," typically for stream-like files
 *
 * @param <T> the type of values in the file
 */
public abstract class AbstractStreamEmuUnixFileHandle<T> implements EmuUnixFileDescriptor<T> {
	protected final PcodeArithmetic<T> arithmetic;
	protected final int offsetBytes;

	private final T offset;

	/**
	 * Construct a new handle
	 * 
	 * @see AbstractEmuUnixSyscallUseropLibrary#createHandle(int, EmuUnixFile, int)
	 * @param machine the machine emulating the hardware
	 * @param cSpec the ABI of the target platform
	 */
	public AbstractStreamEmuUnixFileHandle(PcodeMachine<T> machine, CompilerSpec cSpec) {
		this.arithmetic = machine.getArithmetic();
		this.offsetBytes = cSpec.getDataOrganization().getLongSize(); // off_t's fundamental type
		this.offset = arithmetic.fromConst(0, offsetBytes);
	}

	@Override
	public T getOffset() {
		return offset;
	}

	@Override
	public void seek(T offset) throws EmuIOException {
		// No effect
	}

	@Override
	public EmuUnixFileStat stat() {
		return Unfinished.TODO();
	}
}
