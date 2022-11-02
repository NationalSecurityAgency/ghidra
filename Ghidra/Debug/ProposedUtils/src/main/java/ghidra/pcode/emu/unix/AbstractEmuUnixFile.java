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

import ghidra.pcode.emu.sys.EmuFileContents;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.util.MathUtilities;

/**
 * An abstract file contained in an emulated file system
 *
 * <p>
 * Contrast this with {@link DefaultEmuUnixFileHandle}, which is a particular process's handle when
 * opening the file, not the file itself.
 *
 * @param <T> the type of values stored in the file
 */
public abstract class AbstractEmuUnixFile<T> implements EmuUnixFile<T> {

	protected final String pathname;
	protected final EmuUnixFileStat stat;
	protected EmuFileContents<T> contents;

	/**
	 * Construct a new file
	 * 
	 * <p>
	 * TODO: Technically, a file can be hardlinked to several pathnames, but for simplicity, or for
	 * diagnostics, we let the file know its own original name.
	 * 
	 * @see AbstractEmuUnixFileSystem#newFile(String)
	 * @param pathname the pathname of the file
	 * @param mode the mode of the file
	 */
	public AbstractEmuUnixFile(String pathname, int mode) {
		this.pathname = pathname;
		this.stat = createStat();
		this.stat.st_mode = mode;
		this.contents = createDefaultContents();
	}

	/**
	 * A factory method for the file's {@code stat} structure.
	 * 
	 * @return the stat structure.
	 */
	protected EmuUnixFileStat createStat() {
		return new EmuUnixFileStat();
	}

	/**
	 * A factory method for the file's default contents
	 * 
	 * @return the contents
	 */
	protected abstract EmuFileContents<T> createDefaultContents();

	@Override
	public String getPathname() {
		return pathname;
	}

	@Override
	public EmuUnixFileStat getStat() {
		return stat;
	}

	@Override
	public T read(PcodeArithmetic<T> arithmetic, T offset, T buf) {
		long off = arithmetic.toLong(offset, Purpose.OTHER);
		long len = contents.read(off, buf, stat.st_size);
		return arithmetic.fromConst(len, (int) arithmetic.sizeOf(offset));
	}

	@Override
	public T write(PcodeArithmetic<T> arithmetic, T offset, T buf) {
		long off = arithmetic.toLong(offset, Purpose.OTHER);
		long len = contents.write(off, buf, stat.st_size);
		stat.st_size = MathUtilities.unsignedMax(stat.st_size, off + len);
		return arithmetic.fromConst(len, (int) arithmetic.sizeOf(offset));
	}

	@Override
	public synchronized void truncate() {
		stat.st_size = 0;
		contents.truncate();
	}
}
