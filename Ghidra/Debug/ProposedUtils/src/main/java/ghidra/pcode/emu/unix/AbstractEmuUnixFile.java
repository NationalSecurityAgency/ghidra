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
	protected final EmuUnixFileStat stat = createStat();

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
		stat.st_mode = mode;
	}

	/**
	 * A factory method for the file's {@code stat} structure.
	 * 
	 * @return the stat structure.
	 */
	protected EmuUnixFileStat createStat() {
		return new EmuUnixFileStat();
	}

	@Override
	public String getPathname() {
		return pathname;
	}

	@Override
	public EmuUnixFileStat getStat() {
		return stat;
	}
}
