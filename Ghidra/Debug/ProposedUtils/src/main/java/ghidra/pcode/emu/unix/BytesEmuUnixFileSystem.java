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

import ghidra.pcode.emu.sys.BytesEmuFileContents;
import ghidra.pcode.emu.sys.EmuFileContents;

/**
 * A concrete in-memory file system simulator suitable for UNIX programs
 */
public class BytesEmuUnixFileSystem extends AbstractEmuUnixFileSystem<byte[]> {

	/**
	 * A concrete in-memory file suitable for UNIX programs
	 */
	protected static class BytesEmuUnixFile extends AbstractEmuUnixFile<byte[]> {
		public BytesEmuUnixFile(String pathname, int mode) {
			super(pathname, mode);
		}

		@Override
		protected EmuFileContents<byte[]> createDefaultContents() {
			return new BytesEmuFileContents();
		}
	}

	/**
	 * Construct a new concrete simulated file system
	 */
	public BytesEmuUnixFileSystem() {
	}

	@Override
	public BytesEmuUnixFile newFile(String pathname, int mode) {
		return new BytesEmuUnixFile(pathname, mode);
	}
}
