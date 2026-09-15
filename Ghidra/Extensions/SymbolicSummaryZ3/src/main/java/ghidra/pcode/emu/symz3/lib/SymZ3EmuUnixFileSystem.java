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
package ghidra.pcode.emu.symz3.lib;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.pcode.emu.sys.*;
import ghidra.pcode.emu.unix.AbstractEmuUnixFile;
import ghidra.pcode.emu.unix.AbstractEmuUnixFileSystem;
import ghidra.symz3.model.SymValueZ3;

public class SymZ3EmuUnixFileSystem extends AbstractEmuUnixFileSystem<Pair<byte[], SymValueZ3>> {

	/**
	 * A file whose contents have a SymValueZ3 piece
	 */
	public static class SymZ3EmuUnixFile extends AbstractEmuUnixFile<Pair<byte[], SymValueZ3>> {
		protected BytesEmuFileContents concrete = new BytesEmuFileContents();

		public SymZ3EmuUnixFile(String pathname, int mode) {
			super(pathname, mode);
		}

		@Override
		protected EmuFileContents<Pair<byte[], SymValueZ3>> createDefaultContents() {
			// for now we leave the piece null
			return new PairedEmuFileContents<>(concrete, null);
		}
	}

	@Override
	public AbstractEmuUnixFile<Pair<byte[], SymValueZ3>> newFile(String pathname, int mode)
			throws EmuIOException {
		return new SymZ3EmuUnixFile(pathname, mode);
	}
}
