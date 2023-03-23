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
package ghidra.pcode.emu.taint.lib;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.pcode.emu.sys.*;
import ghidra.pcode.emu.unix.*;
import ghidra.taint.model.TaintVec;

/**
 * A file system containing tainted files
 */
public class TaintEmuUnixFileSystem extends AbstractEmuUnixFileSystem<Pair<byte[], TaintVec>> {

	/**
	 * A taint-contents for a file whose contents are not tainted
	 */
	public static class UntaintedFileContents implements EmuFileContents<TaintVec> {
		@Override
		public long read(long offset, TaintVec buf, long fileSize) {
			buf.setEmpties();
			return buf.length;
		}

		@Override
		public long write(long offset, TaintVec buf, long curSize) {
			return 0; // I don't care
		}

		@Override
		public void truncate() {
		}
	}

	/**
	 * A taint-contents for a read-only file whose contents are completely tainted
	 */
	public static class ReadOnlyTaintArrayFileContents implements EmuFileContents<TaintVec> {
		private final String filename;

		public ReadOnlyTaintArrayFileContents(String filename) {
			this.filename = filename;
		}

		@Override
		public long read(long offset, TaintVec buf, long fileSize) {
			buf.setArray(filename, offset);
			return buf.length;
		}

		@Override
		public long write(long offset, TaintVec buf, long curSize) {
			return 0; // I don't care
		}

		@Override
		public void truncate() {
		}
	}

	/**
	 * A file whose contents have a taint piece
	 */
	public static class TaintEmuUnixFile extends AbstractEmuUnixFile<Pair<byte[], TaintVec>> {
		protected BytesEmuFileContents concrete = new BytesEmuFileContents();

		public TaintEmuUnixFile(String pathname, int mode) {
			super(pathname, mode);
		}

		@Override
		protected EmuFileContents<Pair<byte[], TaintVec>> createDefaultContents() {
			return new PairedEmuFileContents<>(concrete, new UntaintedFileContents());
		}

		public void setTainted(boolean tainted) {
			contents =
				new PairedEmuFileContents<>(concrete, new ReadOnlyTaintArrayFileContents(pathname));
		}
	}

	@Override
	public AbstractEmuUnixFile<Pair<byte[], TaintVec>> newFile(String pathname, int mode)
			throws EmuIOException {
		return new TaintEmuUnixFile(pathname, mode);
	}

	/**
	 * Place a tainted file into the file system with the given contents
	 * 
	 * @param pathname the pathname of the file
	 * @param contents the concrete contents of the file
	 */
	public void putTaintedFile(String pathname, byte[] contents) {
		TaintEmuUnixFile file = new TaintEmuUnixFile(pathname, 0777);
		file.setTainted(true);
		EmuUnixFileStat stat = file.getStat();
		file.concrete.write(0, contents, stat.st_size);
		stat.st_size = contents.length;
		putFile(pathname, file);
	}
}
