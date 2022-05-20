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

import ghidra.pcode.emu.sys.EmuIOException;
import ghidra.pcode.exec.BytesPcodeArithmetic;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.program.model.lang.Language;
import ghidra.util.MathUtilities;

/**
 * A concrete in-memory file system simulator suitable for UNIX programs
 */
public class BytesEmuUnixFileSystem extends AbstractEmuUnixFileSystem<byte[]> {

	/**
	 * A concrete in-memory file suitable for UNIX programs
	 */
	protected static class BytesEmuUnixFile extends AbstractEmuUnixFile<byte[]> {
		protected static final int INIT_CONTENT_SIZE = 1024;

		protected byte[] content = new byte[INIT_CONTENT_SIZE];

		/**
		 * Construct a new file
		 * 
		 * @see BytesEmuUnixFileSystem#newFile(String)
		 * @param pathname the original pathname of the file
		 */
		public BytesEmuUnixFile(String pathname, int mode) {
			super(pathname, mode);
		}

		@Override
		public synchronized byte[] read(PcodeArithmetic<byte[]> arithmetic, byte[] offset,
				byte[] buf) {
			// NOTE: UNIX takes long offsets, but since we're backing with arrays, we use int
			int off = arithmetic.toConcrete(offset).intValue();
			int len = Math.min(buf.length, (int) stat.st_size - off);
			if (len < 0) {
				throw new EmuIOException("Offset is past end of file");
			}
			System.arraycopy(content, off, buf, 0, len);
			return arithmetic.fromConst(len, offset.length);
		}

		@Override
		public synchronized byte[] write(PcodeArithmetic<byte[]> arithmetic, byte[] offset,
				byte[] buf) {
			int off = arithmetic.toConcrete(offset).intValue();
			if (off + buf.length > content.length) {
				byte[] grown = new byte[content.length * 2];
				System.arraycopy(content, 0, grown, 0, (int) stat.st_size);
				content = grown;
			}
			System.arraycopy(buf, 0, content, off, buf.length);
			// TODO: Uhh, arrays can't get larger than INT_MAX anyway
			stat.st_size = MathUtilities.unsignedMax(stat.st_size, off + buf.length);
			return arithmetic.fromConst(buf.length, offset.length);
		}

		@Override
		public synchronized void truncate() {
			stat.st_size = 0;
			// TODO: Zero content?
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
