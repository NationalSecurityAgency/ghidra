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

import java.io.IOException;

import ghidra.pcode.emu.sys.EmuFileContents;
import ghidra.pcode.emu.sys.EmuIOException;
import ghidra.program.database.mem.FileBytes;

public class FileBytesEmuUnixFile extends AbstractEmuUnixFile<byte[]> {
	static final int BLOCK_SIZE = 4096;
	private final FileBytes fileBytes;

	public FileBytesEmuUnixFile(String pathname, int mode, FileBytes fileBytes) {
		this.fileBytes = fileBytes;
		super(pathname, mode);
	}

	@Override
	protected EmuFileContents<byte[]> createDefaultContents() {
		return new FileBytesEmuFileContents(fileBytes);
	}

	@Override
	protected EmuUnixFileStat createStat() {
		EmuUnixFileStat stat = super.createStat();
		stat.st_blksize = BLOCK_SIZE;
		stat.st_blocks = (fileBytes.getSize() + BLOCK_SIZE - 1) / BLOCK_SIZE;
		stat.st_size = fileBytes.getSize();
		return stat;
	}

	public static class FileBytesEmuFileContents implements EmuFileContents<byte[]> {
		private final FileBytes fileBytes;

		public FileBytesEmuFileContents(FileBytes fileBytes) {
			this.fileBytes = fileBytes;
		}

		public FileBytes getFileBytes() {
			return fileBytes;
		}

		@Override
		public int read(long offset, byte[] buf, long fileSize) {
			try {
				return fileBytes.getOriginalBytes(offset, buf);
			}
			catch (IndexOutOfBoundsException | IOException e) {
				throw new EmuIOException("Error reading: %s".formatted(e.getMessage()), e);
			}
		}

		@Override
		public int write(long offset, byte[] buf, long curSize) {
			throw new EmuIOException("Cannot write");
		}

		@Override
		public void truncate() {
			throw new EmuIOException("Cannot write");
		}
	}
}
