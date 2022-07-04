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
package ghidra.file.formats.dump.cmd;

import java.io.File;
import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.mem.*;

/**
 * <code>MemBufferByteProvider</code> provide a {@link ByteProvider} backed by a {@link MemBuffer}.
 */
public class ProgramInsertByteProvider implements ByteProvider {

	private MemoryBufferImpl buffer;
	private ProgramFragment mod;
	private long len;

	public ProgramInsertByteProvider(Memory memory, ProgramFragment mod) {
		this.mod = mod;
		len = mod.getMaxAddress().subtract(mod.getMinAddress()) + 1;
		buffer = new MemoryBufferImpl(memory, mod.getMinAddress(), (int) len);
	}

	@Override
	public File getFile() {
		return null;
	}

	@Override
	public String getName() {
		return mod.getName();
	}

	@Override
	public String getAbsolutePath() {
		return null;
	}

	/**
	 * Return maximum length since actual length is unknown
	 * 
	 * @return maximum possible length
	 */
	@Override
	public long length() {
		return len;
	}

	@Override
	public boolean isValidIndex(long index) {
		if (index < 0 || index > len) {
			return false;
		}
		try {
			buffer.getByte((int) index);
			return true;
		}
		catch (MemoryAccessException e) {
			return false;
		}
	}

	@Override
	public void close() throws IOException {
		// not applicable
	}

	@Override
	public byte readByte(long index) throws IOException {
		if (index < 0 || index > Integer.MAX_VALUE) {
			throw new IOException("index out of range");
		}
		try {
			return buffer.getByte((int) index);
		}
		catch (MemoryAccessException e) {
			throw new RuntimeException("index out of range");
		}
	}

	@Override
	public byte[] readBytes(long index, long length) throws IOException {
		if (index < 0 || (index + length - 1) > Integer.MAX_VALUE) {
			throw new IOException("index/length of range");
		}
		int ilen = (int) length;
		byte[] bytes = new byte[ilen];
		if (buffer.getBytes(bytes, (int) index) != ilen) {
			throw new RuntimeException("index/length of range");
		}
		return bytes;
	}

}
