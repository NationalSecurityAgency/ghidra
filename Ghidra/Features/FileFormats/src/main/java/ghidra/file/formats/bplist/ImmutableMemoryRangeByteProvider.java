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
package ghidra.file.formats.bplist;

import java.io.*;

import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

class ImmutableMemoryRangeByteProvider implements ByteProvider {

	private Memory memory;
	private Address start;
	private Address end;

	ImmutableMemoryRangeByteProvider(Memory memory, Address start, Address end) {
		this.memory = memory;
		this.start = start;
		this.end = end;
	}

	@Override
	public File getFile() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getName() {
		MemoryBlock block = memory.getBlock(start);
		if (block != null) {
			return block.getName();
		}
		return memory.getProgram().getName() + "_" + start.toString();
	}

	@Override
	public String getAbsolutePath() {
		throw new UnsupportedOperationException();
	}

	@Override
	public long length() throws IOException {
		return end.subtract(start) + 1;
	}

	@Override
	public boolean isValidIndex(long index) {
		Address indexAddress = start.add(index);
		return start.compareTo(indexAddress) >= 0 && end.compareTo(indexAddress) <= 0;
	}

	@Override
	public void close() throws IOException {
		// nothing to close
	}

	@Override
	public byte readByte(long index) throws IOException {
		Address indexAddress = start.add(index);
		try {
			return memory.getByte(indexAddress);
		}
		catch (Exception e) {
			throw new IOException(e.getMessage());
		}
	}

	@Override
	public byte[] readBytes(long index, long length) throws IOException {
		try {
			byte[] bytes = new byte[(int) length];
			Address indexAddress = start.add(index);
			int nRead = memory.getBytes(indexAddress, bytes);
			if (nRead != length) {
				throw new IOException("Unable to read " + length + " bytes at index " + index);
			}
			return bytes;
		}
		catch (Exception e) {
			throw new IOException(e.getMessage());
		}
	}

	@Override
	public InputStream getInputStream(long index) throws IOException {
		throw new UnsupportedOperationException();
	}

}
