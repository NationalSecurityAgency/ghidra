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
package ghidra.app.util.bin;

import java.io.*;

import ghidra.program.model.address.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

/**
 * A {@link ByteProvider} implementation based on {@link Memory}.
 */
public class MemoryByteProvider implements ByteProvider {

	protected Memory memory;
	protected Address baseAddress;

	/**
	 * Constructs a new {@link MemoryByteProvider} for a specific {@link AddressSpace}.  Bytes will be
	 * provided starting at address 0 in the space.
	 * 
	 * @param memory the {@link Memory}
	 * @param space the {@link AddressSpace}
	 */
	public MemoryByteProvider(Memory memory, AddressSpace space) {
		this(memory, space.getAddress(0));
	}

	/**
	 * Constructs a new {@link MemoryByteProvider} relative to the specified base address.
	 * 
	 * @param memory the {@link Memory}
	 * @param baseAddress the base address
	 */
	public MemoryByteProvider(Memory memory, Address baseAddress) {
		this.memory = memory;
		this.baseAddress = baseAddress;
	}

	/**
	 * Converts an index into this ByteProvider into an {@link Address}.
	 * <p>
	 * 
	 * @param index absolute index in this ByteProvider to convert into an Address
	 * @return {@link Address}
	 * @throws AddressOutOfBoundsException if wrapping is not supported by the 
	 * corresponding address space and the addition causes an out-of-bounds
	 * error
	 */
	public Address getAddress(long index) {
		return baseAddress.add(index);
	}

	@Override
	public InputStream getInputStream(long index) throws IOException {
		return new MemoryByteProviderInputStream(memory, baseAddress.add(index));
	}

	@Override
	public File getFile() {
		return new File(memory.getProgram().getExecutablePath());
	}

	@Override
	public String getName() {
		return memory.getProgram().getName();
	}

	@Override
	public String getAbsolutePath() {
		return memory.getProgram().getExecutablePath();
	}

	@Override
	public long length() throws IOException {
		MemoryBlock block = memory.getBlock(baseAddress);
		if (block == null || !block.isInitialized()) {
			return 0;
		}
		return block.getEnd().subtract(baseAddress) + 1;
	}

	@Override
	public boolean isValidIndex(long index) {
		try {
			Address indexAddress = baseAddress.add(index);
			return memory.contains(indexAddress);
		}
		catch (AddressOutOfBoundsException e) {
			return false;
		}
	}

	@Override
	public byte readByte(long index) throws IOException {
		try {
			return memory.getByte(baseAddress.add(index));
		}
		catch (Exception e) {
			throw new IOException(e.getMessage());
		}
	}

	@Override
	public byte[] readBytes(long index, long length) throws IOException {
		try {
			byte[] bytes = new byte[(int) length];
			int nRead = memory.getBytes(baseAddress.add(index), bytes);
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
	public void close() {
		// don't do anything for now
	}
}
