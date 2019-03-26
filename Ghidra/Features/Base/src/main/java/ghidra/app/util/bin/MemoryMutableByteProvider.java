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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.Memory;

import java.io.IOException;

/**
 * A Byte Provider implementation based on Memory.
 */
public class MemoryMutableByteProvider extends MemoryByteProvider implements MutableByteProvider {
	/**
	 * Constructs a new provider for a specific address space.
	 * @param memory the memory
	 */
	public MemoryMutableByteProvider(Memory memory, AddressSpace space) {
		super(memory, space);
	}

	/**
	 * Constructs a new provider relative to the base address.
	 * @param memory the memory
	 * @param baseAddress the relative base address
	 */
	public MemoryMutableByteProvider(Memory memory, Address baseAddress) {
		super(memory, baseAddress);
	}

	@Override
	public void writeByte(long index, byte value) throws IOException {
		try {
			memory.setByte(baseAddress.add(index), value);
		}
		catch (Exception e) {
			throw new IOException(e.getMessage());
		}
	}

	@Override
	public void writeBytes(long index, byte[] values) throws IOException {
		try {
			memory.setBytes(baseAddress.add(index), values);
		}
		catch (Exception e) {
			throw new IOException(e.getMessage());
		}
	}
}
