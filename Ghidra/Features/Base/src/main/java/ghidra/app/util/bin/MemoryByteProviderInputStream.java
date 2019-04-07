/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
import ghidra.program.model.mem.Memory;

import java.io.IOException;
import java.io.InputStream;

class MemoryByteProviderInputStream extends InputStream {
	private Memory memory;
	private Address startAddress;
	private Address address;

	MemoryByteProviderInputStream(Memory memory, Address address) {
		this.memory = memory;
		this.startAddress = address;
		this.address = address;
	}

	@Override
	public int read() throws IOException {
		try {
			byte b = memory.getByte(address);
			address = address.add(1);
			return b & 0xff;
		}
		catch (Exception e) {
			throw new IOException(e.getMessage());
		}
	}

	@Override
	public int read(byte [] b, int off, int len) throws IOException {
		try {
			int nRead = memory.getBytes(address, b, off, len);
			address = address.add(len);
			return nRead;
		}
		catch (Exception e) {
			throw new IOException(e.getMessage());
		}
	}

	@Override
	public int available() throws IOException {
		return (int)memory.getMaxAddress().subtract(address);
	}

	@Override
	public synchronized void reset() throws IOException {
		address = startAddress;
	}

	@Override
	public void close() throws IOException {
		super.close();
		memory = null;
		address = null;
	}
}
