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
package ghidra.pcode.emulate;

import ghidra.pcode.memstate.MemoryState;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.*;

import java.math.BigInteger;

/**
 * <code>MemoryStateBuffer</code> provides a MemBuffer for instruction parsing use
 * which wraps an emulator MemoryState.  This implementation wraps all specified 
 * memory offsets within the associated address space.
 */
public class EmulateMemoryStateBuffer implements MemBuffer {

	private final MemoryState memState;
	private Address address;

	public EmulateMemoryStateBuffer(MemoryState memState, Address addr) {
		this.memState = memState;
		setAddress(addr);
	}

	public void setAddress(Address addr) {
		address = addr;
	}

	@Override
	public Address getAddress() {
		return address;
	}

	private long availableInSpace(Address startAddr) {
		return address.getAddressSpace().getMaxAddress().subtract(startAddr) + 1;
	}

	private Address getWrappedAddress(int offset) {
		return address.addWrap(offset);
	}

	/**
	 * Determine if request is valid and compute wrapped memory offset relative to 
	 * current buffer address.  A request is invalid if too close to the end of the 
	 * memory space to read the requested number of bytes.
	 * @param offset relative offset
	 * @param size read request size
	 * @return absolute memory offset (wrapped)
	 * @throws MemoryAccessException
	 */
	private long checkGetRequest(int offset, int size) throws MemoryAccessException {
		Address offsetAddr = getWrappedAddress(offset);
		long available = availableInSpace(offsetAddr);
		if (available > 0 && available < size) {
			throw new MemoryAccessException();
		}
		return offsetAddr.getOffset();
	}

	@Override
	public BigInteger getBigInteger(int offset, int size, boolean signed)
			throws MemoryAccessException {
		long memOffset = checkGetRequest(offset, size);
		return memState.getBigInteger(address.getAddressSpace(), memOffset, size, signed);
	}

	@Override
	public int getBytes(byte[] b, int offset) {
		Address offsetAddr = getWrappedAddress(offset);
		return memState.getChunk(b, address.getAddressSpace(), offsetAddr.getOffset(), b.length,
			true);
	}

	@Override
	public byte getByte(int offset) throws MemoryAccessException {
		long memOffset = checkGetRequest(offset, 1);
		return (byte) memState.getValue(address.getAddressSpace(), memOffset, 1);
	}

	@Override
	public short getShort(int offset) throws MemoryAccessException {
		long memOffset = checkGetRequest(offset, 2);
		return (short) memState.getValue(address.getAddressSpace(), memOffset, 2);
	}

	@Override
	public int getInt(int offset) throws MemoryAccessException {
		long memOffset = checkGetRequest(offset, 4);
		return (int) memState.getValue(address.getAddressSpace(), memOffset, 4);
	}

	@Override
	public long getLong(int offset) throws MemoryAccessException {
		long memOffset = checkGetRequest(offset, 8);
		return memState.getValue(address.getAddressSpace(), memOffset, 8);
	}

	@Override
	public Memory getMemory() {
		// Make sure Sleigh language provider does not call this method
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isBigEndian() {
		return memState.getMemoryBank(address.getAddressSpace()).isBigEndian();
	}

}
