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
package ghidra.program.model.mem;

import java.math.BigInteger;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;

public class WrappedMemBuffer implements MemBuffer {

	private final MemBuffer memBuffer;
	private int baseOffset;
	private Address address;

	/**
	 * Construct a wrapped MemBuffer with an adjustable base offset
	 * @param buf memory buffer
	 * @param offset base offset for this buffer relative to buf's address
	 * @throws AddressOutOfBoundsException
	 */
	public WrappedMemBuffer(MemBuffer buf, int offset) throws AddressOutOfBoundsException {
		this.memBuffer = buf;
		setBaseOffset(offset);
	}

	/**
	 * Set new base offset relative to the associated MemBuffer's address
	 * @param offset new base offset of this buffer
	 * @throws AddressOutOfBoundsException
	 */
	public void setBaseOffset(int offset) throws AddressOutOfBoundsException {
		this.baseOffset = offset;
		this.address = memBuffer.getAddress().add(baseOffset);
	}

	@Override
	public Address getAddress() {
		return address;
	}

	/**
	 * Compute offset into original memBuffer, making sure the offset doesn't wrap 
	 * @param offset the offset relative to the baseOffset.
	 * @return the offset relative to the original memBuffer.
	 */
	private int computeOffset(int offset) throws MemoryAccessException {
		int bufOffset = baseOffset + offset;
		if (offset > 0 && bufOffset < baseOffset) {
			throw new MemoryAccessException();
		}
		if (offset < 0 && bufOffset > baseOffset) {
			throw new MemoryAccessException();
		}
		return bufOffset;
	}

	@Override
	public byte getByte(int offset) throws MemoryAccessException {
		return memBuffer.getByte(computeOffset(offset));
	}

	@Override
	public int getBytes(byte[] b, int offset) {
		try {
			return memBuffer.getBytes(b, computeOffset(offset));
		}
		catch (MemoryAccessException e) {
			return 0;
		}
	}

	@Override
	public int getInt(int offset) throws MemoryAccessException {
		return memBuffer.getInt(computeOffset(offset));
	}

	@Override
	public long getLong(int offset) throws MemoryAccessException {
		return memBuffer.getLong(computeOffset(offset));
	}

	@Override
	public BigInteger getBigInteger(int offset, int size, boolean signed)
			throws MemoryAccessException {
		return memBuffer.getBigInteger(computeOffset(offset), size, signed);
	}

	@Override
	public Memory getMemory() {
		return memBuffer.getMemory();
	}

	@Override
	public short getShort(int offset) throws MemoryAccessException {
		return memBuffer.getShort(computeOffset(offset));
	}

	@Override
	public boolean isBigEndian() {
		return memBuffer.isBigEndian();
	}
}
