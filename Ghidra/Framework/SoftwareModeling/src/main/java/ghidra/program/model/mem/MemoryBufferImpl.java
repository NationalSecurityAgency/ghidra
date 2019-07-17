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

import ghidra.program.model.address.*;
import ghidra.util.GhidraBigEndianDataConverter;
import ghidra.util.GhidraLittleEndianDataConverter;

import java.math.BigInteger;

/**
 * MemBufferImpl implements the MemBuffer interface.  It buffers up N bytes
 * at time, reducing the overall number of calls to Memory, greatly reducing
 * the overhead of various error checks.  This implementation will not wrap
 * if the end of the memory space is encountered.
 * 
 * The {@link #getByte(int)} method can cause the buffer cache to adjust if
 * outside the current cache range.  This is not the case for other methods which 
 * will simply defer to the underlying memory if outside the cache range.
 */

public class MemoryBufferImpl implements MutableMemBuffer {

	private static final int DEFAULT_BUFSIZE = 1024;
	private static final int THRESH = 8;

	private Memory mem;
	private Address startAddr;
	private byte[] buffer;
	private int startAddrIndex = 0;
	private int minOffset = 0;
	private int maxOffset = -1;

	/**
	 * Construct a new MemoryBufferImpl
	 * @param mem memory associated with the given address
	 * @param addr start address
	 */
	public MemoryBufferImpl(Memory mem, Address addr) {
		this(mem, addr, DEFAULT_BUFSIZE);
	}

	/**
	 * Construct a new MemoryBufferImpl
	 * @param mem memory associated with the given address
	 * @param addr start address
	 * @param bufSize the size of the memory buffer.
	 */
	public MemoryBufferImpl(Memory mem, Address addr, int bufSize) {
		this.mem = mem;
		buffer = new byte[bufSize];
		setPosition(addr);
	}

	@Override
	public MemoryBufferImpl clone() {
		return new MemoryBufferImpl(mem, startAddr, buffer.length);
	}

	@Override
	public void advance(int displacement) throws AddressOverflowException {
		Address addr = startAddr.addNoWrap(displacement);
		setPosition(addr);
	}

	@Override
	public void setPosition(Address addr) {
		if (minOffset <= maxOffset) {
			if (addr.getAddressSpace().equals(startAddr.getAddressSpace())) {
				long diff = addr.subtract(startAddr);
				if (diff >= minOffset && diff < maxOffset - THRESH) {
					startAddr = addr;
					minOffset -= (int) diff;
					maxOffset -= (int) diff;
					startAddrIndex += diff;
					return;
				}
			}
		}
		startAddr = addr;
		startAddrIndex = 0;
		minOffset = 0;
		maxOffset = -1;

		try {
			maxOffset = mem.getBytes(addr, buffer, 0, buffer.length) - 1;
		}
		catch (AddressOutOfBoundsException | MemoryAccessException e) {
			// handled by maxOffset == -1
		}
	}

	@Override
	public byte getByte(int offset) throws MemoryAccessException {
		if ((offset >= minOffset) && (offset <= maxOffset)) {
			return buffer[startAddrIndex + offset];
		}
		try {
			Address addr = startAddr.addNoWrap(offset);

			int nRead = mem.getBytes(addr, buffer, 0, buffer.length);

			startAddrIndex = -offset;
			minOffset = offset;
			maxOffset = offset + nRead - 1;

			return buffer[0];
		}
		catch (AddressOverflowException e) {
			throw new MemoryAccessException(e.getMessage());
		}
	}

	@Override
	public Address getAddress() {
		return startAddr;
	}

	@Override
	public Memory getMemory() {
		return mem;
	}

	@Override
	public int getBytes(byte[] b, int offset) {
		if (offset >= minOffset && (b.length + offset) <= maxOffset) {
			System.arraycopy(buffer, startAddrIndex + offset, b, 0, b.length);
			return b.length;
		}
		try {
			return mem.getBytes(startAddr.addNoWrap(offset), b);
		}
		catch (AddressOverflowException | MemoryAccessException e) {
			return 0;
		}
	}

	@Override
	public boolean isBigEndian() {
		return mem.isBigEndian();
	}

	@Override
	public short getShort(int offset) throws MemoryAccessException {
		if (mem.isBigEndian()) {
			return GhidraBigEndianDataConverter.INSTANCE.getShort(this, offset);
		}
		return GhidraLittleEndianDataConverter.INSTANCE.getShort(this, offset);
	}

	@Override
	public int getInt(int offset) throws MemoryAccessException {
		if (mem.isBigEndian()) {
			return GhidraBigEndianDataConverter.INSTANCE.getInt(this, offset);
		}
		return GhidraLittleEndianDataConverter.INSTANCE.getInt(this, offset);
	}

	@Override
	public long getLong(int offset) throws MemoryAccessException {
		if (mem.isBigEndian()) {
			return GhidraBigEndianDataConverter.INSTANCE.getLong(this, offset);
		}
		return GhidraLittleEndianDataConverter.INSTANCE.getLong(this, offset);
	}

	@Override
	public BigInteger getBigInteger(int offset, int size, boolean signed)
			throws MemoryAccessException {
		if (mem.isBigEndian()) {
			return GhidraBigEndianDataConverter.INSTANCE.getBigInteger(this, offset, size, signed);
		}
		return GhidraLittleEndianDataConverter.INSTANCE.getBigInteger(this, offset, size, signed);
	}

}
