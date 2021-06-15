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
import ghidra.util.GhidraDataConverter;

/**
 * WrappedMemBuffer implements a MemBuffer that provides a zero based index
 * on top of an underlying membuffer with at a given address.  It can buffer N bytes
 * at time using the constructor that takes a cache size.  However the default
 * is to provide no buffering.  Use of the buffer can
 * reduce the overall number of calls to Memory, greatly reducing
 * the overhead of various error checks.  This implementation will not wrap
 * if the end of the memory space is encountered.
 * 
 * The {@link #getByte(int)}, {@link #getBytes(byte[], int)} methods can cause the bytes in the
 * buffer cache if the request is outside of the current cached bytes.
 * 
 * WARNING: The underlying MemBuffer should not change its base address. Using a
 * mutable MemBuffer can cause problematic behavior if not controlled carefully.
 * 
 * WARNING: Not thread-safe.
 */

public class WrappedMemBuffer implements MemBuffer {

	private final GhidraDataConverter converter;

	private final MemBuffer memBuffer;
	private int baseOffset;
	private Address address;

	private static final int DEFAULT_BUFSIZE = 0;  // default no buffer

	private byte[] buffer;
	private int minOffset = 0;
	private int maxOffset = -1;

	/**
	 * Construct a wrapped MemBuffer with an adjustable base offset
	 * @param buf memory buffer
	 * @param baseOffset offset relative to the underlying buffer's start address
	 *               (addr + baseOffset) will be the 0 index into this buffer
	 * @throws AddressOutOfBoundsException
	 */
	public WrappedMemBuffer(MemBuffer buf, int baseOffset) throws AddressOutOfBoundsException {
		this(buf, DEFAULT_BUFSIZE, baseOffset);
	}

	/**
	 * Construct a wrapped MemBuffer with an adjustable base offset
	 * @param buf memory buffer
	 * @param bufferSize size of cache buffer - specify 0 for no buffering
	 * @param baseOffset offset relative to the underlying buffer's start address
	 *               (addr + baseOffset) will be the 0 index into this buffer
	 * @throws AddressOutOfBoundsException
	 */
	public WrappedMemBuffer(MemBuffer buf, int bufferSize, int baseOffset)
			throws AddressOutOfBoundsException {
		this.memBuffer = buf;
		this.converter = GhidraDataConverter.getInstance(buf.isBigEndian());

		buffer = new byte[bufferSize];

		setBaseOffset(baseOffset);
	}

	@Override
	public Address getAddress() {
		return address;
	}

	/**
	 * Set new base offset relative to the associated MemBuffer's address
	 * @param offset new base offset of this buffer
	 * @throws AddressOutOfBoundsException
	 */
	private void setBaseOffset(int offset) throws AddressOutOfBoundsException {
		this.address = memBuffer.getAddress().add(offset);

		this.baseOffset = offset;

		if (buffer.length > 0) {
			minOffset = 0;
			maxOffset = -1;

			maxOffset = memBuffer.getBytes(buffer, baseOffset) - 1;
		}
	}

	/**
	 * Compute offset into original memBuffer, making sure the offset doesn't wrap 
	 * @param offset the offset relative to the baseOffset.
	 * @return the offset relative to the original memBuffer.
	 */
	private int computeOffset(int offset) throws MemoryAccessException {
		int bufOffset = baseOffset + offset;
		if (offset > 0 && bufOffset < baseOffset) {
			throw new MemoryAccessException(
				"Invalid WrappedMemBuffer, offset would wrap underlying memory buffer");
		}
		if (offset < 0 && bufOffset > baseOffset) {
			throw new MemoryAccessException(
				"Invalid WrappedMemBuffer offset, offset would wrap underlying memory buffer");
		}
		return bufOffset;
	}

	@Override
	public byte getByte(int offset) throws MemoryAccessException {
		// no buffering, just get the byte
		if (buffer.length == 0) {
			return memBuffer.getByte(computeOffset(offset));
		}

		// byte found in buffer
		if ((offset >= minOffset) && (offset <= maxOffset)) {
			return buffer[offset - minOffset];
		}

		fillBuffer(offset);

		return buffer[0];
	}

	@Override
	public int getBytes(byte[] b, int offset) {
		try {
			// if there is a buffer, and the number of bytes requested will fit in the buffer
			if (buffer.length > 0 && b.length <= buffer.length) {
				// bytes not in buffer
				if (offset < minOffset || (b.length + offset - 1) > maxOffset) {
					fillBuffer(offset);
				}
				// bytes are contained in the buffer
				if (offset >= minOffset && (b.length + offset - 1) <= maxOffset) {
					System.arraycopy(buffer, offset - minOffset, b, 0, b.length);
					return b.length;
				}
			}

			// grab from wrapped buffer, too many bytes, or no buffer
			return memBuffer.getBytes(b, computeOffset(offset));

		}
		catch (MemoryAccessException e) {
			return 0;
		}
	}

	private void fillBuffer(int offset) throws MemoryAccessException {
		// fill the buffer
		int nRead = memBuffer.getBytes(buffer, computeOffset(offset));

		if (nRead == 0) {
			throw new MemoryAccessException("No bytes available in memory to cache");
		}

		minOffset = offset;
		maxOffset = offset + nRead - 1;
	}

	@Override
	public Memory getMemory() {
		return memBuffer.getMemory();
	}

	@Override
	public boolean isBigEndian() {
		return memBuffer.isBigEndian();
	}

	@Override
	public short getShort(int offset) throws MemoryAccessException {
		return converter.getShort(this, offset);
	}

	@Override
	public int getInt(int offset) throws MemoryAccessException {
		return converter.getInt(this, offset);
	}

	@Override
	public long getLong(int offset) throws MemoryAccessException {
		return converter.getLong(this, offset);
	}

	@Override
	public BigInteger getBigInteger(int offset, int size, boolean signed)
			throws MemoryAccessException {
		return converter.getBigInteger(this, offset, size, signed);
	}
}
