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

/**
 * MemBuffer provides an array like interface into memory at a
 * specific address.  Bytes can be retrieved by using a positive
 * offset from the current position.  Depending on the implementation,
 * the offset may be restricted to a specific positive range.  If the
 * implementation does have a restriction, then a MemoryAccessException
 * will be thrown, except for the {@link #getBytes(byte[], int)}
 * method which will return 0.
 *
 * The purpose of this class is to
 * allow an efficient implementation that buffers memory accesses and
 * does not have to keep translating addresses.  This was designed to
 * be passed to a language parser.  One advantage of MemBuffer over a
 * byte array is that if necessary the actual Memory and Address can
 * be retrieved in case all of the necessary bytes are not local.
 *
 * This interface does not provide methods to reposition the memory
 * buffer.  This is so that it is clear that methods accepting this
 * base class are not to mess which the base Address for this object.
 *
 * Memory-backed access is an optional implementation dependent
 * capability.  In addition, the use of the relative offset is
 * implementation dependent, but in general those implementations
 * which are backed by memory may choose to wrap the offset
 * when computing the corresponding memory address.  The treatment
 * of the offset argument should be consistent across the various
 * methods for a given implementation.
 *
 * @see ghidra.program.model.mem.MutableMemBuffer
 */
public interface MemBuffer {

	/**
	 * Returns true if this buffer's starting address has valid data.
	 * 
	 * @return boolean true if first byte of memory buffer can be read
	 */
	public default boolean isInitializedMemory() {
		// TODO: possible alternate method of testing
		//return getMemory().getAllInitializedAddressSet().contains(getAddress());
		try {
			getByte(0); // test for uninitialized memory
			return true;
		}
		catch (MemoryAccessException e) {
			// ignore
		}
		return false;
	}

	/**
	 * Get one byte from memory at the current position plus offset.
	 *
	 * @param offset the displacement from the current position.
	 * @return the data at offset from the current position.
	 * @throws MemoryAccessException if memory cannot be read at the specified offset
	 */
	public byte getByte(int offset) throws MemoryAccessException;

	/**
	 * Get one unsigned byte from memory at the current position plus offset.
	 *
	 * @param offset the displacement from the current position.
	 * @return the byte data at offset from the current position, as a {@code int} value.
	 * @throws MemoryAccessException if memory cannot be read at the specified offset
	 */
	default public int getUnsignedByte(int offset) throws MemoryAccessException {
		return getByte(offset) & 0xff;
	}

	/**
	 * Reads <code>b.length</code> bytes from this memory buffer
	 * starting at the address of this memory buffer plus the given memoryBufferOffset
	 * from that position.  The actual number of bytes may be fewer
	 * if bytes can't be read.
	 *
	 * @param b the buffer into which bytes will be placed
	 * @param offset the offset <b>in this memory buffer</b> from which to
	 *        start reading bytes.
	 * @return the number of bytes read which may be fewer than b.length if
	 * available bytes are exhausted or no bytes are available at the specified
	 * offset.
	 */
	public int getBytes(byte[] b, int offset);

	/**
	 * Get the Address which corresponds to the offset 0.
	 *
	 * @return the current address of offset 0.
	 */
	public Address getAddress();

	/**
	 * Get the Memory object actually used by the MemBuffer.
	 *
	 * @return the Memory used by this MemBuffer.
	 */
	public Memory getMemory();

	/**
	 * Returns true if the underlying bytes are in big-endian order, false if they are little endian.
	 * @return true if the underlying bytes are in big-endian order, false if they are little endian.
	 */
	public boolean isBigEndian();

	/**
	 * returns the short at the given offset, taking into account the endianess.
	 * @param offset the offset from the membuffers origin (the address that it is set at)
	 * @return the short at the given offset, taking into account the endianess.
	 * @throws MemoryAccessException if a 2-byte short value cannot be read at the specified offset
	 */
	public short getShort(int offset) throws MemoryAccessException;

	/**
	 * Returns the unsigned short at the given offset, taking into account the endian-ness.
	 * @param offset the offset from the membuffers origin (the address that it is set at)
	 * @return the unsigned short at the given offset, as a {@code int}, taking into account the endianess.
	 * @throws MemoryAccessException if a 2-byte short value cannot be read at the specified offset
	 */
	default public int getUnsignedShort(int offset) throws MemoryAccessException {
		return getShort(offset) & 0xffff;
	}

	/**
	 * returns the int at the given offset, taking into account the endianess.
	 * @param offset the offset from the membuffers origin (the address that it is set at)
	 * @return the int at the given offset, taking into account the endianess.
	 * @throws MemoryAccessException if a 4-byte integer value cannot be read at the specified offset
	 */
	public int getInt(int offset) throws MemoryAccessException;

	/**
	 * Returns the unsigned int at the given offset, taking into account the endianess.
	 * @param offset the offset from the membuffers origin (the address that it is set at)
	 * @return the unsigned int at the given offset, as a {@code long}, taking into account the endianess.
	 * @throws MemoryAccessException if a 4-byte integer value cannot be read at the specified offset
	 */
	default public long getUnsignedInt(int offset) throws MemoryAccessException {
		return getInt(offset) & 0xFFFF_FFFFL;
	}

	/**
	 * returns the long at the given offset, taking into account the endianess.
	 * @param offset the offset from the membuffers origin (the address that it is set at)
	 * @return the long at the given offset, taking into account the endianess.
	 * @throws MemoryAccessException if a 8-byte long value cannot be read at the specified offset
	 */
	public long getLong(int offset) throws MemoryAccessException;

	/**
	 * returns the value at the given offset, taking into account the endianess.
	 * @param offset the offset from the membuffers origin (the address that it is set at)
	 * @param size the number of bytes to include in the value
	 * @param signed true if value should be treated as a signed twos-compliment value.
	 * @return the value at the given offset, taking into account the endianess.
	 * @throws MemoryAccessException if the request size value cannot be read at the specified offset
	 */
	public BigInteger getBigInteger(int offset, int size, boolean signed)
			throws MemoryAccessException;

	/**
	 * Returns the signed value of the integer (of the specified length) at the specified offset.
	 *
	 * @param offset the offset from the membuffers origin (the address that it is set at)
	 * @param len the number of bytes that the integer occupies (ie. 2 bytes == short int, 4
	 * bytes == 32bit int, etc), valid lens are 1, 2 and 4.
	 * @return int integer value
	 * @throws MemoryAccessException
	 */
	default public int getVarLengthInt(int offset, int len) throws MemoryAccessException {
		switch (len) {
			case 1:
				return getByte(offset);
			case 2:
				return getShort(offset);
			case 4:
				return getInt(offset);
			default:
				throw new MemoryAccessException("Invalid length for read: " + len);
		}
	}

	/**
	 * Returns the unsigned value of the integer (of the specified length) at the specified offset.
	 *
	 * @param offset the offset from the membuffers origin (the address that it is set at)
	 * @param len the number of bytes that the integer occupies (ie. 2 bytes == short int, 4
	 * bytes == 32bit int, etc), valid lens are 1, 2 and 4.
	 * @return long integer value
	 * @throws MemoryAccessException
	 */
	default public long getVarLengthUnsignedInt(int offset, int len) throws MemoryAccessException {
		switch (len) {
			case 1:
				return getUnsignedByte(offset);
			case 2:
				return getUnsignedShort(offset);
			case 4:
				return getUnsignedInt(offset);
			default:
				throw new MemoryAccessException("Invalid length for read: " + len);
		}
	}
}
