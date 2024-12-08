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
package ghidra.features.base.memsearch.bytesequence;

import ghidra.features.base.memsearch.bytesource.AddressableByteSource;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;

/**
 * This class provides a {@link ByteSequence} view into an {@link AddressableByteSource}. By 
 * specifying an address and length, this class provides a view into the byte source
 * as a indexable sequence of bytes. It is mutable and can be reused by setting a new
 * address range for this sequence. This was to avoid constantly allocating large byte arrays.
 */
public class AddressableByteSequence implements ByteSequence {

	private final AddressableByteSource byteSource;
	private final byte[] bytes;
	private final int capacity;

	private Address startAddress;
	private int length;

	/**
	 * Constructor
	 * @param byteSource the source of the underlying bytes that is a buffer into
	 * @param capacity the maximum size range that this object will buffer
	 */
	public AddressableByteSequence(AddressableByteSource byteSource, int capacity) {
		this.byteSource = byteSource;
		this.capacity = capacity;
		this.length = 0;
		this.bytes = new byte[capacity];
	}

	/**
	 * Sets this view to an empty byte sequence
	 */
	public void clear() {
		startAddress = null;
		length = 0;
	}

	/**
	 * Sets the range of bytes that this object will buffer. This immediately will read the bytes
	 * from the byte source into it's internal byte array buffer.
	 * @param range the range of bytes to buffer
	 */
	public void setRange(AddressRange range) {
		// Note that this will throw an exception if the range length is larger then Integer.MAX 
		// which is unsupported by the ByteSequence interface
		try {
			setRange(range.getMinAddress(), range.getBigLength().intValueExact());
		}
		catch (ArithmeticException e) {
			throw new IllegalArgumentException("Length exceeds capacity");
		}
	}

	/**
	 * Returns the address of the byte represented by the given index into this buffer.
	 * @param index the index into the buffer to get its associated address
	 * @return the Address for the given index
	 */
	public Address getAddress(int index) {
		if (index < 0 || index >= length) {
			throw new IndexOutOfBoundsException();
		}
		if (index == 0) {
			return startAddress;
		}
		return startAddress.add(index);
	}

	@Override
	public int getLength() {
		return length;
	}

	@Override
	public byte getByte(int index) {
		if (index < 0 || index >= length) {
			throw new IndexOutOfBoundsException();
		}
		return bytes[index];
	}

	@Override
	public byte[] getBytes(int index, int size) {
		if (index < 0 || index + size > length) {
			throw new IndexOutOfBoundsException();
		}
		byte[] results = new byte[size];
		System.arraycopy(bytes, index, results, 0, size);
		return results;
	}

	@Override
	public boolean hasAvailableBytes(int index, int length) {
		return index >= 0 && index + length <= getLength();
	}

	private void setRange(Address start, int length) {
		if (length > capacity) {
			throw new IllegalArgumentException("Length exceeds capacity");
		}
		this.startAddress = start;
		this.length = length;
		byteSource.getBytes(start, bytes, length);
	}

}
