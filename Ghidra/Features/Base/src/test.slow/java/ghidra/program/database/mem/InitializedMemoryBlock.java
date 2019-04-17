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
package ghidra.program.database.mem;

import java.io.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.mem.*;

/**
 * Default implementation for a MemoryBlock containing initialized data.
 */
class InitializedMemoryBlock implements MemoryBlock {

	private final static long serialVersionUID = 1;

	private String name;
	protected byte[] data;
	private Address start;
	private Address end;
	private String comment;
	private String sourceName;
	private int permissions = READ | WRITE;
	private long sourceOffset;

	/**
	 * Constructor for InitializedMemoryBlock.
	 * @param name name of the block
	 * @param start starting address of the block
	 * @param data bytes that make up the block
	 * @throws AddressOverflowException if the block size extends beyond the end
	 * of the address space
	 */
	InitializedMemoryBlock(String name, Address start, byte[] data)
			throws AddressOverflowException {

		if ((data == null) || (data.length == 0)) {
			throw new IllegalArgumentException("Missing or zero length data byte array");
		}
		this.name = name;
		this.start = start;
		this.data = data;
		end = start.addNoWrap(data.length - 1);
	}

	/**
	 * @see MemoryBlock#contains(Address)
	 */
	@Override
	public boolean contains(Address addr) {
		try {
			long diff = addr.subtract(start);
			return diff >= 0 && diff < data.length;

		}
		catch (IllegalArgumentException e) {
		}

		return false;
	}

	/**
	 * @see MemoryBlock#getStart()
	 */
	@Override
	public Address getStart() {
		return start;
	}

	/**
	 * @see MemoryBlock#getEnd()
	 */
	@Override
	public Address getEnd() {
		return end;
	}

	/**
	 * @see MemoryBlock#getSize()
	 */
	@Override
	public long getSize() {
		return data.length;
	}

	/**
	 * @see MemoryBlock#getName()
	 */
	@Override
	public String getName() {
		return name;
	}

	/**
	 * @see MemoryBlock#setName(String)
	 */
	@Override
	public void setName(String name) {
		this.name = name;
	}

	/**
	 * @see MemoryBlock#getComment()
	 */
	@Override
	public String getComment() {
		return comment;
	}

	/**
	 * @see MemoryBlock#setComment(String)
	 */
	@Override
	public void setComment(String comment) {
		this.comment = comment;
	}

	/**
	 * @see MemoryBlock#getSourceName()
	 */
	@Override
	public String getSourceName() {
		return sourceName;
	}

	/**
	 * @see MemoryBlock#setSourceName(String)
	 */
	@Override
	public void setSourceName(String sourceName) {
		this.sourceName = sourceName;
	}

	/**
	 * @see MemoryBlock#getByte(Address)
	 */
	@Override
	public byte getByte(Address addr) throws MemoryAccessException {
		int index = getIndex(addr);
		return data[index];
	}

	/**
	 * @see MemoryBlock#getBytes(Address, byte[])
	 */
	@Override
	public int getBytes(Address addr, byte[] b) throws MemoryAccessException {
		int index = getIndex(addr);
		int len = b.length;
		if (index + len > data.length) {
			len = data.length - index;
		}

		System.arraycopy(data, index, b, 0, len);
		return len;
	}

	/**
	 * @see MemoryBlock#getBytes(Address, byte[], int, int)
	 */
	@Override
	public int getBytes(Address addr, byte[] b, int off, int len) throws MemoryAccessException {
		int index = getIndex(addr);
		int length = len;
		if (index + length > data.length) {
			length = data.length - index;
		}
		System.arraycopy(data, index, b, off, length);
		return length;
	}

	/**
	 * @see MemoryBlock#putByte(Address, byte)
	 */
	@Override
	public void putByte(Address addr, byte b) throws MemoryAccessException {
		changeData(addr, new byte[] { b });
	}

	/**
	 * @see MemoryBlock#putBytes(Address, byte[])
	 */
	@Override
	public int putBytes(Address addr, byte[] b) throws MemoryAccessException {
		return changeData(addr, b);
	}

	/**
	 * @see MemoryBlock#putBytes(Address, byte[], int, int)
	 */
	@Override
	public int putBytes(Address addr, byte[] b, int off, int len) throws MemoryAccessException {
		int index = getIndex(addr);
		int length = len;
		if (index + length > data.length) {
			length = data.length - index;
		}

		byte[] oldValue = new byte[length];
		System.arraycopy(data, index, oldValue, 0, oldValue.length);

		byte[] newValue = new byte[length];
		System.arraycopy(b, off, newValue, 0, length);

		System.arraycopy(b, off, data, index, length);

		return length;
	}

	/**
	 * Compare the start address of this block to obj's start address if
	 * obj is a MemoryBlock.
	 * @see java.lang.Comparable#compareTo(Object)
	 */
	@Override
	public int compareTo(MemoryBlock block) {
		return start.compareTo(block.getStart());
	}

	MemoryBlock create(String lName, Address lStart, int offset, int length)
			throws AddressOverflowException {

		byte[] b = copyData(offset, length);
		InitializedMemoryBlock block = new InitializedMemoryBlock(lName, lStart, b);
		copyProperties(block);
		block.sourceOffset += offset;
		return block;
	}

	/**
	 * Append the given block to this block.
	 */
	MemoryBlock append(MemoryBlock block) throws AddressOverflowException, MemoryBlockException {

		if (!(block instanceof InitializedMemoryBlock)) {
			throw new MemoryBlockException("Cannot append: Block is not a InitializedMemoryBlock");
		}
		InitializedMemoryBlock imb = (InitializedMemoryBlock) block;
		byte[] b = combineData(imb);

		InitializedMemoryBlock newblock = new InitializedMemoryBlock(name, start, b);
		copyProperties(newblock);
		return newblock;
	}

	/**
	 * Copy properties from this block to the given block.
	 */
	private void copyProperties(InitializedMemoryBlock block) {
		block.permissions = permissions;
		block.comment = comment;
		block.sourceName = sourceName;
		block.sourceOffset = sourceOffset;
	}

	/**
	 * Get the index into this block for the given address.
	 * @throws IllegalArgumentException if the the address is not in this
	 * block.
	 */
	private int getIndex(Address addr) {
		long diff = addr.subtract(start);
		if (diff < 0 || diff >= data.length) {
			throw new IllegalArgumentException("Address " + addr + " is not in this block");
		}
		return (int) diff;
	}

	/**
	 * Change the data and notify the listeners.
	 * @param addr address of where to do the change
	 * @param newValue new byte values
	 * @return number of bytes that changed
	 */
	private int changeData(Address addr, byte[] newValue) {
		int index = getIndex(addr);

		int len = newValue.length;
		if (index + len > data.length) {
			len = data.length - index;
		}

		byte[] oldValue = new byte[len];
		System.arraycopy(data, index, oldValue, 0, oldValue.length);

		System.arraycopy(newValue, 0, data, index, len);
		return len;
	}

	private byte[] copyData(int offset, int length) {
		if (data.length == 0) {
			return new byte[0];
		}
		int nbytes = Math.min(data.length, length);
		byte[] b = new byte[length];
		System.arraycopy(data, offset, b, 0, nbytes);
		return b;
	}

	private byte[] combineData(InitializedMemoryBlock block) {
		if (data.length == 0 && block.data.length == 0) {
			return new byte[0];
		}

		int newdataSize = data.length + block.data.length;

		byte[] b = new byte[newdataSize];

		System.arraycopy(data, 0, b, 0, data.length);
		System.arraycopy(block.data, 0, b, data.length, block.data.length);
		return b;
	}

	private void readObject(ObjectInputStream ois) throws ClassNotFoundException, IOException {
		ois.defaultReadObject();
	}

	@Override
	public boolean isVolatile() {
		return (permissions & VOLATILE) != 0;
	}

	@Override
	public boolean isExecute() {
		return (permissions & EXECUTE) != 0;
	}

	@Override
	public boolean isRead() {
		return (permissions & READ) != 0;
	}

	@Override
	public boolean isWrite() {
		return (permissions & WRITE) != 0;
	}

	@Override
	public void setVolatile(boolean v) {
		if (v) {
			permissions |= VOLATILE;
		}
		else {
			permissions &= ~VOLATILE;
		}
	}

	@Override
	public void setExecute(boolean e) {
		if (e) {
			permissions |= EXECUTE;
		}
		else {
			permissions &= ~EXECUTE;
		}
	}

	@Override
	public void setRead(boolean r) {
		if (r) {
			permissions |= READ;
		}
		else {
			permissions &= ~READ;
		}
	}

	@Override
	public void setWrite(boolean w) {
		if (w) {
			permissions |= WRITE;
		}
		else {
			permissions &= ~WRITE;
		}
	}

	@Override
	public MemoryBlockType getType() {
		if (start.getAddressSpace().isOverlaySpace()) {
			return MemoryBlockType.OVERLAY;
		}
		return MemoryBlockType.DEFAULT;
	}

	@Override
	public InputStream getData() {
		return new ByteArrayInputStream(data);
	}

	@Override
	public int getPermissions() {
		return permissions;
	}

	@Override
	public boolean isInitialized() {
		return true;
	}

	@Override
	public boolean isMapped() {
		return false;
	}

	@Override
	public boolean isLoaded() {
		return start.getAddressSpace().isLoadedMemorySpace();
	}
}
