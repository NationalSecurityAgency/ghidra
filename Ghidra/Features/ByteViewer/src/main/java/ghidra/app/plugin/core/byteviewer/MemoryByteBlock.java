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
package ghidra.app.plugin.core.byteviewer;

import java.math.BigInteger;

import ghidra.app.plugin.core.format.ByteBlock;
import ghidra.app.plugin.core.format.ByteBlockAccessException;
import ghidra.program.database.mem.ByteMappingScheme;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

/**
 * Implementation for the byte block that represents memory in a program.
 */
public class MemoryByteBlock implements ByteBlock {

	private MemoryBlock block;
	private Memory memory;
	private Address start;
	private boolean bigEndian;
	private Address mAddr;
	private Program program;

	/**
	 * Constructor
	 * @param program program used in generating plugin events
	 * @param memory  memory from a program
	 * @param block block from memory
	 */
	MemoryByteBlock(Program program, Memory memory, MemoryBlock block) {
		this.program = program;
		this.memory = memory;
		this.block = block;
		start = block.getStart();
		bigEndian = memory.isBigEndian();
		mAddr = start;
	}

	/**
	 * Get the location representation for the given index.
	 * @param index byte index into this block
	 * @throws IndexOutOfBoundsException if index in not in this block.
	 */
	@Override
	public String getLocationRepresentation(BigInteger index) {
		Address addr = getAddress(index);
		if (!memory.contains(addr)) {
			return null;
		}
		return addr.toString();

	}

	@Override
	public int getMaxLocationRepresentationSize() {
		if (start == null) {
			return 1;
		}
		AddressSpace space = start.getAddressSpace();
		Address address = space.getAddress(1);
		return address.toString(space.showSpaceName(), true).length();
	}

	/**
	 * Return the name to be used for describing the indexes into the
	 * byte block.
	 */
	@Override
	public String getIndexName() {
		return "Addresses";
	}

	/**
	 * Get the number of bytes in this block.
	 */
	@Override
	public BigInteger getLength() {

		long size = block.getSize();
		if (size < 0) {
			return BigInteger.valueOf(size + 0x8000000000000000L).subtract(
				BigInteger.valueOf(0x8000000000000000L));
		}
		return BigInteger.valueOf(size);
	}

	/**
	 * Set the byte at the given index.
	 * @param index byte index
	 * @param value value to set
	 * @throws ByteBlockAccessException if the block cannot be updated
	 * @throws IndexOutOfBoundsException if the given index is not in this
	 * block.
	 */
	@Override
	public void setByte(BigInteger index, byte value) throws ByteBlockAccessException {
		Address addr = getAddress(index);
		checkEditsAllowed(addr, 1);
		try {
			memory.setByte(addr, value);
		}
		catch (MemoryAccessException e) {
			throw new ByteBlockAccessException(e.getMessage());
		}
	}

	/**
	 * Get the byte at the given index.
	 * @param index byte index
	 * @throws ByteBlockAccessException if the block cannot be read
	 * @throws IndexOutOfBoundsException if the given index is not in this
	 * block.
	 */
	@Override
	public byte getByte(BigInteger index) throws ByteBlockAccessException {
		Address addr = getAddress(index);
		try {
			return memory.getByte(addr);
		}
		catch (MemoryAccessException e) {
			throw new ByteBlockAccessException(e.getMessage());
		}
	}

	@Override
	public boolean hasValue(BigInteger index) {
		Address addr = getAddress(index);
		return memory.getAllInitializedAddressSet().contains(addr);
	}

	/**
	 * Set the long at the given index.
	 * @param index byte index
	 * @param value value to set
	 * @throws ByteBlockAccessException if the block cannot be updated
	 * @throws IndexOutOfBoundsException if the given index is not in this
	 * block.
	 */
	@Override
	public void setLong(BigInteger index, long value) throws ByteBlockAccessException {
		Address addr = getAddress(index);
		checkEditsAllowed(addr, 8);
		try {
			memory.setLong(addr, value, bigEndian);
		}
		catch (MemoryAccessException e) {
			throw new ByteBlockAccessException(e.getMessage());
		}
	}

	/**
	 * Get the long at the given index.
	 * @param index byte index
	 * @throws ByteBlockAccessException if the block cannot be read
	 * @throws IndexOutOfBoundsException if the given index is not in this
	 * block.
	 */
	@Override
	public long getLong(BigInteger index) throws ByteBlockAccessException {
		Address addr = getAddress(index);
		try {
			return memory.getLong(addr, bigEndian);
		}
		catch (MemoryAccessException e) {
			throw new ByteBlockAccessException(e.getMessage());
		}
	}

	/**
	 * Set the block according to the bigEndian parameter.
	 * @param bigEndian true means big endian; false means little endian
	 */
	@Override
	public void setBigEndian(boolean bigEndian) {
		this.bigEndian = bigEndian;

	}

	/**
	 * Get the int value at the given index.
	 * @param index byte index
	 * @throws ByteBlockAccessException if the block cannot be read
	 * @throws IndexOutOfBoundsException if the given index is not in this
	 * block.
	 */
	@Override
	public int getInt(BigInteger index) throws ByteBlockAccessException {
		Address addr = getAddress(index);
		try {
			return memory.getInt(addr, bigEndian);
		}
		catch (MemoryAccessException e) {
			throw new ByteBlockAccessException(e.getMessage());
		}
	}

	/**
	 * Set the int at the given index.
	 * @param index byte index
	 * @param value value to set
	 * @throws ByteBlockAccessException if the block cannot be updated
	 * @throws IndexOutOfBoundsException if the given index is not in this
	 * block.
	 */
	@Override
	public void setInt(BigInteger index, int value) throws ByteBlockAccessException {
		Address addr = getAddress(index);
		checkEditsAllowed(addr, 4);
		try {
			memory.setInt(addr, value, bigEndian);
		}
		catch (MemoryAccessException e) {
			throw new ByteBlockAccessException(e.getMessage());
		}
	}

	/**
	 * Return true if this block can be modified.
	 */
	@Override
	public boolean isEditable() {
		return true;
	}

	/**
	 * Return true if the block is big endian.
	 * @return false if the block is little endian
	 */
	@Override
	public boolean isBigEndian() {
		return bigEndian;
	}

	/**
	 * Returns the natural alignment (offset) for the given radix.  If there is
	 * no natural alignment, it should return 0.  A natural alignment only exists if
	 * there is some underlying indexing structure that isn't based at 0.  For example,
	 * if the underlying structure is address based and the starting address is not 0,
	 * then the natural alignment is the address offset mod the radix (if the starting
	 * address is 10 and the radix is 4, then then the alignment is 2)).
	 */
	@Override
	public int getAlignment(int radix) {
		return (int) (start.getOffset() % radix);
	}

	private Address getMappedAddress(Address addr) {
		MemoryBlock memBlock = memory.getBlock(addr);
		if (memBlock != null && memBlock.getType() == MemoryBlockType.BYTE_MAPPED) {
			try {
				MemoryBlockSourceInfo info = memBlock.getSourceInfos().get(0);
				AddressRange mappedRange = info.getMappedRange().get();
				ByteMappingScheme byteMappingScheme = info.getByteMappingScheme().get();
				addr = byteMappingScheme.getMappedSourceAddress(mappedRange.getMinAddress(),
					addr.subtract(memBlock.getStart()));
			}
			catch (AddressOverflowException e) {
				// ignore
			}
		}
		return addr;
	}

	/**
	 * Get the address based on the index.
	 */
	public Address getAddress(BigInteger index) {
		try {
			mAddr = start;
			mAddr = mAddr.addNoWrap(index);
			return mAddr;
		}
		catch (AddressOverflowException e) {
			throw new IndexOutOfBoundsException("Index " + index + " is not in this block");
		}
	}

	/**
	 * Indicates whether some other object is "equal to" this one.
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || getClass() != obj.getClass()) {
			return false;
		}

		MemoryByteBlock mb = (MemoryByteBlock) obj;
		return block == mb.block;
	}

	/////////////////////////////////////////////////////////////////////

	/**
	 * Check for whether edits are allowed at the given address; edits are
	 * not allowed if a code unit (other than undefined data) exists at the
	 * given address.
	 */
	private void checkEditsAllowed(Address addr, long length) throws ByteBlockAccessException {
		if (!editAllowed(addr, length)) {
			String msg = "Instruction exists at address " + addr;
			if (length > 1) {
				Address toAddr = null;
				try {
					toAddr = addr.addNoWrap(length);
				}
				catch (AddressOverflowException e) {
				}
				msg = "Instruction exists in address range " + addr + " to " + toAddr;
			}
			throw new ByteBlockAccessException(msg);
		}
	}

	/**
	 * Return true if undefined data exists at the given address; return
	 * false if code unit exists, thus editing is not allowed.
	 */
	private boolean editAllowed(Address addr, long length) {
		Listing listing = program.getListing();
		Address a = addr;
		for (int i = 0; i < length; i++) {
			try {
				a = a.addNoWrap(i);
			}
			catch (AddressOverflowException e) {
				return false;
			}
			CodeUnit cu = listing.getCodeUnitContaining(a);
			if (cu instanceof Data) {
				continue;
			}
			return false;
		}
		return true;
	}
}
