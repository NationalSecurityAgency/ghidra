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

import java.io.*;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

/**
 * A {@link ByteProvider} implementation based on {@link Memory}.
 * <p>
 * The bytes returned by this provider are indexed relative to the {@code baseAddress}
 * supplied to the constructor, and are limited to {@link MemoryBlock memory blocks} of the
 * same address space.
 * <p>
 * <b>Warnings:</b>
 * <p>
 * Using this ByteProvider with memory block/address spaces that are not simple "ram" initialized 
 * memory blocks is fraught with peril.
 * <p>
 * Addresses and address spaces can use all 64 bits of a {@code long} as an offset, which 
 * causes a problem when trying to express the correct {@link #length()} of this ByteProvider as
 * a long. (this is why address ranges deal with inclusive end values instead of exclusive).
 * <ul>
 * 	<li>The return value of {@link #length()} is constrained to a max of Long.MAX_VALUE</li>
 * 	<li>{@link #isValidIndex(long)} treats its argument as an unsigned int64, and works
 * 	for the entire address space range.</li>
 * </ul>
 * <p>
 * Not all byte provider index locations between 0 and {@link #length()} will be valid
 * (because gaps between memory blocks), and may generate exceptions when those locations are read.
 * <ul>
 *  <li>To avoid this situation, the caller will need to use information from the program's Memory
 *  manager to align reads to valid locations.</li>
 * </ul>
 */
public class MemoryByteProvider implements ByteProvider {

	/**
	 * Create a {@link ByteProvider} that is limited to the specified {@link MemoryBlock}.
	 * 
	 * @param memory {@link Memory} of the program
	 * @param block {@link MemoryBlock} to read from
	 * @return new {@link ByteProvider} that contains the bytes of the specified MemoryBlock
	 */
	public static MemoryByteProvider createMemoryBlockByteProvider(Memory memory,
			MemoryBlock block) {
		return new MemoryByteProvider(memory, block.getStart(), block.getEnd());
	}

	/**
	 * Create a {@link ByteProvider} that starts at the beginning of the specified 
	 * {@link Program program's} memory, containing either just the first 
	 * memory block, or all memory blocks (of the same address space).
	 * 
	 * @param program {@link Program} to read
	 * @param firstBlockOnly boolean flag, if true, only the first memory block will be accessible
	 * via the returned provider, if false, all memory blocks of the address space will be accessible
	 * @return new {@link MemoryByteProvider}, starting at program's minAddress
	 */
	public static MemoryByteProvider createProgramHeaderByteProvider(Program program,
			boolean firstBlockOnly) {
		return new MemoryByteProvider(program.getMemory(), program.getMinAddress(), firstBlockOnly);
	}

	/**
	 * Create a {@link ByteProvider} that starts at the beginning (e.g. 0) of the specified 
	 * {@link Program program's} default address space memory, containing either the first memory 
	 * block, or all memory blocks (of the same address space).
	 * 
	 * @param program {@link Program} to read
	 * @param firstBlockOnly boolean flag, if true, only the first memory block will be accessible
	 * via the returned provider, if false, all memory blocks of the address space will be accessible
	 * @return new {@link MemoryByteProvider}, starting at program's minAddress
	 */
	public static MemoryByteProvider createDefaultAddressSpaceByteProvider(Program program,
			boolean firstBlockOnly) {
		return new MemoryByteProvider(program.getMemory(),
			program.getAddressFactory().getDefaultAddressSpace().getMinAddress(), firstBlockOnly);
	}

	protected Memory memory;
	protected Address baseAddress;
	protected long maxOffset; // max valid offset, inclusive
	protected boolean isEmtpy; // empty is tracked separately because maxOffset == 0 does not mean empty

	/**
	 * Constructs a new {@link MemoryByteProvider} for a specific {@link AddressSpace}.  Bytes 
	 * will be provided relative to the minimum address (typically 0) in the space, and ranges 
	 * to the highest address in the same address space currently found in the memory map.
	 * <p>
	 * 
	 * 
	 * @param memory the {@link Memory}
	 * @param space the {@link AddressSpace}
	 */
	public MemoryByteProvider(Memory memory, AddressSpace space) {
		this(memory, space.getMinAddress());
	}

	/**
	 * Constructs a new {@link MemoryByteProvider} relative to the specified base address,
	 * containing the address range to the highest address in the same address space currently
	 * found in the memory map.
	 * 
	 * @param memory the {@link Memory}
	 * @param baseAddress the base address
	 */
	public MemoryByteProvider(Memory memory, Address baseAddress) {
		this(memory, baseAddress, false);
	}

	/**
	 * Constructs a new {@link MemoryByteProvider} relative to the specified base address,
	 * containing the address range to the end of the first memory block, or the highest address
	 * in the same address space, currently found in the memory map.
	 * 
	 * @param memory the {@link Memory}
	 * @param baseAddress the base address
	 * @param firstBlockOnly boolean flag, if true, only the first memory block will be accessible,
	 * if false, all memory blocks of the address space will be accessible
	 */
	public MemoryByteProvider(Memory memory, Address baseAddress, boolean firstBlockOnly) {
		this(memory, baseAddress, firstBlockOnly
				? findEndOfBlock(memory, baseAddress)
				: findAddressSpaceMax(memory, baseAddress));
	}

	/**
	 * Constructs a new {@link MemoryByteProvider} relative to the specified base address, with
	 * the specified length.
	 * 
	 * @param memory the {@link Memory}
	 * @param baseAddress the base address
	 * @param maxAddress the highest address accessible by this provider (inclusive), or null
	 * if there is no memory
	 */
	public MemoryByteProvider(Memory memory, Address baseAddress, Address maxAddress) {
		this.memory = memory;
		this.baseAddress = baseAddress;
		this.maxOffset = maxAddress != null
				? maxAddress.subtract(baseAddress)
				: 0;
		this.isEmtpy = maxAddress == null;
	}

	private Address getAddress(long index) throws IOException {
		if (index == 0) {
			return baseAddress;
		}
		long base = baseAddress.getOffset();
		long newAddress = base + index;
		if (Long.compareUnsigned(base, newAddress) > 0) {
			throw new IOException("Invalid index: %s".formatted(Long.toUnsignedString(index)));
		}
		return baseAddress.getNewAddress(newAddress);
	}

	/**
	 * Returns the address of the first byte of this provider.
	 *   
	 * @return address of the first byte returned by this provider (at index 0)
	 */
	public Address getStartAddress() {
		return baseAddress;
	}

	/**
	 * Returns the address of the last byte of this provider.
	 * 
	 * @return address of the last byte returned by this provider
	 */
	public Address getEndAddress() {
		return baseAddress.getNewAddress(baseAddress.getOffset() + maxOffset);
	}

	/**
	 * Returns the address range of the bytes of this provider.
	 * 
	 * @return address range of first byte to last byte of this provider
	 */
	public AddressSetView getAddressSet() {
		return new AddressSet(baseAddress, getEndAddress());
	}

	@Override
	public boolean isEmpty() {
		return isEmtpy;
	}

	@Override
	public File getFile() {
		return new File(memory.getProgram().getExecutablePath());
	}

	@Override
	public String getName() {
		return memory.getProgram().getName();
	}

	@Override
	public String getAbsolutePath() {
		return memory.getProgram().getExecutablePath();
	}

	@Override
	public long length() throws IOException {
		if (isEmtpy) {
			return 0;
		}

		// clamp the max length to Long.MAX_VALUE
		return Long.compareUnsigned(maxOffset, Long.MAX_VALUE - 1) >= 0
				? Long.MAX_VALUE
				: maxOffset + 1;
	}

	@Override
	public boolean isValidIndex(long index) {
		// this method treats the index as an unsigned int64, and will give accurate results
		// for the entire range of the underlying AddressSpace
		try {
			if (isEmtpy || Long.compareUnsigned(index, maxOffset) > 0) {
				return false;
			}
			return memory.contains(getAddress(index));
		}
		catch (IOException | AddressOutOfBoundsException e) {
			return false;
		}
	}

	@Override
	public byte readByte(long index) throws IOException {
		ensureBounds(index, 1);
		try {
			return memory.getByte(getAddress(index));
		}
		catch (Exception e) {
			throw new IOException(e.getMessage());
		}
	}

	@Override
	public byte[] readBytes(long index, long length) throws IOException {
		ensureBounds(index, length);
		try {
			byte[] bytes = new byte[(int) length];
			int nRead = memory.getBytes(getAddress(index), bytes);
			if (nRead != length) {
				throw new IOException("Unable to read %d bytes at index %s".formatted(length,
					Long.toUnsignedString(index)));
			}
			return bytes;
		}
		catch (IOException e) {
			throw e;
		}
		catch (Exception e) {
			throw new IOException(e.getMessage());
		}
	}

	@Override
	public void close() {
		// don't do anything for now
	}

	//--------------------------------------------------------------------------------------------
	private void ensureBounds(long index, long length) throws IOException {
		// ensure length is valid
		if (length < 0 || length > Integer.MAX_VALUE) {
			throw new IOException(
				"Unable to read more than Integer.MAX_VALUE bytes in one operation: %s"
						.formatted(Long.toUnsignedString(length)));
		}
		if (index == 0 && length == 0) {
			return;	// success for read of 0 bytes at offset 0
		}

		// ensure read start index is valid
		if (isEmtpy || Long.compareUnsigned(index, maxOffset) > 0) {
			throw new EOFException("Invalid index: %s".formatted(Long.toUnsignedString(index)));
		}

		// NOTE: there should be a +1 on "remaining" to accurately model the count of remaining bytes
		// Because it could cause an overflow, adjust "length" by -1 instead 
		long remaining = maxOffset - index /* + 1 -> becomes length - 1 */;

		// ensure length of read is within bounds
		if (length != 0 && Long.compareUnsigned(length - 1, remaining) > 0) {
			throw new EOFException(
				"Unable to read past EOF: %s, %d".formatted(Long.toUnsignedString(index), length));
		}
	}

	private static Address findEndOfBlock(Memory memory, Address minAddr) {
		MemoryBlock block = memory.getBlock(minAddr);
		if (block != null) {
			// address was inside a block, return it's end
			return block.getEnd();
		}

		// address was outside all blocks.  try to find a block that contains it and return its end
		AddressSpace space = minAddr.getAddressSpace();
		for (MemoryBlock block2 : memory.getBlocks()) {
			Address end = block2.getEnd();
			if (end.getAddressSpace().equals(space) && end.compareTo(minAddr) >= 0) {
				return end;
			}
		}
		return null;
	}

	private static Address findAddressSpaceMax(Memory memory, Address minAddr) {
		if (minAddr == null) {
			return null;
		}
		AddressSpace space = minAddr.getAddressSpace();
		Address maxAddr = null;
		for (AddressRange range : memory.getAddressRanges()) {
			if (!range.getAddressSpace().equals(space)) {
				continue;
			}
			Address rangeEnd = range.getMaxAddress();
			if (rangeEnd.compareTo(minAddr) >= 0 &&
				(maxAddr == null || rangeEnd.compareTo(maxAddr) >= 0)) {
				maxAddr = rangeEnd;
			}
		}
		return maxAddr;
	}

}
