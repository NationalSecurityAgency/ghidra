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

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.framework.store.LockException;
import ghidra.program.database.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

/**
 * Interface for Memory.
 */
public interface Memory extends AddressSetView {

	static final int GBYTE_SHIFT_FACTOR = 30;
	static long GBYTE = 1L << GBYTE_SHIFT_FACTOR;

	/**
	 * Maximum size of all memory blocks, 16-GByte (see {@link #getAllInitializedAddressSet()}).
	 * This restriction is somewhat arbitrary but is established to prevent an excessive
	 * number of memory map segments which can have a negative impact on performance.
	 */
	public static final int MAX_BINARY_SIZE_GB = 16;
	public static final long MAX_BINARY_SIZE = (long) MAX_BINARY_SIZE_GB << GBYTE_SHIFT_FACTOR;

	/**
	 * The current max size of a memory block. 
	 */
	public static final int MAX_BLOCK_SIZE_GB = 16;  // set to 16 because anything larger, ghidra bogs down
	public static final long MAX_BLOCK_SIZE = (long) MAX_BLOCK_SIZE_GB << GBYTE_SHIFT_FACTOR;

	/**
	 * Returns the program that this memory belongs to.
	 */
	public Program getProgram();

	/**
	 * Returns the set of addresses which correspond to all the "loaded" memory blocks that have
	 * initialized data.  This does not include initialized memory blocks that contain data from
	 * the program's file header such as debug sections.
	 */
	public AddressSetView getLoadedAndInitializedAddressSet();

	/**
	 * Returns the set of addresses which correspond to all memory blocks that have
	 * initialized data.  This includes initialized memory blocks that contain data from
	 * the program's file header that are not actually in the running in memory image,
	 * such as debug sections.  Use {@link #getLoadedAndInitializedAddressSet} if you only want
	 * the addressed of the loaded in memory blocks.
	 */
	public AddressSetView getAllInitializedAddressSet();

	/**
	 * Use {@link #getLoadedAndInitializedAddressSet} instead.
	 * @deprecated
	 */
	@Deprecated
	public AddressSetView getInitializedAddressSet();

	/**
	 * Returns the set of addresses which correspond to the executable memory.
	 */
	public AddressSetView getExecuteSet();

	/**
	 * Returns true if the memory is bigEndian, false otherwise.
	 */
	public boolean isBigEndian();

	/**
	 * Sets the live memory handler
	 * @param handler the live memory handler
	 */
	public void setLiveMemoryHandler(LiveMemoryHandler handler);

	/**
	 * Returns the live memory handler instance used by this memory.
	 * @return the live memory handler
	 */
	public LiveMemoryHandler getLiveMemoryHandler();

	/**
	 * Returns true if exclusive lock exists and memory blocks may be
	 * created, removed, split, joined or moved.  If false is returned,
	 * these types of methods will throw a LockException.  The manner in which
	 * a lock is acquired is application specific.
	 */
//	public boolean haveLock();

	/**
	 * Create an initialized memory block and add it to this Memory.
	 * @param name block name (See {@link Memory#isValidMemoryBlockName(String)} for
	 * naming rules)
	 * @param start start address of the block
	 * @param is source of the data used to fill the block or null for zero initialization.
	 * @param length the size of the block
	 * @param monitor task monitor
	 * @param overlay if true, the block will be created as an OVERLAY which means that a new
	 * overlay address space will be created and the block will have a starting address at the same
	 * offset as the given start address parameter, but in the new address space.
	 * @return new Initialized Memory Block
	 * @throws LockException if exclusive lock not in place (see haveLock())
	 * @throws MemoryConflictException if the new block overlaps with a
	 * previous block
	 * @throws AddressOverflowException if the start is beyond the
	 * address space
	 * @throws CancelledException user cancelled operation
	 * @throws IllegalArgumentException if invalid block name specified
	 */
	public MemoryBlock createInitializedBlock(String name, Address start, InputStream is,
			long length, TaskMonitor monitor, boolean overlay)
			throws LockException, MemoryConflictException, AddressOverflowException,
			CancelledException, IllegalArgumentException;

	/**
	 * Create an initialized memory block and add it to this Memory.
	 * @param name block name (See {@link Memory#isValidMemoryBlockName(String)} for
	 * naming rules)
	 * @param start start of the block
	 * @param size block length (positive non-zero value required)
	 * @param initialValue initialization value for every byte in the block.
	 * @param monitor progress monitor, may be null.
	 * @param overlay if true, the block will be created as an OVERLAY which means that a new
	 * overlay address space will be created and the block will have a starting address at the same
	 * offset as the given start address parameter, but in the new address space.
	 * @return new Initialized Memory Block
	 * @throws LockException if exclusive lock not in place (see haveLock())
	 * @throws MemoryConflictException if the new block overlaps with a
	 * previous block
	 * @throws AddressOverflowException if the start is beyond the
	 * address space
	 * @throws IllegalArgumentException if invalid block name specified
	 * @throws CancelledException user cancelled operation
	 */
	public MemoryBlock createInitializedBlock(String name, Address start, long size,
			byte initialValue, TaskMonitor monitor, boolean overlay)
			throws LockException, IllegalArgumentException, MemoryConflictException,
			AddressOverflowException, CancelledException;

	/**
	 * Create an initialized memory block using bytes from a {@link FileBytes} object.
	 * 
	 * @param name block name (See {@link Memory#isValidMemoryBlockName(String)} for
	 * naming rules)
	 * @param start starting address of the block
	 * @param fileBytes the {@link FileBytes} object to use as the underlying source of bytes.
	 * @param offset the offset into the FileBytes for the first byte of this memory block.
	 * @param size block length (positive non-zero value required)
	 * @param overlay if true, the block will be created as an OVERLAY which means that a new
	 * overlay address space will be created and the block will have a starting address at the same
	 * offset as the given start address parameter, but in the new address space.
	 * @return new Initialized Memory Block
	 * @throws LockException if exclusive lock not in place (see haveLock())
	 * @throws MemoryConflictException if the new block overlaps with a
	 * previous block
	 * @throws AddressOverflowException if the start is beyond the address space
	 * @throws IndexOutOfBoundsException if file bytes range specified by offset and size 
	 * is out of bounds for the specified fileBytes.
	 * @throws IllegalArgumentException if invalid block name specified
	 */
	public MemoryBlock createInitializedBlock(String name, Address start, FileBytes fileBytes,
			long offset, long size, boolean overlay) throws LockException, IllegalArgumentException,
			MemoryConflictException, AddressOverflowException;

	/**
	 * Create an uninitialized memory block and add it to this Memory.
	 * @param name block name (See {@link Memory#isValidMemoryBlockName(String)} for
	 * naming rules)
	 * @param start start of the block
	 * @param size block length
	 * @param overlay if true, the block will be created as an OVERLAY which means that a new
	 * overlay address space will be created and the block will have a starting address at the same
	 * offset as the given start address parameter, but in the new address space.
	 * @return new Uninitialized Memory Block
	 * @throws LockException if exclusive lock not in place (see haveLock())
	 * @throws MemoryConflictException if the new block overlaps with a
	 * previous block
	 * @throws AddressOverflowException if the start is beyond the
	 * address space
	 * @throws IllegalArgumentException if invalid block name specified
	 */
	public MemoryBlock createUninitializedBlock(String name, Address start, long size,
			boolean overlay) throws LockException, IllegalArgumentException,
			MemoryConflictException, AddressOverflowException;

	/**
	 * Create a bit overlay memory block and add it to this Memory.
	 * @param name block name (See {@link Memory#isValidMemoryBlockName(String)} for
	 * naming rules)
	 * @param start start of the block
	 * @param mappedAddress  start address in the source block for the
	 * beginning of this block
	 * @param length block length
	 * @param overlay if true, the block will be created as an OVERLAY which means that a new
	 * overlay address space will be created and the block will have a starting address at the same
	 * offset as the given start address parameter, but in the new address space.
	 * @return new Bit Memory Block
	 * @throws LockException if exclusive lock not in place (see haveLock())
	 * @throws MemoryConflictException if the new block overlaps with a
	 * previous block
	 * @throws MemoryConflictException if the new block overlaps with a
	 * previous block
	 * @throws AddressOverflowException if block specification exceeds bounds of address space
	 * @throws IllegalArgumentException if invalid block name specified
	 */
	public MemoryBlock createBitMappedBlock(String name, Address start, Address mappedAddress,
			long length, boolean overlay) throws LockException, MemoryConflictException,
			AddressOverflowException, IllegalArgumentException;

	/**
	 * Create a memory block that uses the bytes located at a different location with a 1:1
	 * byte mapping scheme.
	 * @param name block name (See {@link Memory#isValidMemoryBlockName(String)} for
	 * naming rules)
	 * @param start start of the block
	 * @param mappedAddress  start address in the source block for the
	 * beginning of this block
	 * @param length block length
	 * @param byteMappingScheme byte mapping scheme (may be null for 1:1 mapping)
	 * @param overlay if true, the block will be created as an OVERLAY which means that a new
	 * overlay address space will be created and the block will have a starting address at the same
	 * offset as the given start address parameter, but in the new address space.
	 * @return new Bit Memory Block
	 * @throws LockException if exclusive lock not in place (see haveLock())
	 * @throws MemoryConflictException if the new block overlaps with a previous block
	 * @throws AddressOverflowException if block specification exceeds bounds of address space
	 * @throws IllegalArgumentException if invalid block name
	 */
	public MemoryBlock createByteMappedBlock(String name, Address start, Address mappedAddress,
			long length, ByteMappingScheme byteMappingScheme, boolean overlay) throws LockException,
			MemoryConflictException, AddressOverflowException, IllegalArgumentException;

	/**
	 * Create a memory block that uses the bytes located at a different location with a 1:1
	 * byte mapping scheme.
	 * @param name block name (See {@link Memory#isValidMemoryBlockName(String)} for
	 * naming rules)
	 * @param start start of the block
	 * @param mappedAddress  start address in the source block for the
	 * beginning of this block
	 * @param length block length
	 * @param overlay if true, the block will be created as an OVERLAY which means that a new
	 * overlay address space will be created and the block will have a starting address at the same
	 * offset as the given start address parameter, but in the new address space.
	 * @return new Bit Memory Block
	 * @throws LockException if exclusive lock not in place (see haveLock())
	 * @throws MemoryConflictException if the new block overlaps with a previous block
	 * @throws AddressOverflowException if block specification exceeds bounds of address space
	 * @throws IllegalArgumentException if invalid block name
	 */
	default public MemoryBlock createByteMappedBlock(String name, Address start,
			Address mappedAddress, long length, boolean overlay) throws LockException,
			MemoryConflictException, AddressOverflowException, IllegalArgumentException {
		return createByteMappedBlock(name, start, mappedAddress, length, null, overlay);
	}

	/**
	 * Creates a MemoryBlock at the given address with the same properties
	 * as block, and adds it to this Memory.  Initialized Default blocks will
	 * have block filled with 0's.  Method will only create physical space blocks
	 * and will not create an overlay block.
	 * @param block source block
	 * @param name block name (See {@link Memory#isValidMemoryBlockName(String)} for
	 * naming rules).
	 * @param start start of the block
	 * @param length the size of the new block.
	 * @return new block
	 * @throws LockException if exclusive lock not in place (see haveLock())
	 * @throws MemoryConflictException if block specification conflicts with an existing block
	 * @throws AddressOverflowException if the new memory block would extend
	 * beyond the end of the address space.
	 * @throws IllegalArgumentException if invalid block name specifiede
	 */
	public MemoryBlock createBlock(MemoryBlock block, String name, Address start, long length)
			throws LockException, IllegalArgumentException, MemoryConflictException,
			AddressOverflowException;

	/**
	 * Remove the memory block.  
	 *
	 * @param block the block to be removed.
	 * @param monitor monitor that is used to cancel the remove operation
	 * @throws LockException if exclusive lock not in place (see haveLock())
	 */
	public void removeBlock(MemoryBlock block, TaskMonitor monitor) throws LockException;

	/**
	 * Get the memory size in bytes.
	 */
	public long getSize();

	/**
	 * Returns the Block which contains addr.
	 *
	 * @param addr a valid data Address.
	 * @return the block containing addr; null if addr is not a valid location.
	 */
	public MemoryBlock getBlock(Address addr);

	/**
	 * Returns the Block with the specified blockName
	 * @param blockName the name of the requested block
	 * @return the Block with the specified blockName
	 */
	public MemoryBlock getBlock(String blockName);

	/**
	 * Returns an array containing all the memory blocks.
	 */
	public MemoryBlock[] getBlocks();

	/**
	 * Move the memory block containing source address to the destination
	 * address.
	 * @param block block to be moved
	 * @param newStartAddr new start address for block
	 * @param monitor task monitor so the move block can be canceled
	 * @throws LockException if exclusive lock not in place (see haveLock())
	 * @throws MemoryConflictException if move would cause
	 * blocks to overlap.
	 * @throws MemoryBlockException if block movement is not permitted
	 * @throws AddressOverflowException if new start address +
	 * block.getSize() would cause the Address to wrap around.
	 * @throws NotFoundException if memoryBlock does not exist in
	 *   this memory.
	 */
	public void moveBlock(MemoryBlock block, Address newStartAddr, TaskMonitor monitor)
			throws LockException, MemoryBlockException, MemoryConflictException,
			AddressOverflowException, NotFoundException;

	/**
	 * Split a block at the given addr and create a new block
	 * starting at addr.
	 * @param block block to be split into two
	 * @param addr address (within block) that will be the
	 * start of new block
	 * @throws LockException if exclusive lock not in place (see haveLock())
	 * @throws NotFoundException thrown if block does not exist
	 * in memory
	 * @throws MemoryBlockException memory split not permitted
	 * @throws AddressOutOfBoundsException thrown if address is
	 * not in the block
	 */
	public void split(MemoryBlock block, Address addr)
			throws MemoryBlockException, LockException, NotFoundException;

	/**
	 * Join the two blocks to create a single memory block.
	 * IMPORTANT! When done, both blockOne and blockTwo should no longer be used.
	 * @param blockOne block to be combined with blockTwo
	 * @param blockTwo block to be combined with blockOne
	 * @return new block
	 * @throws LockException if exclusive lock not in place (see haveLock())
	 * @throws MemoryBlockException thrown if the blocks are
	 * not contiguous in the address space,
	 */
	public MemoryBlock join(MemoryBlock blockOne, MemoryBlock blockTwo)
			throws LockException, MemoryBlockException, NotFoundException;

	/**
	 * Convert an existing uninitialized block with an
	 * initialized block.
	 * @param unitializedBlock unitialized block to convert
	 * @param initialValue initial value for the bytes
	 * @throws LockException if exclusive lock not in place (see haveLock())
	 * @throws MemoryBlockException if there is no block in memory
	 * at the same address as block or if the block lengths are not
	 * the same.
	 */
	public MemoryBlock convertToInitialized(MemoryBlock unitializedBlock, byte initialValue)
			throws LockException, MemoryBlockException, NotFoundException;

	public MemoryBlock convertToUninitialized(MemoryBlock itializedBlock)
			throws MemoryBlockException, NotFoundException, LockException;

	/**
	  * Finds a sequence of contiguous bytes that match the
	  * given byte array at all bit positions where the mask contains an "on" bit.
	  *
	  * @param addr The beginning address in memory to search.
	  * @param bytes the array of bytes to search for.
	  * @param masks the array of masks. (One for each byte in the byte array)
	  *              if all bits of each byte is to be checked (ie: all mask bytes are 0xff),
	  *              then pass a null for masks.
	  * @param forward if true, search in the forward direction.
	  *
	  * @return The address of where the first match is found. Null is returned
	  * if there is no match.
	  */
	public Address findBytes(Address addr, byte[] bytes, byte[] masks, boolean forward,
			TaskMonitor monitor);

	/**
	  * Finds a sequence of contiguous bytes that match the
	  * given byte array at all bit positions where the mask contains an "on" bit.
	  * Starts at startAddr and ends at endAddr.
	  * If forward is true, search starts at startAddr and will end if startAddr "&gt;" endAddr.
	  * If forward is false, search starts at start addr and will end if startAddr "&lt;" endAddr.
	  *
	  * @param startAddr The beginning address in memory to search.
	  * @param endAddr   The ending address in memory to search (inclusive).
	  * @param bytes the array of bytes to search for.
	  * @param masks the array of masks. (One for each byte in the byte array)
	  *              if all bits of each byte is to be checked (ie: all mask bytes are 0xff),
	  *              then pass a null for masks.
	  * @param forward if true, search in the forward direction.
	  *
	  * @return The address of where the first match is found. Null is returned
	  * if there is no match.
	  */
	public Address findBytes(Address startAddr, Address endAddr, byte[] bytes, byte[] masks,
			boolean forward, TaskMonitor monitor);

	/**
	 * Get byte at addr.
	 *
	 * @param addr the Address of the byte.
	 * @return the byte.
	 * @throws MemoryAccessException if the address is
	 * not contained in any memory block.
	 */
	public byte getByte(Address addr) throws MemoryAccessException;

	/**
	 * Get dest.length number of bytes starting at the given address.
	 *
	 * @param addr the starting Address.
	 * @param dest the byte array to populate.
	 * @return the number of bytes put into dest.  May be less than
	 * dest.length if the requested number extends beyond available memory.
	 * @throws MemoryAccessException if the starting address is
	 * not contained in any memory block.
	 */
	public int getBytes(Address addr, byte[] dest) throws MemoryAccessException;

	/**
	 * Get size number of bytes starting at the given address and populates
	 * dest starting at dIndex.
	 *
	 * @param addr the starting Address.
	 * @param dest the byte array to populate.
	 * @param destIndex the offset into dest to place the bytes.
	 * @param size the number of bytes to get.
	 * @return the number of bytes put into dest.  May be less than
	 * size if the requested number extends beyond initialized / available memory.
	 * @throws MemoryAccessException if the starting address is
	 * not contained in any memory block or is an uninitialized location.
	 */
	public int getBytes(Address addr, byte[] dest, int destIndex, int size)
			throws MemoryAccessException;

	/**
	 * Get the short at addr.
	 *
	 * @param addr the Address where the short starts.
	 * @return the short.
	 * @throws MemoryAccessException if not all needed bytes are contained in initialized memory.
	 */
	public short getShort(Address addr) throws MemoryAccessException;

	/**
	 * Get the short at addr using the specified endian order.
	 *
	 * @param addr the Address where the short starts.
	 * @param bigEndian true means to get the short in
	 * bigEndian order
	 * @return the short.
	 *
	 * @throws MemoryAccessException if not all needed bytes are contained in initialized memory.
	 */
	public short getShort(Address addr, boolean bigEndian) throws MemoryAccessException;

	/**
	 * Get dest.length number of shorts starting at the given address.
	 *
	 * @param addr the starting Address.
	 * @param dest the short array to populate.
	 * @return the number of shorts put into dest.  May be less than
	 * dest.length if the requested number extends beyond available memory.
	 * If the number of retrievable bytes is odd, the final byte will be discarded.
	 * @throws MemoryAccessException if not all needed bytes are contained in initialized memory.
	 */
	public int getShorts(Address addr, short[] dest) throws MemoryAccessException;

	/**
	 * Get dest.length number of shorts starting at the given address.
	 *
	 * @param addr the starting Address.
	 * @param dest the short array to populate.
	 * @param dIndex the offset into dest to place the shorts.
	 * @param nElem the number of shorts to get.
	 * @return the number of shorts put into dest.  May be less than
	 * dest.length if the requested number extends beyond available memory.
	 * If the number of retrievable bytes is odd, the final byte will be discarded.
	 * @throws MemoryAccessException if not all needed bytes are contained in initialized memory.
	 */
	public int getShorts(Address addr, short[] dest, int dIndex, int nElem)
			throws MemoryAccessException;

	/**
	 * Get dest.length number of shorts starting at the given address.
	 *
	 * @param addr the starting Address.
	 * @param dest the short array to populate.
	 * @param dIndex the offset into dest to place the shorts.
	 * @param nElem the number of shorts to get.
	 * @param isBigEndian true means to get the shorts in
	 * bigEndian order
	 * @return the number of shorts put into dest.  May be less than
	 * dest.length if the requested number extends beyond available memory.
	 * If the number of retrievable bytes is odd, the final byte will be discarded.
	 * @throws MemoryAccessException if not all needed bytes are contained in initialized memory.
	 */
	public int getShorts(Address addr, short[] dest, int dIndex, int nElem, boolean isBigEndian)
			throws MemoryAccessException;

	/**
	 * Get the int at addr.
	 *
	 * @param addr the Address where the int starts.
	 * @return the int.
	 *
	 * @throws MemoryAccessException if not all needed bytes are contained in initialized memory.
	 */
	public int getInt(Address addr) throws MemoryAccessException;

	/**
	 * Get the int at addr using the specified endian order.
	 *
	 * @param addr the Address where the int starts.
	 * @param bigEndian true means to get the int in
	 * big endian order
	 * @return the int.
	 *
	 * @throws MemoryAccessException if not all needed bytes are contained in initialized memory.
	 */
	public int getInt(Address addr, boolean bigEndian) throws MemoryAccessException;

	/**
	 * Get dest.length number of ints starting at the given address.
	 *
	 * @param addr the starting Address.
	 * @param dest the int array to populate.
	 * @return the number of ints put into dest.  May be less than
	 * dest.length if the requested number extends beyond available memory.
	 * If the number of retrievable bytes is not 0 mod 4, the final byte(s) will be discarded.
	 * @throws MemoryAccessException if the starting address is
	 * not contained in any memory block.
	 */
	public int getInts(Address addr, int[] dest) throws MemoryAccessException;

	/**
	 * Get dest.length number of ints starting at the given address.
	 *
	 * @param addr the starting Address.
	 * @param dest the int array to populate.
	 * @param dIndex the offset into dest to place the ints.
	 * @param nElem the number of ints to get.
	 * @return the number of ints put into dest.  May be less than
	 * dest.length if the requested number extends beyond available memory.
	 * If the number of retrievable bytes is not 0 mod 4, the final byte(s) will be discarded.
	 * @throws MemoryAccessException if not all needed bytes are contained in initialized memory.
	 */
	public int getInts(Address addr, int[] dest, int dIndex, int nElem)
			throws MemoryAccessException;

	/**
	 * Get dest.length number of ints starting at the given address.
	 *
	 * @param addr the starting Address.
	 * @param dest the int array to populate.
	 * @param dIndex the offset into dest to place the ints.
	 * @param nElem the number of ints to get.
	 * @param isBigEndian true means to get the ints in
	 * bigEndian order
	 * @return the number of ints put into dest.  May be less than
	 * dest.length if the requested number extends beyond available memory.
	 * If the number of retrievable bytes is not 0 mod 4, the final byte(s) will be discarded.
	 * @throws MemoryAccessException if not all needed bytes are contained in initialized memory.
	 */
	public int getInts(Address addr, int[] dest, int dIndex, int nElem, boolean isBigEndian)
			throws MemoryAccessException;

	/**
	 * Get the long at addr.
	 *
	 * @param addr the Address where the long starts.
	 * @return the long.
	 *
	 * @throws MemoryAccessException if not all needed bytes are contained in initialized memory.
	 */
	public long getLong(Address addr) throws MemoryAccessException;

	/**
	 * Get the long at addr in the specified endian order.
	 *
	 * @param addr the Address where the long starts.
	 * @param bigEndian true means to get the long in
	 * big endian order
	 * @return the long.
	 *
	 * @throws MemoryAccessException if not all needed bytes are contained in initialized memory.
	 */
	public long getLong(Address addr, boolean bigEndian) throws MemoryAccessException;

	/**
	 * Get dest.length number of longs starting at the given address.
	 *
	 * @param addr the starting Address.
	 * @param dest the long array to populate.
	 * @return the number of longs put into dest.  May be less than
	 * dest.length if the requested number extends beyond available memory.
	 * If the number of retrievable bytes is not 0 mod 8, the final byte(s) will be discarded.
	 * @throws MemoryAccessException if not all needed bytes are contained in initialized memory.
	 */
	public int getLongs(Address addr, long[] dest) throws MemoryAccessException;

	/**
	 * Get dest.length number of longs starting at the given address.
	 *
	 * @param addr the starting Address.
	 * @param dest the long array to populate.
	 * @param dIndex the offset into dest to place the longs.
	 * @param nElem the number of longs to get.
	 * @return the number of longs put into dest.  May be less than
	 * dest.length if the requested number extends beyond available memory.
	 * If the number of retrievable bytes is not 0 mod 8, the final byte(s) will be discarded.
	 * @throws MemoryAccessException if not all needed bytes are contained in initialized memory.
	 */
	public int getLongs(Address addr, long[] dest, int dIndex, int nElem)
			throws MemoryAccessException;

	/**
	 * Get dest.length number of longs starting at the given address.
	 *
	 * @param addr the starting Address.
	 * @param dest the long array to populate.
	 * @param dIndex the offset into dest to place the longs.
	 * @param nElem the number of longs to get.
	 * @param isBigEndian true means to get the longs in
	 * bigEndian order
	 * @return the number of longs put into dest.  May be less than
	 * dest.length if the requested number extends beyond available memory.
	 * If the number of retrievable bytes is not 0 mod 8, the final byte(s) will be discarded.
	 * @throws MemoryAccessException if not all needed bytes are contained in initialized memory.
	 */
	public int getLongs(Address addr, long[] dest, int dIndex, int nElem, boolean isBigEndian)
			throws MemoryAccessException;

	/**
	 * Write byte at addr.
	 *
	 * @param addr the Address of the byte.
	 * @param value the data to write.
	 *
	 * @throws MemoryAccessException if writing is not allowed.
	 */
	public void setByte(Address addr, byte value) throws MemoryAccessException;

	/**
	 * Write size bytes from values at addr.
	 *
	 * @param addr   the starting Address.
	 * @param source the bytes to write.
	 * @throws MemoryAccessException if writing is not allowed.
	 */
	public void setBytes(Address addr, byte[] source) throws MemoryAccessException;

	/**
	 * Write an array of bytes.  This should copy size bytes or fail!
	 *
	 * @param addr the starting Address of the bytes.
	 * @param source an array to get bytes from.
	 * @param sIndex the starting source index.
	 * @param size the number of bytes to fill.
	 * @throws MemoryAccessException if writing is not allowed.
	 */
	public void setBytes(Address addr, byte[] source, int sIndex, int size)
			throws MemoryAccessException;

	/**
	 * Write short at addr in big endian order.
	 *
	 * @param addr the Address of the short.
	 * @param value the data to write.
	 *
	 * @throws MemoryAccessException if writing is not allowed.
	 */
	public void setShort(Address addr, short value) throws MemoryAccessException;

	/**
	 * Write short at addr in the specified endian order.
	 *
	 * @param addr the Address of the short.
	 * @param value the data to write.
	 * @param bigEndian true means to write short in
	 * big endian order
	 * @throws MemoryAccessException if writing is not allowed.
	 */
	public void setShort(Address addr, short value, boolean bigEndian) throws MemoryAccessException;

	/**
	 * Write int at addr.
	 *
	 * @param addr the Address of the int.
	 * @param value the data to write.
	 *
	 * @throws MemoryAccessException if writing is not allowed.
	 */
	public void setInt(Address addr, int value) throws MemoryAccessException;

	/**
	 * Write int at addr in the specified endian order.
	 *
	 * @param addr the Address of the int.
	 * @param bigEndian true means to write the short in
	 * bigEndian order
	 * @param value the data to write.
	 *
	 * @throws MemoryAccessException if writing is not allowed.
	 */
	public void setInt(Address addr, int value, boolean bigEndian) throws MemoryAccessException;

	/**
	 * Write long at addr.
	 *
	 * @param addr the Address of the long.
	 * @param value the data to write.
	 *
	 * @throws MemoryAccessException if writing is not allowed.
	 */
	public void setLong(Address addr, long value) throws MemoryAccessException;

	/**
	 * Write long at addr in the specified endian order.
	 *
	 * @param addr the Address of the long.
	 * @param value the data to write.
	 * @param bigEndian true means to write the long in
	 * bigEndian order
	 *
	 * @throws MemoryAccessException if writing is not allowed.
	 */
	public void setLong(Address addr, long value, boolean bigEndian) throws MemoryAccessException;

	/**
	 * Stores a sequence of bytes into the program.  Typically, this method is used by importers
	 * to store the original raw program bytes.
	 *
	 * @param filename the name of the file from where the bytes originated
	 * @param offset the offset into the file for the first byte in the input stream.
	 * @param size the number of bytes to store from the input stream.
	 * @param is the input stream that will supply the bytes to store in the program.
	 * @param monitor 
	 * @return a FileBytes that was created to access the bytes.
	 * @throws IOException if there was an IOException saving the bytes to the program database.
	 * @throws CancelledException if the user cancelled this operation. Note: the database will
	 * be stable, but the buffers may contain 0s instead of the actual bytes.
	 */
	public FileBytes createFileBytes(String filename, long offset, long size, InputStream is,
			TaskMonitor monitor) throws IOException, CancelledException;

	/**
	 * Returns a list of all the stored original file bytes objects
	 * @return a list of all the stored original file bytes objects
	 */
	public List<FileBytes> getAllFileBytes();

	/**
	 * Deletes a stored sequence of file bytes.  The file bytes can only be deleted if there
	 * are no memory block references to the file bytes.
	 * 
	 * @param fileBytes the FileBytes for the file bytes to be deleted.
	 * @return true if the FileBytes was deleted.  If any memory blocks are referenced by this 
	 * FileBytes or it is invalid then it will not be deleted and false will be returned.
	 * @throws IOException if there was an error updating the database.
	 */
	public boolean deleteFileBytes(FileBytes fileBytes) throws IOException;

	/**
	 * Returns information ({@link AddressSourceInfo}) about the byte source at the given address.
	 * @param address the address to query. Returns null if the address is not in memory.
	 * @return information ({@link AddressSourceInfo}) about the byte source at the given address or
	 * null if the address is not in memory.
	 */
	public AddressSourceInfo getAddressSourceInfo(Address address);

	/**
	 * Validate the given block name: cannot be null, cannot be an empty string, 
	 * cannot contain control characters (ASCII 0..0x19).
	 * <BR>
	 * NOTE: When producing an overlay memory space which corresponds to a block, the space
	 * name will be modified to be consistent with address space name restrictions
	 * and to ensure uniqueness.
	 * @param name memory block name
	 * @return true if name is valid else false
	 */
	public static boolean isValidMemoryBlockName(String name) {
		if (name == null || name.length() == 0) {
			return false;
		}
		for (int i = 0; i < name.length(); i++) {
			char c = name.charAt(i);
			if (c < 0x20) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Gets a {@link List} of {@link Address addresses} that correspond to the given file offset.
	 * @param fileOffset the file offset that will be used to locate the corresponding memory 
	 *   addresses
	 * @return a {@link List} of {@link Address}es that are associated with the provided file offset 
	 */
	public default List<Address> locateAddressesForFileOffset(long fileOffset) {
		List<Address> list = new ArrayList<>();
		for (MemoryBlock memBlock : getBlocks()) {
			for (MemoryBlockSourceInfo info : memBlock.getSourceInfos()) {
				Address addr = info.locateAddressForFileOffset(fileOffset);
				if (addr != null) {
					list.add(addr);
				}
			}
		}
		return list;
	}

	/**
	 * Gets a list of addresses where the byte at the given offset
	 * from the given FileBytes was loaded into memory.
	 * @param offset the file offset in the given FileBytes of the byte that is to be 
	 * located in memory
	 * @param fileBytes the FileBytesobject whose byte is to be located in memory
	 * @return a list of addresses that are associated with the given
	 * FileBytes and offset 
	 */
	public default List<Address> locateAddressesForFileBytesOffset(FileBytes fileBytes, long offset) {
		List<Address> list = new ArrayList<>();
		for (MemoryBlock memBlock : getBlocks()) {
			for (MemoryBlockSourceInfo info : memBlock.getSourceInfos()) {
				Optional<FileBytes> blockFileBytes = info.getFileBytes();
				if (blockFileBytes.isPresent() && blockFileBytes.get().equals(fileBytes)) {
					Address addr = info.locateAddressForFileOffset(offset);
					if (addr != null) {
						list.add(addr);
					}
				}
			}
		}
		return list;
	}
}
