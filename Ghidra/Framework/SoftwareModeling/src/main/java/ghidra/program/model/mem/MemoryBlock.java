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

import java.io.InputStream;
import java.io.Serializable;
import java.util.List;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.NamingUtilities;

/**
 * Interface that defines a block in memory.
 */
public interface MemoryBlock extends Serializable, Comparable<MemoryBlock> {

	/**
	 * A special EXTERNAL block may be created by certain program loaders (e.g., Elf) to
	 * act as a stand-in for unknown external symbol locations.
	 */
	public static final String EXTERNAL_BLOCK_NAME = "EXTERNAL";

	// Memory block permission bits
	public static int VOLATILE = 0x8;
	public static int READ = 0x4;
	public static int WRITE = 0x2;
	public static int EXECUTE = 0x1;

	/**
	 * Returns block permissions as a bit mask.
	 * Permission bits defined as READ, WRITE, EXECUTE and VOLATILE 
	 */
	public int getPermissions();

	/**
	 * Get memory data in the form of an InputStream. 
	 * Null is returned for thos memory blocks which have no data.
	 */
	public InputStream getData();

	/**
	 * Return whether addr is contained in this block.
	 * @param addr address 
	 */
	public boolean contains(Address addr);

	/**
	 * Return the starting address for this block.
	 * 
	 * @return block's start address
	 */
	public Address getStart();

	/**
	 * Return the end address of this block.
	 * 
	 * @return end address of the block
	 */
	public Address getEnd();

	/**
	 * Get the number of bytes in this block.
	 * 
	 * @return number of bytes in the block
	 */
	public long getSize();

	/**
	 * Get the name of this block
	 */
	public String getName();

	/**
	 * Set the name for this block (See {@link NamingUtilities#isValidName(String)} for
	 * naming rules).  Specified name must not conflict with an address space name.
	 * @param name the new name for this block.
	 * @throws IllegalArgumentException if invalid name specified
	 * @throws LockException renaming an Overlay block without exclusive access
	 */
	public void setName(String name)
			throws IllegalArgumentException, LockException;

	/**
	 * Get the comment associated with this block.
	 */
	public String getComment();

	/**
	 * Set the comment associated with this block.
	 * @param comment the comment to associate with this block.
	 */
	public void setComment(String comment);

	/**
	 * Returns the value of the read property associated with this block
	 */
	public boolean isRead();

	/**
	 * Sets the read property associated with this block.
	 * @param r the value to set the read property to.
	 */
	public void setRead(boolean r);

	/**
	 * Returns the value of the write property associated with this block
	 */
	public boolean isWrite();

	/**
	 * Sets the write property associated with this block.
	 * @param w the value to set the write property to.
	 */
	public void setWrite(boolean w);

	/**
	 * Returns the value of the execute property associated with this block
	 */
	public boolean isExecute();

	/**
	 * Sets the execute property associated with this block.
	 * @param e the value to set the execute property to.
	 */
	public void setExecute(boolean e);

	/**
	 * Sets the read, write, execute permissions on this block
	 * @param read the read permission
	 * @param write the write permission
	 * @param execute the execute permission
	 */
	public void setPermissions(boolean read, boolean write, boolean execute);

	/**
	 * Returns the value of the volatile property associated with this block.
	 * This attribute is generally associated with block of I/O regions of memory.
	 */
	public boolean isVolatile();

	/**
	 * Sets the volatile property associated with this block.
	 * @param v the value to set the volatile property to.
	 */
	public void setVolatile(boolean v);

	/**
	 * Get the name of the source of this memory block.
	 * 
	 * @return source name
	 */
	public String getSourceName();

	/**
	 * Sets the name of the source file that provided the data.
	 * @param sourceName the name of the source file.
	 */
	public void setSourceName(String sourceName);

	/**
	 * Returns the byte at the given address in this block.
	 * @param addr the address.
	 * @throws MemoryAccessException if any of the requested bytes are
	 * uninitialized.
	 * @throws IllegalArgumentException if the Address is not in this block.
	 */
	public byte getByte(Address addr) throws MemoryAccessException;

	/**
	 * Tries to get b.length bytes from this block at the given address.  May 
	 * return fewer bytes if the requested length is beyond the end of the block.
	 * @param addr the address from which to get the bytes.
	 * @param b the byte array to populate.
	 * @return the number of bytes actually populated.
	 * @throws MemoryAccessException if any of the requested bytes are
	 * uninitialized.
	 * @throws IllegalArgumentException if the Address is not in this block.
	 */
	public int getBytes(Address addr, byte[] b) throws MemoryAccessException;

	/**
	 * Tries to get len bytes from this block at the given address and put them 
	 * into the given byte array at the specified offet.  May return
	 * fewer bytes if the requested length is beyond the end of the block.
	 * @param addr the address from which to get the bytes.
	 * @param b the byte array to populate.
	 * @param off the offset into the byte array.
	 * @param len the number of bytes to get.
	 * @return the number of bytes actually populated.
	 * @throws MemoryAccessException if any of the requested bytes are
	 * uninitialized.
	 * @throws IllegalArgumentException if the Address is not in this block.
	 */
	public int getBytes(Address addr, byte[] b, int off, int len) throws MemoryAccessException;

	/**
	 * Puts the given byte at the given address in this block.
	 * @param addr the address.
	 * @throws MemoryAccessException if the block is uninitialized
	 * @throws IllegalArgumentException if the Address is not in this block.
	 */
	public void putByte(Address addr, byte b) throws MemoryAccessException;

	/**
	 * Tries to put b.length bytes from the specified byte array to this block. 
	 * All the bytes may not be put if the requested length is beyond the end of
	 * the block.
	 * @param addr the address of where to put the bytes.
	 * @param b the byte array containing the bytes to write.
	 * @return the number of bytes actually written.	
	 * @throws MemoryAccessException if the block is uninitialized
	 * @throws IllegalArgumentException if the Address is not in this block.
	 */
	public int putBytes(Address addr, byte[] b) throws MemoryAccessException;

	/**
	 * Tries to put len bytes from the specified byte array to this block.  All 
	 * the bytes may not be written if the requested length is beyond the end of
	 * the block.
	 * @param addr the address of where to put the bytes.
	 * @param b the byte array containing the bytes to write.
	 * @param off the offset into the byte array.
	 * @param len the number of bytes to write.
	 * @return the number of bytes actually written.	
	 * @throws MemoryAccessException if the block is uninitialized
	 * @throws IllegalArgumentException if the Address is not in this block.
	 */
	public int putBytes(Address addr, byte[] b, int off, int len) throws MemoryAccessException;

	/**
	 * Get the type for this block: DEFAULT, BIT_MAPPED, or BYTE_MAPPED
	 */
	public MemoryBlockType getType();

	/**
	 * Return whether this block has been initialized.
	 */
	public boolean isInitialized();

	/**
	 * Returns true if this is either a bit-mapped or byte-mapped block
	 */
	public boolean isMapped();

	/**
	 * Returns true if this is an overlay block (i.e., contained within overlay space).
	 * @return true if this is an overlay block
	 */
	public boolean isOverlay();

	/**
	 * Returns true if this memory block is a real loaded block (i.e. RAM) and not a special block
	 * containing file header data such as debug sections.
	 * @return true if this is a loaded block and not a "special" block such as a file header.
	 */
	public boolean isLoaded();

	/**
	 * Returns a list of {@link MemoryBlockSourceInfo} objects for this block.  A block may consist of 
	 * multiple sequences of bytes from different sources.  Each such source of bytes is described
	 * by its respective SourceInfo object.  Blocks may have multiple sources after two or more
	 * memory blocks have been joined together and the underlying byte sources can't be joined.
	 * @return a list of SourceInfo objects, one for each different source of bytes in this block.
	 */
	public List<MemoryBlockSourceInfo> getSourceInfos();

	/**
	 * Determine if the specified address is contained within the reserved EXTERNAL block.
	 * @param address address of interest
	 * @param program
	 * @return true if address is contained within the reserved EXTERNAL block, else false.
	 */
	public static boolean isExternalBlockAddress(Address address, Program program) {
		Memory memory = program.getMemory();
		if (!address.isMemoryAddress()) {
			return false;
		}
		MemoryBlock block = memory.getBlock(address);
		return block != null && MemoryBlock.EXTERNAL_BLOCK_NAME.equals(block.getName());
	}
}
