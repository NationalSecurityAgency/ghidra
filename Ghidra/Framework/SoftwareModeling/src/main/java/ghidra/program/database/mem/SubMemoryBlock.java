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

import java.io.IOException;

import db.DBRecord;
import ghidra.program.model.mem.*;

/**
 * Interface for the various types of memory block sections.  They are used by a {@link MemoryBlockDB}
 * to do the actual storing and fetching of the bytes that make up a MemoryBlock
 */
abstract class SubMemoryBlock implements Comparable<SubMemoryBlock> {

	protected final MemoryMapDBAdapter adapter;
	protected final DBRecord record;
	protected long subBlockLength;
	protected long subBlockOffset;

	protected SubMemoryBlock(MemoryMapDBAdapter adapter, DBRecord record) {
		this.adapter = adapter;
		this.record = record;
		this.subBlockOffset = record.getLongValue(MemoryMapDBAdapter.SUB_START_OFFSET_COL);
		this.subBlockLength = record.getLongValue(MemoryMapDBAdapter.SUB_LENGTH_COL);
	}

	/**
	 * Return whether this block has been initialized (has byte values)
	 * 
	 * @return true if the block has associated byte values.
	 */
	public abstract boolean isInitialized();

	/**
	 * Returns the id of the MemoryBlockDB object that owns this sub block.
	 * @return  the id of the MemoryBlockDB object that owns this sub block.
	 */
	public final long getParentBlockID() {
		return record.getLongValue(MemoryMapDBAdapter.SUB_PARENT_ID_COL);
	}

	/**
	 * Returns the starting offset for this sub block.  In other words, the first byte in this sub 
	 * block is at this starting offset relative to the containing {@link MemoryBlockDB}
	 * 
	 * @return the starting offset for this sub block.
	 */
	public final long getStartingOffset() {
		return subBlockOffset;
	}

	/**
	 * Returns the length of this sub block
	 * @return the length of this sub block
	 */
	public final long getLength() {
		return subBlockLength;
	}

	/**
	 * Returns true if the given {@link MemoryBlockDB} offset is in this sub block.
	 * 
	 * @param memBlockOffset the offset relative to the containing {@link MemoryBlockDB}
	 * @return true if the offset is valid for this block
	 */
	public final boolean contains(long memBlockOffset) {
		return (memBlockOffset >= subBlockOffset) &&
			(memBlockOffset < subBlockOffset + subBlockLength);
	}

	/**
	 * Returns the byte in this sub block corresponding to the given offset relative to the containing
	 * {@link MemoryBlockDB}.  In other words, the first byte in this sub block can be retrieved
	 * using an offset equal to this blocks starting offset.
	 * 
	 * @param memBlockOffset the offset from the start of the containing {@link MemoryBlockDB}
	 * @return the byte at the given containing block offset.
	 * @throws MemoryAccessException if the block is uninitialized.
	 * @throws IOException if there is a problem reading from the database
	 */
	public abstract byte getByte(long memBlockOffset) throws MemoryAccessException, IOException;

	/**
	 * Tries to get len bytes from this block at the given offset (relative to the containing
	 * {@link MemoryBlockDB} and put them into the given byte array at the specified offset.  
	 * May return fewer bytes if the requested length is beyond the end of the block.
	 * @param memBlockOffset the offset relative to the containing {@link MemoryBlockDB}
	 * @param b the byte array to populate.
	 * @param off the offset into the byte array.
	 * @param len the number of bytes to get.
	 * @return the number of bytes actually populated.
	 * @throws MemoryAccessException if any of the requested bytes are
	 * uninitialized.
	 * @throws IOException if there is a problem reading from the database
	 * @throws IllegalArgumentException if the offset is not in this block.
	 */
	public abstract int getBytes(long memBlockOffset, byte[] b, int off, int len)
			throws MemoryAccessException, IOException;

	/**
	 * Stores the byte in this sub block at the given offset relative to the containing
	 * {@link MemoryBlockDB}.  In other words, the first byte in this sub block can be targeted
	 * using an offset equal to this blocks starting offset.
	 * 
	 * @param memBlockOffset the offset from the start of the containing {@link MemoryBlockDB}
	 * @param b the byte value to store at the given offset.
	 * @throws MemoryAccessException if the block is uninitialized
	 * @throws IOException if there is a problem writing to the database
	 * @throws IllegalArgumentException if the offset is not in this block.
	 */
	public abstract void putByte(long memBlockOffset, byte b)
			throws MemoryAccessException, IOException;

	/**
	 * Tries to write len bytes to this block at the given offset (relative to the containing
	 * {@link MemoryBlockDB} using the bytes contained in the given byte array at the specified byte
	 * array offset.  
	 * May write fewer bytes if the requested length is beyond the end of the block.
	 * 
	 * @param memBlockOffset the offset relative to the containing {@link MemoryBlockDB}
	 * @param b the byte array with the bytes to store.
	 * @param off the offset into the byte array.
	 * @param len the number of bytes to write.
	 * @return the number of bytes actually written
	 * @throws MemoryAccessException if this block is uninitialized.
	 * @throws IOException if there is a problem writing to the database
	 * @throws IllegalArgumentException if the offset is not in this block.
	 */
	public abstract int putBytes(long memBlockOffset, byte[] b, int off, int len)
			throws MemoryAccessException, IOException;

	/**
	 * Deletes this SumMemoryBlock
	 * @throws IOException if a database error occurs
	 */
	public void delete() throws IOException {
		adapter.deleteSubBlock(record.getKey());
	}

	/**
	 * Sets the length of a subblock (Used by the split command)
	 * @param length the new length of the block
	 * @throws IOException if a database error occurs
	 */
	protected void setLength(long length) throws IOException {
		this.subBlockLength = length;
		record.setLongValue(MemoryMapDBAdapter.SUB_LENGTH_COL, length);
		adapter.updateSubBlockRecord(record);
	}

	/**
	 * Attempts to join the given SubMemoryBlock with this block if possible
	 * 
	 * @param other the SubMemoryBlock to join with this one.
	 * @return true if the given SubMemoryBlock was successfully merged into this one
	 * @throws IOException if a database error occurs.
	 */
	protected abstract boolean join(SubMemoryBlock other) throws IOException;

	/**
	 * Returns true if this is either a bit-mapped or byte-mapped block.
	 * 
	 * @return true if this is either a bit-mapped or byte-mapped block.
	 */
	protected boolean isMapped() {
		return false;
	}

	/**
	 * Get the {@link MemoryBlockType} for this block: DEFAULT, BIT_MAPPED, or BYTE_MAPPED
	 * 
	 * @return the type for this block: DEFAULT, BIT_MAPPED, or BYTE_MAPPED
	 */
	protected MemoryBlockType getType() {
		return MemoryBlockType.DEFAULT;
	}

	/**
	 * Returns the {@link MemoryBlockSourceInfo} object for this SubMemoryBlock
	 * @param block the {@link MemoryBlock} that this block belongs to.
	 * @return the {@link MemoryBlockSourceInfo} object for this SubMemoryBlock
	 */
	protected final MemoryBlockSourceInfo getSourceInfo(MemoryBlock block) {
		return new MemoryBlockSourceInfoDB(block, this);
	}

	/**
	 * Splits this SubMemoryBlock into two memory blocks
	 * @param memBlockOffset the offset relative to the owning MemoryBlock (not this SubMemoryBlock)
	 * To get the offset relative to this SubMemoryBlock, you have to subtract this sub blocks 
	 * starting offset.
	 * @return the new SubMemoryBlock that contains the back half of this block
	 * @throws IOException if a database error occurs.
	 */
	protected abstract SubMemoryBlock split(long memBlockOffset) throws IOException;

	/**
	 * Updates this SubMemoryBlock to have a new owning MemoryBlock and offset within that block. 
	 * This is used when splitting a block and entire sub blocks have to be moved to the new split 
	 * block.
	 * @param key the id of the new owning memory block.
	 * @param startingOffset the starting offset of this sub block in the new block.
	 * @throws IOException if a database error occurs.
	 */
	protected void setParentIdAndStartingOffset(long key, long startingOffset) throws IOException {
		this.subBlockOffset = startingOffset;
		record.setLongValue(MemoryMapDBAdapter.SUB_PARENT_ID_COL, key);
		record.setLongValue(MemoryMapDBAdapter.SUB_START_OFFSET_COL, startingOffset);
		adapter.updateSubBlockRecord(record);
	}

	/**
	 * Returns a description of this SubMemoryBlock suitable to be displayed to the user.
	 * @return a description of this SubMemoryBlock suitable to be displayed to the user.
	 */
	protected abstract String getDescription();

	/**
	 * Returns true if this subBlock uses the given fileBytes as its byte source.
	 * @param fileBytes  the {@link FileBytes} to check for use
	 * @return  true if this subBlock uses the given fileBytes as its byte source.
	 */
	protected boolean uses(FileBytes fileBytes) {
		return false;
	}

	@Override
	public int compareTo(SubMemoryBlock o) {
		long result = getStartingOffset() - o.getStartingOffset();
		if (result == 0) {
			return 0;
		}
		return result > 0 ? 1 : -1;
	}
}
