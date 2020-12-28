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
import java.io.InputStream;
import java.util.List;

import db.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.mem.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

abstract class MemoryMapDBAdapter {

	static final int CURRENT_VERSION = MemoryMapDBAdapterV3.V3_VERSION;

	static Schema BLOCK_SCHEMA = MemoryMapDBAdapterV3.V3_BLOCK_SCHEMA;
	static Schema SUB_BLOCK_SCHEMA = MemoryMapDBAdapterV3.V3_SUB_BLOCK_SCHEMA;

	public static final int NAME_COL = MemoryMapDBAdapterV3.V3_NAME_COL;
	public static final int COMMENTS_COL = MemoryMapDBAdapterV3.V3_COMMENTS_COL;
	public static final int SOURCE_COL = MemoryMapDBAdapterV3.V3_SOURCE_COL;
	public static final int PERMISSIONS_COL = MemoryMapDBAdapterV3.V3_PERMISSIONS_COL;
	public static final int START_ADDR_COL = MemoryMapDBAdapterV3.V3_START_ADDR_COL;
	public static final int LENGTH_COL = MemoryMapDBAdapterV3.V3_LENGTH_COL;
	public static final int SEGMENT_COL = MemoryMapDBAdapterV3.V3_SEGMENT_COL;

	public static final int SUB_PARENT_ID_COL = MemoryMapDBAdapterV3.V3_SUB_PARENT_ID_COL;
	public static final int SUB_TYPE_COL = MemoryMapDBAdapterV3.V3_SUB_TYPE_COL;
	public static final int SUB_LENGTH_COL = MemoryMapDBAdapterV3.V3_SUB_LENGTH_COL;
	public static final int SUB_START_OFFSET_COL = MemoryMapDBAdapterV3.V3_SUB_START_OFFSET_COL;

	/**
	 * Subblock record int data1 usage:
	 * <ul>
	 * <li>{@link BufferSubMemoryBlock} - data buffer ID</li>
	 * <li>{@link FileBytesSubMemoryBlock} - file bytes layered data buffer ID</li>
	 * <li>{@link ByteMappedSubMemoryBlock} - encoded byte mapping scheme</li>
	 * <li>{@link BitMappedSubMemoryBlock} - (not used) 0</li>
	 * <li>{@link UninitializedSubMemoryBlock} - (not used) 0</li>
	 * </ul>
	 */
	public static final int SUB_INT_DATA1_COL = MemoryMapDBAdapterV3.V3_SUB_INT_DATA1_COL;

	/**
	 * Subblock record long data2 usage:
	 * <ul>
	 * <li>{@link BufferSubMemoryBlock} - (not used) 0</li>
	 * <li>{@link FileBytesSubMemoryBlock} - starting byte offset within file bytes buffer</li>
	 * <li>{@link ByteMappedSubMemoryBlock} - encoded mapped source address</li>
	 * <li>{@link BitMappedSubMemoryBlock} - encoded mapped source address</li>
	 * <li>{@link UninitializedSubMemoryBlock} - (not used) 0</li>
	 * </ul>
	 */
	public static final int SUB_LONG_DATA2_COL = MemoryMapDBAdapterV3.V3_SUB_LONG_DATA2_COL;

	public static final byte SUB_TYPE_BIT_MAPPED = MemoryMapDBAdapterV3.V3_SUB_TYPE_BIT_MAPPED;
	public static final byte SUB_TYPE_BYTE_MAPPED = MemoryMapDBAdapterV3.V3_SUB_TYPE_BYTE_MAPPED;
	public static final byte SUB_TYPE_BUFFER = MemoryMapDBAdapterV3.V3_SUB_TYPE_BUFFER;
	public static final byte SUB_TYPE_UNITIALIZED = MemoryMapDBAdapterV3.V3_SUB_TYPE_UNITIALIZED;
	public static final byte SUB_TYPE_FILE_BYTES = MemoryMapDBAdapterV3.V3_SUB_TYPE_FILE_BYTES;

	static MemoryMapDBAdapter getAdapter(DBHandle handle, int openMode, MemoryMapDB memMap,
			TaskMonitor monitor) throws VersionException, IOException {

		if (openMode == DBConstants.CREATE) {
			return new MemoryMapDBAdapterV3(handle, memMap, Memory.GBYTE, true);
		}
		try {
			return new MemoryMapDBAdapterV3(handle, memMap, Memory.GBYTE, false);
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			MemoryMapDBAdapter adapter = findReadOnlyAdapter(handle, memMap);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(handle, adapter, memMap, monitor);
			}
			return adapter;
		}
	}

	static MemoryMapDBAdapter findReadOnlyAdapter(DBHandle handle, MemoryMapDB memMap)
			throws VersionException, IOException {
		try {
			return new MemoryMapDBAdapterV2(handle, memMap);
		}
		catch (VersionException e) {
			// try next oldest version
		}
		try {
			return new MemoryMapDBAdapterV1(handle, memMap);
		}
		catch (VersionException e) {
			// try next oldest version
		}
		return new MemoryMapDBAdapterV0(handle, memMap);
	}

	static MemoryMapDBAdapter upgrade(DBHandle handle, MemoryMapDBAdapter oldAdapter,
			MemoryMapDB memMap, TaskMonitor monitor) throws VersionException, IOException {

		try {
			monitor.setMessage("Upgrading Memory Blocks...");
			List<MemoryBlockDB> blocks = oldAdapter.getMemoryBlocks();
			oldAdapter.deleteTable(handle);

			monitor.initialize(blocks.size() * 2);

			MemoryMapDBAdapter newAdapter =
				new MemoryMapDBAdapterV3(handle, memMap, Memory.GBYTE, true);
			for (MemoryBlockDB block : blocks) {
				MemoryBlock newBlock = null;
				if (block.isInitialized()) {
					DBBuffer buf = block.getBuffer();
					newBlock = newAdapter.createInitializedBlock(block.getName(), block.getStart(),
						buf, block.getPermissions());
				}
				else {
					Address mappedAddress = null;

					if (block.isMapped()) {
						MemoryBlockSourceInfo info = block.getSourceInfos().get(0);
						mappedAddress = info.getMappedRange().get().getMinAddress();
					}
					newBlock =
						newAdapter.createBlock(block.getType(), block.getName(), block.getStart(),
							block.getSize(), mappedAddress, false, block.getPermissions(), 0);
				}
				newBlock.setComment(block.getComment());
				newBlock.setSourceName(block.getSourceName());
			}
			newAdapter.refreshMemory();
			return newAdapter;
		}
		catch (AddressOverflowException e) {
			// This should not occur
			throw new AssertException(e);
		}
	}

	/**
	 * Returns a DBBuffer object for the given database buffer id
	 * @param bufferID the id of the first buffer in the DBBuffer.
	 * @return the DBBuffer for the given id.
	 * @throws IOException if a database IO error occurs.
	 */
	abstract DBBuffer getBuffer(int bufferID) throws IOException;

	abstract void deleteTable(DBHandle handle) throws IOException;

	/**
	 * 
	 * @throws IOException if a database IO error occurs.
	 */
	abstract void refreshMemory() throws IOException;

	/**
	 * Returns an array of memory blocks sorted on start Address
	 * @return  all the memory blocks
	 */
	abstract List<MemoryBlockDB> getMemoryBlocks();

	/**
	 * Creates a new initialized block object using data provided from an 
	 * input stream.  Once the input stream has been exhausted, the remaining 
	 * block data will be initialized to zero (0x00).
	 * @param name the name of the block
	 * @param startAddr the start address of the block.
	 * @param is data source or null for zero initialization
	 * @param length size of block
	 * @param permissions the new block permissions
	 * @return new memory block
	 * @throws IOException
	 * @throws AddressOverflowException if block length is too large for the underlying space
	 */
	abstract MemoryBlockDB createInitializedBlock(String name, Address startAddr, InputStream is,
			long length, int permissions) throws AddressOverflowException, IOException;

	/**
	 * Creates a new initialized block object
	 * @param name the name of the block
	 * @param startAddr the start address of the block.
	 * @param buf the DBBuffer used to hold the bytes for the block.
	 * @param permissions the new block permissions
	 * @return new memory block
	 * @throws IOException if a database IO error occurs.
	 * @throws AddressOverflowException if block length is too large for the underlying space
	 */
	abstract MemoryBlockDB createInitializedBlock(String name, Address startAddr, DBBuffer buf,
			int permissions) throws AddressOverflowException, IOException;

	/**
	 * Creates a new memory block that doesn't have associated bytes.
	 * @param blockType the type of block to create.
	 * @param name the name of the block.
	 * @param startAddr the start address of the block
	 * @param length the size of the block
	 * @param mappedAddress the starting byte source address at which to map 
	 * the block. (used for bit/byte-mapped blocks only)
	 * @param initializeBytes if true, creates a database buffer for storing the 
	 * bytes in the block (applies to initialized default blocks only)
	 * @param permissions the new block permissions
	 * @param encodedMappingScheme byte mapping scheme (used by byte-mapped blocks only)
	 * @return new memory block
	 * @throws IOException if a database IO error occurs.
	 * @throws AddressOverflowException if block length is too large for the underlying space
	 */
	abstract MemoryBlockDB createBlock(MemoryBlockType blockType, String name, Address startAddr,
			long length, Address mappedAddress, boolean initializeBytes, int permissions,
			int encodedMappingScheme) throws AddressOverflowException, IOException;

	/**
	 * Deletes the given memory block.
	 * @param key the key for the memory block record
	 * @throws IOException if a database IO error occurs.
	 */
	abstract void deleteMemoryBlock(long key) throws IOException;

	/**
	 * Updates the memory block record.
	 * @param record the record to update.
	 * @throws IOException if a database IO error occurs.
	 */
	abstract void updateBlockRecord(DBRecord record) throws IOException;

	/**
	 * Creates a new DBuffer object with the given length and initial value.
	 * @param length block/chunk buffer length (length limited by ChainedBuffer implementation)
	 * @param initialValue fill value
	 * @return a new DBuffer object with the given length and initial value.
	 * @throws IOException if a database IO error occurs.
	 */
	abstract DBBuffer createBuffer(int length, byte initialValue) throws IOException;

	/**
	 * Returns the MemoryMap that owns this adapter.
	 * @return  the MemoryMap that owns this adapter.
	 */
	abstract MemoryMapDB getMemoryMap();

	/**
	 * Deletes the sub block record for the given key.
	 * @param key the record id of the sub block record to delete.
	 * @throws IOException if a database error occurs.
	 */
	abstract void deleteSubBlock(long key) throws IOException;

	/**
	 * Updates the sub memory block record.
	 * @param record the record to update.
	 * @throws IOException if a database IO error occurs.
	 */
	protected abstract void updateSubBlockRecord(DBRecord record) throws IOException;

	/**
	 * Creates a record for a new created sub block
	 * @param memBlockId the id of the memory block that contains this sub block
	 * @param startingOffset the starting offset relative to the containing memory block where this
	 * sub block starts
	 * @param length the length of this sub block
	 * @param subType the type of the subBlock
	 * @param data1 subblock implementation specific integer data 
	 * @param data2 subblock implementation specific long data 
	 * @return the newly created record.
	 * @throws IOException if a database error occurs
	 */
	abstract DBRecord createSubBlockRecord(long memBlockId, long startingOffset, long length,
			byte subType, int data1, long data2) throws IOException;

	/**
	 * Creates a new memory block.
	 * @param name the name of the block
	 * @param startAddress the start address of the block
	 * @param length the length of the block
	 * @param permissions the permissions for the block
	 * @param splitBlocks the list of subBlock objects that make up this block
	 * @return the new MemoryBlock
	 * @throws IOException if a database error occurs
	 */
	protected abstract MemoryBlockDB createBlock(String name, Address startAddress, long length,
			int permissions, List<SubMemoryBlock> splitBlocks) throws IOException;

	/**
	 * Creates a new memory block using a FileBytes
	 * @param name the name of the block
	 * @param startAddress the start address of the block
	 * @param length the length of the block
	 * @param fileBytes the {@link FileBytes} object that provides the bytes for this block
	 * @param offset the offset into the {@link FileBytes} object
	 * @param permissions the permissions for the block
	 * @return the new MemoryBlock
	 * @throws IOException if a database error occurs
	 * @throws AddressOverflowException if block length is too large for the underlying space
	 */
	protected abstract MemoryBlockDB createFileBytesBlock(String name, Address startAddress,
			long length, FileBytes fileBytes, long offset, int permissions)
			throws IOException, AddressOverflowException;
}
