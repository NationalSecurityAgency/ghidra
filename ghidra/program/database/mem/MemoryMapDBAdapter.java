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

import db.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.mem.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

abstract class MemoryMapDBAdapter {

	static final String TABLE_NAME = "Memory Blocks";

	static final int CURRENT_VERSION = 2;

	static Schema BLOCK_SCHEMA = new Schema(CURRENT_VERSION, "Key",
		new Class[] { StringField.class, StringField.class, StringField.class, ByteField.class,
			LongField.class, ShortField.class, LongField.class, LongField.class, IntField.class,
			IntField.class },
		new String[] { "Name", "Comments", "Source Name", "Permissions", "Start Address",
			"Block Type", "Overlay Address", "Length", "Chain Buffer ID", "Segment" });

	static final int NAME_COL = 0;
	static final int COMMENTS_COL = 1;
	static final int SOURCE_COL = 2;
	static final int PERMISSIONS_COL = 3;
	static final int START_ADDR_COL = 4;
	static final int BLOCK_TYPE_COL = 5;
	static final int OVERLAY_ADDR_COL = 6;
	static final int LENGTH_COL = 7;
	static final int CHAIN_BUF_COL = 8;
	static final int SEGMENT_COL = 9;

	static final int INITIALIZED = 0;
	static final int UNINITIALIZED = 1;
	static final int BIT_MAPPED = 2;
	static final int BYTE_MAPPED = 4;

	static MemoryMapDBAdapter getAdapter(DBHandle handle, int openMode, MemoryMapDB memMap,
			TaskMonitor monitor) throws VersionException, IOException {

		if (openMode == DBConstants.CREATE) {
			return new MemoryMapDBAdapterV2(handle, memMap, true);
		}
		try {
			return new MemoryMapDBAdapterV2(handle, memMap, false);
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
			return new MemoryMapDBAdapterV1(handle, memMap);
		}
		catch (VersionException e) {
		}
		return new MemoryMapDBAdapterV0(handle, memMap);
	}

	static MemoryMapDBAdapter upgrade(DBHandle handle, MemoryMapDBAdapter oldAdapter,
			MemoryMapDB memMap, TaskMonitor monitor) throws VersionException, IOException {

		try {
			monitor.setMessage("Upgrading Memory Blocks...");
			MemoryBlockDB[] blocks = oldAdapter.getMemoryBlocks();
			monitor.initialize(blocks.length * 2);

			MemoryMapDBAdapter newAdapter = new MemoryMapDBAdapterV2(handle, memMap, true);
			for (int i = 0; i < blocks.length; i++) {
				MemoryBlockDB block = blocks[i];
				MemoryBlock newBlock = null;
				if (blocks[i].isInitialized()) {
					DBBuffer buf = block.getBuffer();
					newBlock = newAdapter.createInitializedBlock(block.getName(), block.getStart(),
						buf, MemoryBlock.READ);
				}
				else {
					Address mappedAddress = null;
					MemoryBlockType type = block.getType();
					if (type == MemoryBlockType.BIT_MAPPED || type == MemoryBlockType.BYTE_MAPPED) {
						mappedAddress = ((MappedMemoryBlock) block).getOverlayedMinAddress();
					}
					newBlock = newAdapter.createBlock(block.getType(), block.getName(),
						block.getStart(), block.getSize(), mappedAddress, false, MemoryBlock.READ);
				}
				newBlock.setComment(block.getComment());
				newBlock.setSourceName(block.getSourceName());
				if (block.isExecute()) {
					newBlock.setExecute(true);
				}
				if (block.isWrite()) {
					newBlock.setWrite(true);
				}
				if (block.isVolatile()) {
					newBlock.setVolatile(true);
				}
			}
			oldAdapter.deleteTable(handle);
			newAdapter.refreshMemory();
			return newAdapter;
		}
		catch (AddressOverflowException e) {
			// This should not occur
			throw new AssertException(e);
		}
	}

	static MemoryBlockDB getMemoryBlock(MemoryMapDBAdapter adapter, Record record, DBBuffer buf,
			MemoryMapDB memMap) throws IOException {

		int blockType = record.getShortValue(MemoryMapDBAdapter.BLOCK_TYPE_COL);
		switch (blockType) {
			case INITIALIZED:
			case UNINITIALIZED:
				return new MemoryBlockDB(adapter, record, buf, memMap);
			case BIT_MAPPED:
			case BYTE_MAPPED:
				return new OverlayMemoryBlockDB(adapter, record, memMap);
		}
		throw new IllegalStateException("Bad block type");
	}

	abstract void deleteTable(DBHandle handle) throws IOException;

	/**
	 * 
	 * @throws IOException if a database IO error occurs.
	 */
	abstract void refreshMemory() throws IOException;

	/**
	 * Returns an array of memory blocks sorted on start Address
	 */
	abstract MemoryBlockDB[] getMemoryBlocks();

	/**
	 * Creates a new initialized block object using data provided from an 
	 * input stream.  Once the input stream has been exhausted, the remaining 
	 * block data will be initialized to zero (0x00).
	 * @param name the name of the block
	 * @param startAddr the start address of the block.
	 * @param is data source
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
	 * @param mappedAddress the address at which to overlay this block. (If the type is overlay)
	 * @param initializeBytes if true, creates a database buffer for the bytes in the block
	 * @param permissions the new block permissions
	 * @return new memory block
	 * @throws IOException if a database IO error occurs.
	 * @throws AddressOverflowException if block length is too large for the underlying space
	 */
	abstract MemoryBlockDB createBlock(MemoryBlockType blockType, String name, Address startAddr,
			long length, Address mappedAddress, boolean initializeBytes, int permissions)
			throws AddressOverflowException, IOException;

	/**
	 * Splits a memory block at the given offset and create a new block at the split location.
	 * @param block the the split.
	 * @param offset the offset within the block at which to split off into a new block
	 * @return the new memory block created.
	 * @throws IOException if a database IO error occurs.
	 */
	abstract MemoryBlockDB splitBlock(MemoryBlockDB block, long offset) throws IOException;

	/**
	 * Combines two memory blocks into one.
	 * @param block1 the first block 
	 * @param block2 the second block
	 * @return the block that contains the bytes of block1 and block2.
	 * @throws IOException if a database IO error occurs.
	 */
	abstract MemoryBlockDB joinBlocks(MemoryBlockDB block1, MemoryBlockDB block2)
			throws IOException;

	/**
	 * Deletes the given memory block.
	 * @param block the block to delete.
	 * @throws IOException if a database IO error occurs.
	 */
	abstract void deleteMemoryBlock(MemoryBlockDB block) throws IOException;

	/**
	 * Updates the memory block record.
	 * @param record the record to update.
	 * @throws IOException if a database IO error occurs.
	 */
	abstract void updateBlockRecord(Record record) throws IOException;

	/**
	 * Creates a new DBuffer object with the given length and initial value.
	 * @param length block/chunk buffer length (length limited by ChainedBuffer implementation)
	 * @param initialValue fill value
	 * @throws IOException if a database IO error occurs.
	 */
	abstract DBBuffer createBuffer(int length, byte initialValue) throws IOException;

	/**
	 * Returns a DBBuffer object for the given database buffer id
	 * @param bufferID the id of the first buffer in the DBBuffer.
	 * @throws IOException if a database IO error occurs.
	 */
	abstract DBBuffer getBuffer(int bufferID) throws IOException;

}
