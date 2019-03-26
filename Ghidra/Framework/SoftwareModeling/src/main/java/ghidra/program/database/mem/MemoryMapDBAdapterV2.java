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
import java.util.Arrays;

import db.*;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.util.exception.IOCancelledException;
import ghidra.util.exception.VersionException;

class MemoryMapDBAdapterV2 extends MemoryMapDBAdapter {

	private static final int VERSION = CURRENT_VERSION;

	private DBHandle handle;
	private Table blockTable;
	private MemoryMapDB memMap;
	private AddressMap addrMap;
	private MemoryBlockDB[] blocks = new MemoryBlockDB[0];

	MemoryMapDBAdapterV2(DBHandle handle, MemoryMapDB memMap, boolean create)
			throws VersionException, IOException {
		this.handle = handle;
		this.memMap = memMap;
		this.addrMap = memMap.getAddressMap();
		if (create) {
			blockTable = handle.createTable(TABLE_NAME, BLOCK_SCHEMA);
		}
		else {
			blockTable = handle.getTable(TABLE_NAME);
			if (blockTable == null) {
				throw new VersionException(
					handle.getTable(MemoryMapDBAdapterV0.V0_TABLE_NAME) != null);
			}
			if (blockTable.getSchema().getVersion() != VERSION) {
				int version = blockTable.getSchema().getVersion();
				throw new VersionException(version < VERSION);
			}
//			refreshMemory();
		}
	}

	/**
	 * @see ghidra.program.database.mem.MemoryMapDBAdapter#refreshMemory()
	 */
	@Override
	void refreshMemory() throws IOException {
		MemoryBlockDB[] updatedBlocks = new MemoryBlockDB[blockTable.getRecordCount()];
		RecordIterator it = blockTable.iterator();
		int index = 0;
		while (it.hasNext()) {
			Record blockRec = it.next();
			long key = blockRec.getKey();
			for (int n = 0; n < blocks.length; n++) {
				if (blocks[n] != null && blocks[n].getID() == key) {
					updatedBlocks[index] = blocks[n];
					updatedBlocks[index].refresh(blockRec);
					blocks[n] = null;
					break;
				}
			}
			if (updatedBlocks[index] == null) {
				updatedBlocks[index] =
					MemoryMapDBAdapter.getMemoryBlock(this, blockRec, null, memMap);
			}
			++index;
		}
		for (int i = 0; i < blocks.length; i++) {
			if (blocks[i] != null) {
				blocks[i].invalidate();
			}
		}
		Arrays.sort(updatedBlocks);
		blocks = updatedBlocks;
	}

	/**
	 * @see ghidra.program.database.mem.MemoryMapDBAdapter#getMemoryBlocks()
	 */
	@Override
	MemoryBlockDB[] getMemoryBlocks() {
		return blocks;
	}

	private int getSegment(Address addr) {
		if (addr instanceof SegmentedAddress) {
//			SegmentedAddress imageBase = (SegmentedAddress)addrMap.getImageBase();
//			int baseSegment = imageBase.getSegment();
			return ((SegmentedAddress) addr).getSegment();
		}
		return 0;
	}

	/**
	 * @see ghidra.program.database.mem.MemoryMapDBAdapter#createBlock(java.lang.String, ghidra.program.model.address.Address, db.DBBuffer)
	 */
	@Override
	MemoryBlockDB createInitializedBlock(String name, Address startAddr, DBBuffer buf,
			int permissions) throws AddressOverflowException, IOException {

		// Ensure that address key has been generated for end address
		Address endAddr = startAddr.addNoWrap(buf.length() - 1);
		addrMap.getKey(endAddr, true);

		int blockID = (int) blockTable.getKey();
		Record blockRec = BLOCK_SCHEMA.createRecord(blockID);
		blockRec.setString(MemoryMapDBAdapter.NAME_COL, name);
		blockRec.setByteValue(MemoryMapDBAdapter.PERMISSIONS_COL, (byte) permissions);
		blockRec.setLongValue(MemoryMapDBAdapter.START_ADDR_COL, addrMap.getKey(startAddr, true));
		blockRec.setShortValue(MemoryMapDBAdapter.BLOCK_TYPE_COL, (short) INITIALIZED);
		blockRec.setIntValue(MemoryMapDBAdapter.CHAIN_BUF_COL, buf.getId());
		blockRec.setLongValue(MemoryMapDBAdapter.LENGTH_COL, buf.length());
		blockRec.setIntValue(MemoryMapDBAdapter.SEGMENT_COL, getSegment(startAddr));

		blockTable.putRecord(blockRec);

		return new MemoryBlockDB(this, blockRec, buf, memMap);
	}

	/** 
	 * @see ghidra.program.database.mem.MemoryMapDBAdapter#createInitializedBlock(java.lang.String, ghidra.program.model.address.Address, java.io.InputStream, long)
	 */
	@Override
	MemoryBlockDB createInitializedBlock(String name, Address startAddr, InputStream is,
			long length, int permissions) throws AddressOverflowException, IOException {

		// Ensure that address key has been generated for end address
		Address endAddr = startAddr.addNoWrap(length - 1);
		addrMap.getKey(endAddr, true);

		int blockID = (int) blockTable.getKey();
		Record blockRec = BLOCK_SCHEMA.createRecord(blockID);
		blockRec.setString(MemoryMapDBAdapter.NAME_COL, name);
		blockRec.setByteValue(MemoryMapDBAdapter.PERMISSIONS_COL, (byte) permissions);
		blockRec.setLongValue(MemoryMapDBAdapter.START_ADDR_COL, addrMap.getKey(startAddr, true));
		blockRec.setShortValue(MemoryMapDBAdapter.BLOCK_TYPE_COL, (short) INITIALIZED);
		blockRec.setLongValue(MemoryMapDBAdapter.LENGTH_COL, length);
		blockRec.setIntValue(MemoryMapDBAdapter.SEGMENT_COL, getSegment(startAddr));
		DBBuffer buf = createBuffer(length, is);

		blockRec.setIntValue(MemoryMapDBAdapter.CHAIN_BUF_COL, buf.getId());

		blockTable.putRecord(blockRec);
		return MemoryMapDBAdapter.getMemoryBlock(this, blockRec, buf, memMap);
	}

	/**
	 * @see ghidra.program.database.mem.MemoryMapDBAdapter#createBlock(int, java.lang.String, ghidra.program.database.mem2.MemoryChunkDB[], ghidra.program.model.address.Address)
	 */
	@Override
	MemoryBlockDB createBlock(MemoryBlockType blockType, String name, Address startAddr,
			long length, Address mappedAddress, boolean initializeBytes, int permissions)
			throws AddressOverflowException, IOException {
		if (initializeBytes) {
			return createInitializedBlock(name, startAddr, null, length, permissions);
		}

		// Ensure that address key has been generated for end address
		Address endAddr = startAddr.addNoWrap(length - 1);
		addrMap.getKey(endAddr, true);

		int blockID = (int) blockTable.getKey();
		Record blockRec = BLOCK_SCHEMA.createRecord(blockID);
		blockRec.setString(MemoryMapDBAdapter.NAME_COL, name);
		blockRec.setByteValue(MemoryMapDBAdapter.PERMISSIONS_COL, (byte) permissions);
		blockRec.setLongValue(MemoryMapDBAdapter.START_ADDR_COL, addrMap.getKey(startAddr, true));
		blockRec.setShortValue(MemoryMapDBAdapter.BLOCK_TYPE_COL,
			(short) encodeBlockType(blockType));
		blockRec.setLongValue(MemoryMapDBAdapter.LENGTH_COL, length);
		blockRec.setIntValue(MemoryMapDBAdapter.SEGMENT_COL, getSegment(startAddr));
		blockRec.setIntValue(MemoryMapDBAdapter.CHAIN_BUF_COL, -1);
		if (mappedAddress != null) {
			blockRec.setLongValue(MemoryMapDBAdapter.OVERLAY_ADDR_COL,
				addrMap.getKey(mappedAddress, true));
		}

		blockTable.putRecord(blockRec);
		return MemoryMapDBAdapter.getMemoryBlock(this, blockRec, null, memMap);
	}

	private int encodeBlockType(MemoryBlockType blockType) {
		if (blockType == MemoryBlockType.BIT_MAPPED) {
			return BIT_MAPPED;
		}
		if (blockType == MemoryBlockType.BYTE_MAPPED) {
			return BYTE_MAPPED;
		}
		return UNINITIALIZED;
	}

	private DBBuffer createBuffer(long length, InputStream is) throws IOException {

		DBBuffer buf = handle.createBuffer((int) length);
		if (is != null) {
			try {
				buf.fill(is);
			}
			catch (IOCancelledException e) {
				buf.delete();
				throw e;
			}
		}
		return buf;
	}

	/**
	 * @see ghidra.program.database.mem.MemoryMapDBAdapter#splitBlock(ghidra.program.database.mem2.MemoryBlockDB, long)
	 */
	@Override
	MemoryBlockDB splitBlock(MemoryBlockDB block, long offset) throws IOException {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * @see ghidra.program.database.mem.MemoryMapDBAdapter#joinBlocks(ghidra.program.database.mem2.MemoryBlockDB, ghidra.program.database.mem2.MemoryBlockDB)
	 */
	@Override
	MemoryBlockDB joinBlocks(MemoryBlockDB block1, MemoryBlockDB block2) throws IOException {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * @see ghidra.program.database.mem.MemoryMapDBAdapter#deleteMemoryBlock(ghidra.program.model.mem.MemoryBlock)
	 */
	@Override
	void deleteMemoryBlock(MemoryBlockDB block) throws IOException {
		blockTable.deleteRecord(block.getID());
		block.invalidate();
	}

	/**
	 * @see ghidra.program.database.mem.MemoryMapDBAdapter#deleteTable(db.DBHandle)
	 */
	@Override
	void deleteTable(DBHandle dbHandle) throws IOException {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.mem.MemoryMapDBAdapter#updateBlockRecord(db.Record)
	 */
	@Override
	void updateBlockRecord(Record record) throws IOException {
		blockTable.putRecord(record);
	}

	/**
	 * @see ghidra.program.database.mem.MemoryMapDBAdapter#createBuffer(int, byte)
	 */
	@Override
	DBBuffer createBuffer(int length, byte initialValue) throws IOException {
		DBBuffer buffer = handle.createBuffer(length);
		buffer.fill(0, length - 1, initialValue);
		return buffer;
	}

	/**
	 * @see ghidra.program.database.mem.MemoryMapDBAdapter#getBuffer(int)
	 */
	@Override
	DBBuffer getBuffer(int bufferID) throws IOException {
		if (bufferID >= 0) {
			return handle.getBuffer(bufferID);
		}
		return null;
	}

}
