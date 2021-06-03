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
import java.util.*;

import db.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.util.exception.VersionException;

/**
 * Adapter for version 2
 */
class MemoryMapDBAdapterV2 extends MemoryMapDBAdapter {
	private static final int V2_VERSION = 2;
	static final String V2_TABLE_NAME = "Memory Blocks";

	static final int V2_NAME_COL = 0;
	static final int V2_COMMENTS_COL = 1;
	static final int V2_SOURCE_COL = 2;
	static final int V2_PERMISSIONS_COL = 3;
	static final int V2_START_ADDR_COL = 4;
	static final int V2_BLOCK_TYPE_COL = 5;
	static final int V2_OVERLAY_ADDR_COL = 6;
	static final int V2_LENGTH_COL = 7;
	static final int V2_CHAIN_BUF_COL = 8;
	static final int V2_SEGMENT_COL = 9;

	static final int INITIALIZED = 0;
	static final int UNINITIALIZED = 1;
	static final int BIT_MAPPED = 2;
	static final int BYTE_MAPPED = 4;

	private DBHandle handle;
	private MemoryMapDB memMap;

	private List<MemoryBlockDB> blocks = new ArrayList<>();

//  The following schema definition documents the schema used in version 2No  	
//	
//	static Schema BLOCK_SCHEMA = new Schema(CURRENT_VERSION, "Key",
//		new Class[] { StringField.class, StringField.class, StringField.class, ByteField.class,
//			LongField.class, ShortField.class, LongField.class, LongField.class, IntField.class,
//			IntField.class },
//		new String[] { "Name", "Comments", "Source Name", "Permissions", "Start Address",
//			"Block Type", "Overlay Address", "Length", "Chain Buffer ID", "Segment" });


	protected MemoryMapDBAdapterV2(DBHandle handle, MemoryMapDB memMap)
			throws VersionException, IOException {
		this.handle = handle;
		this.memMap = memMap;
		Table table = handle.getTable(V2_TABLE_NAME);
		if (table == null) {
			throw new VersionException("Memory Block table not found");
		}
		int versionNumber = table.getSchema().getVersion();
		if (versionNumber != V2_VERSION) {
			throw new VersionException(
				"Memory Block table: Expected Version " + V2_VERSION + ", got " + versionNumber);
		}

		int recCount = table.getRecordCount();
		blocks = new ArrayList<>(recCount);

		int key = 0;

		RecordIterator it = table.iterator();
		while (it.hasNext()) {
			DBRecord rec = it.next();
			int permissions = rec.getByteValue(V2_PERMISSIONS_COL);

			long startAddr = rec.getLongValue(V2_START_ADDR_COL);
			long length = rec.getLongValue(V2_LENGTH_COL);
			int bufID = rec.getIntValue(V2_CHAIN_BUF_COL);
			int segment = rec.getIntValue(V2_SEGMENT_COL);

			DBRecord blockRecord = BLOCK_SCHEMA.createRecord(key);
			DBRecord subBlockRecord = SUB_BLOCK_SCHEMA.createRecord(key);

			blockRecord.setString(NAME_COL, rec.getString(V2_NAME_COL));
			blockRecord.setString(COMMENTS_COL, rec.getString(V2_COMMENTS_COL));
			blockRecord.setString(SOURCE_COL, rec.getString(V2_SOURCE_COL));
			blockRecord.setByteValue(PERMISSIONS_COL, (byte) permissions);
			blockRecord.setLongValue(START_ADDR_COL, startAddr);
			blockRecord.setLongValue(LENGTH_COL, length);
			blockRecord.setIntValue(SEGMENT_COL, segment);

			subBlockRecord.setLongValue(SUB_PARENT_ID_COL, key);
			subBlockRecord.setLongValue(SUB_LENGTH_COL, length);
			subBlockRecord.setLongValue(SUB_START_OFFSET_COL, 0);

			int type = rec.getShortValue(V2_BLOCK_TYPE_COL);
			long overlayAddr = rec.getLongValue(V2_OVERLAY_ADDR_COL);

			SubMemoryBlock subBlock = getSubBlock(bufID, subBlockRecord, type, overlayAddr);

			blocks.add(new MemoryBlockDB(this, blockRecord, Arrays.asList(subBlock)));

		}
		Collections.sort(blocks);

	}

	private SubMemoryBlock getSubBlock(int bufID, DBRecord record, int type, long overlayAddr)
			throws IOException {
		switch (type) {
			case MemoryMapDBAdapterV2.BIT_MAPPED:
				record.setByteValue(SUB_TYPE_COL, SUB_TYPE_BIT_MAPPED);
				record.setLongValue(MemoryMapDBAdapter.SUB_LONG_DATA2_COL, overlayAddr);
				return new BitMappedSubMemoryBlock(this, record);
			case MemoryMapDBAdapterV2.BYTE_MAPPED:
				record.setByteValue(SUB_TYPE_COL, SUB_TYPE_BYTE_MAPPED);
				record.setLongValue(MemoryMapDBAdapter.SUB_LONG_DATA2_COL, overlayAddr);
				return new ByteMappedSubMemoryBlock(this, record);
			case MemoryMapDBAdapterV2.INITIALIZED:
				record.setByteValue(SUB_TYPE_COL, SUB_TYPE_BUFFER);
				record.setIntValue(SUB_INT_DATA1_COL, bufID);
				return new BufferSubMemoryBlock(this, record);
			case MemoryMapDBAdapterV2.UNINITIALIZED:
				record.setByteValue(SUB_TYPE_COL, SUB_TYPE_UNITIALIZED);
				return new UninitializedSubMemoryBlock(this, record);
			default:
				throw new IOException("Unknown memory block type: " + type);
		}
	}

	@Override
	List<MemoryBlockDB> getMemoryBlocks() {
		return blocks;
	}

	@Override
	MemoryBlockDB createInitializedBlock(String name, Address startAddr, DBBuffer buf,
			int permissions) throws AddressOverflowException, IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	MemoryBlockDB createInitializedBlock(String name, Address startAddr, InputStream is,
			long length, int permissions) throws AddressOverflowException, IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	MemoryBlockDB createBlock(MemoryBlockType blockType, String name, Address startAddr,
			long length, Address mappedAddress, boolean initializeBytes, int permissions,
			int mappingScheme)
			throws AddressOverflowException, IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	void deleteMemoryBlock(long key) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	void deleteTable(DBHandle dbHandle) throws IOException {
		dbHandle.deleteTable(V2_TABLE_NAME);
	}

	@Override
	void updateBlockRecord(DBRecord record) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	DBBuffer createBuffer(int length, byte initialValue) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	void refreshMemory() throws IOException {
		// do nothing
	}

	@Override
	DBBuffer getBuffer(int bufferID) throws IOException {
		if (bufferID >= 0) {
			return handle.getBuffer(bufferID);
		}
		return null;
	}

	@Override
	MemoryMapDB getMemoryMap() {
		return memMap;
	}

	@Override
	void deleteSubBlock(long key) {
		throw new UnsupportedOperationException();
	}

	@Override
	protected void updateSubBlockRecord(DBRecord record) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	DBRecord createSubBlockRecord(long memBlockId, long startingOffset, long length, byte subType,
			int data1, long data2) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	protected MemoryBlockDB createBlock(String name, Address addr, long length, int permissions,
			List<SubMemoryBlock> splitBlocks) {
		throw new UnsupportedOperationException();
	}

	@Override
	protected MemoryBlockDB createFileBytesBlock(String name, Address startAddress, long length,
			FileBytes fileBytes, long offset, int permissions)
			throws IOException, AddressOverflowException {
		throw new UnsupportedOperationException();
	}

}
