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
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.util.exception.VersionException;

/**
 * Adapter for version 0
 */
class MemoryMapDBAdapterV0 extends MemoryMapDBAdapter {

	static final String V0_TABLE_NAME = "Memory Block";

	private final static int VERSION = 0;

	private final static int V0_NAME_COL = 0;
	private final static int V0_BUFFER_ID_COL = 1;
	private final static int V0_COMMENTS_COL = 2;
	//private final static int V0_DESCRIPTION_COL = 3; // deprecated/ignored column
	private final static int V0_SOURCE_NAME_COL = 4;
	//private final static int V0_SOURCE_OFFSET_COL = 5; // deprecated/ignored column
	private final static int V0_IS_READ_COL = 6;
	private final static int V0_IS_WRITE_COL = 7;
	private final static int V0_IS_EXECUTE_COL = 8;
	private final static int V0_START_ADDR_COL = 9;
	private final static int V0_LENGTH_COL = 10;
	private final static int V0_TYPE_COL = 11;
	private final static int V0_BASE_ADDR_COL = 12;
	//private final static int V0_SOURCE_BLOCK_ID_COL = 13; // deprecated/ignored column
	private final static int V0_SEGMENT_COL = 14;	// added in version 1

	// Enumerated block type values
	private static final int INITIALIZED = 0;
	private static final int UNINITIALIZED = 1;
	private static final int BIT_MAPPED = 2;
	private static final int BYTE_MAPPED = 4;

//  The following schema definition documents the schema used in version 0
//
//	private Schema SCHEMA = new Schema(0, "Key", 
//			new Class[] {StringField.class, 
//			IntField.class, StringField.class,
//			StringField.class, StringField.class,
//			LongField.class, BooleanField.class, 
//			BooleanField.class, BooleanField.class,
//			LongField.class, IntField.class, 
//			ShortField.class, LongField.class,
//			LongField.class}, 
//		new String[] {"Name", "Chain Buffer ID",
//			"Comments", "Description", "Source Name",
//			"Source Offset", "Is Read", "Is Write",
//			"Is Execute", "Start Address", "Length",
//			"Block Type", "Base Address", 
//			"Source Block ID"});

	private List<MemoryBlockDB> blocks;
	private DBHandle handle;
	private MemoryMapDB memMap;

	MemoryMapDBAdapterV0(DBHandle handle, MemoryMapDB memMap) throws VersionException, IOException {
		this(handle, memMap, VERSION);
	}

	protected MemoryMapDBAdapterV0(DBHandle handle, MemoryMapDB memMap, int expectedVersion)
			throws VersionException, IOException {
		this.handle = handle;
		this.memMap = memMap;
		AddressMap addrMap = memMap.getAddressMap();
		Table table = handle.getTable(V0_TABLE_NAME);
		if (table == null) {
			throw new VersionException("Memory Block table not found");
		}
		int versionNumber = table.getSchema().getVersion();
		if (versionNumber != expectedVersion) {
			throw new VersionException("Memory Block table: Expected Version " + expectedVersion +
				", got " + versionNumber);
		}
		int recCount = table.getRecordCount();
		blocks = new ArrayList<MemoryBlockDB>(recCount);

		AddressFactory addrFactory = memMap.getAddressFactory();
		int key = 0;

		RecordIterator it = table.iterator();
		while (it.hasNext()) {
			DBRecord rec = it.next();
			int flags = 0;
			if (rec.getBooleanValue(V0_IS_READ_COL)) {
				flags |= MemoryBlock.READ;
			}
			if (rec.getBooleanValue(V0_IS_WRITE_COL)) {
				flags |= MemoryBlock.WRITE;
			}
			if (rec.getBooleanValue(V0_IS_EXECUTE_COL)) {
				flags |= MemoryBlock.EXECUTE;
			}
			Address start = addrFactory.oldGetAddressFromLong(rec.getLongValue(V0_START_ADDR_COL));
			long startAddr = addrMap.getKey(start, false);
			long length = rec.getLongValue(V0_LENGTH_COL);
			int bufID = rec.getIntValue(V0_BUFFER_ID_COL);
			int segment = 0;
			if (expectedVersion == 1 && (start instanceof SegmentedAddress)) {
				segment = rec.getIntValue(V0_SEGMENT_COL); // introduced with V1
			}

			DBRecord blockRecord = BLOCK_SCHEMA.createRecord(key);
			DBRecord subBlockRecord = SUB_BLOCK_SCHEMA.createRecord(key);

			blockRecord.setString(NAME_COL, rec.getString(V0_NAME_COL));
			blockRecord.setString(COMMENTS_COL, rec.getString(V0_COMMENTS_COL));
			blockRecord.setString(SOURCE_COL, rec.getString(V0_SOURCE_NAME_COL));
			blockRecord.setByteValue(FLAGS_COL, (byte) flags);
			blockRecord.setLongValue(START_ADDR_COL, startAddr);
			blockRecord.setLongValue(LENGTH_COL, length);
			blockRecord.setIntValue(SEGMENT_COL, segment);

			subBlockRecord.setLongValue(SUB_PARENT_ID_COL, key);
			subBlockRecord.setLongValue(SUB_LENGTH_COL, length);
			subBlockRecord.setLongValue(SUB_START_OFFSET_COL, 0);

			int type = rec.getShortValue(V0_TYPE_COL);
			long overlayAddr = rec.getLongValue(V0_BASE_ADDR_COL);
			overlayAddr = updateOverlayAddr(addrMap, addrFactory, overlayAddr, type);

			SubMemoryBlock subBlock = getSubBlock(bufID, subBlockRecord, type, overlayAddr);

			blocks.add(new MemoryBlockDB(this, blockRecord, Arrays.asList(subBlock)));
		}
		Collections.sort(blocks);
	}

	private SubMemoryBlock getSubBlock(int bufID, DBRecord record, int type, long overlayAddr)
			throws IOException {
		switch (type) {
			case BIT_MAPPED:
				record.setByteValue(SUB_TYPE_COL, SUB_TYPE_BIT_MAPPED);
				record.setLongValue(MemoryMapDBAdapter.SUB_LONG_DATA2_COL, overlayAddr);
				return new BitMappedSubMemoryBlock(this, record);
			case BYTE_MAPPED:
				record.setByteValue(SUB_TYPE_COL, SUB_TYPE_BYTE_MAPPED);
				record.setLongValue(MemoryMapDBAdapter.SUB_LONG_DATA2_COL, overlayAddr);
				return new ByteMappedSubMemoryBlock(this, record);
			case INITIALIZED:
				record.setByteValue(SUB_TYPE_COL, SUB_TYPE_BUFFER);
				record.setIntValue(SUB_INT_DATA1_COL, bufID);
				return new BufferSubMemoryBlock(this, record);
			case UNINITIALIZED:
				record.setByteValue(SUB_TYPE_COL, SUB_TYPE_UNINITIALIZED);
				return new UninitializedSubMemoryBlock(this, record);
			default:
				throw new IOException("Unknown memory block type: " + type);
		}
	}

	private long updateOverlayAddr(AddressMap addrMap, AddressFactory addrFactory, long overlayAddr,
			int type) {
		if (type == BIT_MAPPED || type == BYTE_MAPPED) {
			Address ov = addrFactory.oldGetAddressFromLong(overlayAddr);
			overlayAddr = addrMap.getKey(ov, false);
		}
		return overlayAddr;
	}

	@Override
	void refreshMemory() throws IOException {
		// do nothing
	}

	@Override
	List<MemoryBlockDB> getMemoryBlocks() {
		return blocks;
	}

	@Override
	MemoryBlockDB createInitializedBlock(String name, Address startAddr, InputStream is,
			long length, int flags) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	MemoryBlockDB createInitializedBlock(String name, Address startAddr, DBBuffer buf, int flags)
			throws IOException {
		throw new UnsupportedOperationException();
	}

	void setBlockSize(MemoryBlockDB block, long size) {
		throw new UnsupportedOperationException();
	}

	@Override
	void deleteMemoryBlock(MemoryBlockDB block) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	void deleteTable(DBHandle dbHandle) throws IOException {
		dbHandle.deleteTable(V0_TABLE_NAME);
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
	MemoryBlockDB createBlock(MemoryBlockType blockType, String name, Address startAddr,
			long length, Address overlayAddr, boolean initializeBytes, int flags, int mappingScheme)
			throws IOException {
		throw new UnsupportedOperationException();
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
	protected MemoryBlockDB createBlock(String name, Address addr, long length, int flags,
			List<SubMemoryBlock> splitBlocks) {
		throw new UnsupportedOperationException();
	}

	@Override
	protected MemoryBlockDB createFileBytesBlock(String name, Address startAddress, long length,
			FileBytes fileBytes, long offset, int flags)
			throws IOException, AddressOverflowException {
		throw new UnsupportedOperationException();
	}

}
