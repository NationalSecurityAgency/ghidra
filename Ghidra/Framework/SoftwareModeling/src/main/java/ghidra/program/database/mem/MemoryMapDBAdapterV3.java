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
import java.util.function.Function;
import java.util.stream.Collectors;

import db.*;
import ghidra.program.database.map.AddressMapDB;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.util.exception.*;

/**
 * MemoryMap adapter for version 3.
 * This version introduces the concept of sub memory blocks and FileBytes
 */
public class MemoryMapDBAdapterV3 extends MemoryMapDBAdapter {
	private static final int V3_VERSION = 3;
	private static final String TABLE_NAME = "Memory Blocks";
	private static final String SUB_BLOCK_TABLE_NAME = "Sub Memory Blocks";

	static final int V3_NAME_COL = 0;
	static final int V3_COMMENTS_COL = 1;
	static final int V3_SOURCE_COL = 2;
	static final int V3_FLAGS_COL = 3;
	static final int V3_START_ADDR_COL = 4;
	static final int V3_LENGTH_COL = 5;
	static final int V3_SEGMENT_COL = 6;

	static final int V3_SUB_PARENT_ID_COL = 0;
	static final int V3_SUB_TYPE_COL = 1;
	static final int V3_SUB_LENGTH_COL = 2;
	static final int V3_SUB_START_OFFSET_COL = 3;
	static final int V3_SUB_INT_DATA1_COL = 4;
	static final int V3_SUB_LONG_DATA2_COL = 5;

	static final byte V3_SUB_TYPE_BIT_MAPPED = 0;
	static final byte V3_SUB_TYPE_BYTE_MAPPED = 1;
	static final byte V3_SUB_TYPE_BUFFER = 2;
	static final byte V3_SUB_TYPE_UNINITIALIZED = 3;
	static final byte V3_SUB_TYPE_FILE_BYTES = 4;

	static Schema V3_BLOCK_SCHEMA = new Schema(V3_VERSION, "Key",
		new Field[] { StringField.INSTANCE, StringField.INSTANCE, StringField.INSTANCE,
			ByteField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE, IntField.INSTANCE },
		new String[] { "Name", "Comments", "Source Name", "Flags", "Start Address", "Length",
			"Segment" });

	static Schema V3_SUB_BLOCK_SCHEMA = new Schema(V3_VERSION, "Key",
		new Field[] { LongField.INSTANCE, ByteField.INSTANCE, LongField.INSTANCE,
			LongField.INSTANCE, IntField.INSTANCE, LongField.INSTANCE },
		new String[] { "Parent ID", "Type", "Length", "Starting Offset", "Source ID",
			"Source Address/Offset" });

	private DBHandle handle;

	private Table memBlockTable;
	private Table subBlockTable;
	private MemoryMapDB memMap;
	private AddressMapDB addrMap;

	private List<MemoryBlockDB> memoryBlocks = new ArrayList<>(); // sorted list of blocks
	private long maxSubBlockSize;

	public MemoryMapDBAdapterV3(DBHandle handle, MemoryMapDB memMap, long maxSubBlockSize,
			boolean create) throws VersionException, IOException {
		this.handle = handle;
		this.memMap = memMap;
		this.maxSubBlockSize = maxSubBlockSize;
		this.addrMap = memMap.getAddressMap();

		if (create) {
			memBlockTable = handle.createTable(TABLE_NAME, V3_BLOCK_SCHEMA);
			subBlockTable = handle.createTable(SUB_BLOCK_TABLE_NAME, V3_SUB_BLOCK_SCHEMA);
		}
		else {
			memBlockTable = handle.getTable(TABLE_NAME);
			subBlockTable = handle.getTable(SUB_BLOCK_TABLE_NAME);

			if (memBlockTable == null) {
				// the table name changed going from V1 to V2
				throw new VersionException(
					handle.getTable(MemoryMapDBAdapterV0.V0_TABLE_NAME) != null);
			}
			if (subBlockTable == null || memBlockTable.getSchema().getVersion() != V3_VERSION) {
				int version = memBlockTable.getSchema().getVersion();
				throw new VersionException(version < V3_VERSION);
			}
		}

	}

	@Override
	void deleteTable(DBHandle dbHandle) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	void refreshMemory() throws IOException {
		Map<Long, List<SubMemoryBlock>> subBlockMap = getSubBlockMap();

		Map<Long, MemoryBlockDB> blockMap = memoryBlocks.stream()
				.collect(Collectors.toMap(MemoryBlockDB::getID, Function.identity()));

		List<MemoryBlockDB> newBlocks = new ArrayList<>();
		RecordIterator it = memBlockTable.iterator();
		while (it.hasNext()) {
			DBRecord record = it.next();
			long key = record.getKey();
			MemoryBlockDB block = blockMap.remove(key);
			if (block != null) {
				block.refresh(record, subBlockMap.get(key));
			}
			else {
				block = new MemoryBlockDB(this, record, subBlockMap.get(key));
			}
			newBlocks.add(block);
		}
		for (MemoryBlockDB block : blockMap.values()) {
			block.invalidate();
		}
		Collections.sort(newBlocks);
		memoryBlocks = newBlocks;
	}

	@Override
	List<MemoryBlockDB> getMemoryBlocks() {
		return memoryBlocks;
	}

	private void cacheNewBlock(MemoryBlockDB newBlock) {
		int insertionIndex = Collections.binarySearch(memoryBlocks, newBlock);
		if (insertionIndex >= 0) {  // should not find direct hit
			throw new AssertException("New memory block collides with existing block");
		}
		memoryBlocks.add(-insertionIndex - 1, newBlock);
	}

	private void removeCachedBlock(MemoryBlockDB deletedBlock) {
		int index = Collections.binarySearch(memoryBlocks, deletedBlock);
		if (index < 0) {  // should not find direct hit
			return;
		}
		memoryBlocks.remove(index);
	}

	@Override
	MemoryBlockDB createInitializedBlock(String name, Address startAddr, InputStream is,
			long length, int flags) throws AddressOverflowException, IOException {

		// TODO verify that it is necessary to pre-define all segments in the address map
		updateAddressMapForAllAddresses(startAddr, length);

		List<SubMemoryBlock> subBlocks = new ArrayList<>();
		try {
			DBRecord blockRecord = createMemoryBlockRecord(name, startAddr, length, flags);
			long key = blockRecord.getKey();
			int numFullBlocks = (int) (length / maxSubBlockSize);
			int lastSubBlockSize = (int) (length % maxSubBlockSize);
			long blockOffset = 0;
			for (int i = 0; i < numFullBlocks; i++) {
				subBlocks.add(createBufferSubBlock(key, blockOffset, maxSubBlockSize, is));
				blockOffset += maxSubBlockSize;
			}
			if (lastSubBlockSize > 0) {
				subBlocks.add(createBufferSubBlock(key, blockOffset, lastSubBlockSize, is));
			}
			memBlockTable.putRecord(blockRecord);

			MemoryBlockDB newBlock = new MemoryBlockDB(this, blockRecord, subBlocks);
			cacheNewBlock(newBlock);
			return newBlock;
		}
		catch (IOCancelledException e) {
			// clean up any created DBBufferss
			for (SubMemoryBlock subMemoryBlock : subBlocks) {
				BufferSubMemoryBlock bufferSubMemoryBlock = (BufferSubMemoryBlock) subMemoryBlock;
				subBlockTable.deleteRecord(bufferSubMemoryBlock.getKey());
				bufferSubMemoryBlock.buf.delete();
			}
			throw e;
		}
	}

	@Override
	MemoryBlockDB createBlock(MemoryBlockType blockType, String name, Address startAddr,
			long length, Address mappedAddress, boolean initializeBytes, int flags,
			int encodedMappingScheme) throws AddressOverflowException, IOException {

		if (blockType == MemoryBlockType.BIT_MAPPED) {
			return createBitMappedBlock(name, startAddr, length, mappedAddress, flags);
		}
		if (blockType == MemoryBlockType.BYTE_MAPPED) {
			return createByteMappedBlock(name, startAddr, length, mappedAddress, flags,
				encodedMappingScheme);
		}
		// DEFAULT block type
		if (initializeBytes) {
			return createInitializedBlock(name, startAddr, null, length, flags);
		}
		return createUninitializedBlock(name, startAddr, length, flags);
	}

	@Override
	MemoryBlockDB createInitializedBlock(String name, Address startAddr, DBBuffer buf, int flags)
			throws AddressOverflowException, IOException {
		updateAddressMapForAllAddresses(startAddr, buf.length());

		List<SubMemoryBlock> subBlocks = new ArrayList<>();
		DBRecord blockRecord = createMemoryBlockRecord(name, startAddr, buf.length(), flags);
		long key = blockRecord.getKey();

		DBRecord subRecord =
			createSubBlockRecord(key, 0, buf.length(), V3_SUB_TYPE_BUFFER, buf.getId(), 0);
		subBlockTable.putRecord(subRecord);
		subBlocks.add(new BufferSubMemoryBlock(this, subRecord));

		memBlockTable.putRecord(blockRecord);
		MemoryBlockDB newBlock = new MemoryBlockDB(this, blockRecord, subBlocks);
		cacheNewBlock(newBlock);
		return newBlock;
	}

	MemoryBlockDB createUninitializedBlock(String name, Address startAddress, long length,
			int flags) throws IOException, AddressOverflowException {
		updateAddressMapForAllAddresses(startAddress, length);

		List<SubMemoryBlock> subBlocks = new ArrayList<>();
		DBRecord blockRecord = createMemoryBlockRecord(name, startAddress, length, flags);
		long key = blockRecord.getKey();

		DBRecord subRecord = createSubBlockRecord(key, 0, length, V3_SUB_TYPE_UNINITIALIZED, 0, 0);
		subBlocks.add(new UninitializedSubMemoryBlock(this, subRecord));

		memBlockTable.putRecord(blockRecord);
		MemoryBlockDB newBlock = new MemoryBlockDB(this, blockRecord, subBlocks);
		cacheNewBlock(newBlock);
		return newBlock;
	}

	@Override
	protected MemoryBlockDB createBlock(String name, Address startAddress, long length, int flags,
			List<SubMemoryBlock> splitBlocks) throws IOException {
		DBRecord blockRecord = createMemoryBlockRecord(name, startAddress, length, flags);
		long key = blockRecord.getKey();

		long startingOffset = 0;
		for (SubMemoryBlock subMemoryBlock : splitBlocks) {
			subMemoryBlock.setParentIdAndStartingOffset(key, startingOffset);
			startingOffset += subMemoryBlock.subBlockLength;
		}

		memBlockTable.putRecord(blockRecord);
		MemoryBlockDB newBlock = new MemoryBlockDB(this, blockRecord, splitBlocks);
		cacheNewBlock(newBlock);
		return newBlock;
	}

	MemoryBlockDB createBitMappedBlock(String name, Address startAddress, long length,
			Address mappedAddress, int flags) throws IOException, AddressOverflowException {
		return createMappedBlock(V3_SUB_TYPE_BIT_MAPPED, name, startAddress, length, mappedAddress,
			flags, 0);
	}

	MemoryBlockDB createByteMappedBlock(String name, Address startAddress, long length,
			Address mappedAddress, int flags, int mappingScheme)
			throws IOException, AddressOverflowException {
		return createMappedBlock(V3_SUB_TYPE_BYTE_MAPPED, name, startAddress, length, mappedAddress,
			flags, mappingScheme);
	}

	@Override
	protected MemoryBlockDB createFileBytesBlock(String name, Address startAddress, long length,
			FileBytes fileBytes, long offset, int flags)
			throws IOException, AddressOverflowException {

		updateAddressMapForAllAddresses(startAddress, length);
		List<SubMemoryBlock> subBlocks = new ArrayList<>();
		DBRecord blockRecord = createMemoryBlockRecord(name, startAddress, length, flags);
		long key = blockRecord.getKey();

		DBRecord subRecord = createSubBlockRecord(key, 0, length, V3_SUB_TYPE_FILE_BYTES,
			(int) fileBytes.getId(), offset);
		subBlocks.add(createSubBlock(subRecord));

		memBlockTable.putRecord(blockRecord);
		MemoryBlockDB newBlock = new MemoryBlockDB(this, blockRecord, subBlocks);
		cacheNewBlock(newBlock);
		return newBlock;
	}

	private MemoryBlockDB createMappedBlock(byte type, String name, Address startAddress,
			long length, Address mappedAddress, int flags, int mappingScheme)
			throws IOException, AddressOverflowException {
		updateAddressMapForAllAddresses(startAddress, length);

		List<SubMemoryBlock> subBlocks = new ArrayList<>();
		DBRecord blockRecord = createMemoryBlockRecord(name, startAddress, length, flags);
		long key = blockRecord.getKey();

		long encoded = addrMap.getKey(mappedAddress, true);
		DBRecord subRecord = createSubBlockRecord(key, 0, length, type, mappingScheme, encoded);
		subBlocks.add(createSubBlock(subRecord));

		memBlockTable.putRecord(blockRecord);
		MemoryBlockDB newBlock = new MemoryBlockDB(this, blockRecord, subBlocks);
		cacheNewBlock(newBlock);
		return newBlock;
	}

	@Override
	void deleteMemoryBlock(MemoryBlockDB block) throws IOException {
		removeCachedBlock(block);
		memBlockTable.deleteRecord(block.getID());
	}

	@Override
	void deleteSubBlock(long key) throws IOException {
		subBlockTable.deleteRecord(key);
	}

	@Override
	void updateBlockRecord(DBRecord record) throws IOException {
		memBlockTable.putRecord(record);
	}

	@Override
	protected void updateSubBlockRecord(DBRecord record) throws IOException {
		subBlockTable.putRecord(record);
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
	DBRecord createSubBlockRecord(long parentKey, long startingOffset, long length, byte type,
			int data1, long data2) throws IOException {

		DBRecord record = V3_SUB_BLOCK_SCHEMA.createRecord(subBlockTable.getKey());
		record.setLongValue(V3_SUB_PARENT_ID_COL, parentKey);
		record.setByteValue(V3_SUB_TYPE_COL, type);
		record.setLongValue(V3_SUB_LENGTH_COL, length);
		record.setLongValue(V3_SUB_START_OFFSET_COL, startingOffset);
		record.setIntValue(V3_SUB_INT_DATA1_COL, data1);
		record.setLongValue(V3_SUB_LONG_DATA2_COL, data2);
		subBlockTable.putRecord(record);

		return record;
	}

	private DBRecord createMemoryBlockRecord(String name, Address startAddr, long length,
			int flags) {
		DBRecord record = V3_BLOCK_SCHEMA.createRecord(memBlockTable.getKey());
		record.setString(V3_NAME_COL, name);
		record.setLongValue(V3_START_ADDR_COL, addrMap.getKey(startAddr, true));
		record.setLongValue(V3_LENGTH_COL, length);
		record.setByteValue(V3_FLAGS_COL, (byte) flags);
		record.setIntValue(V3_SEGMENT_COL, getSegment(startAddr));
		return record;
	}

	private Map<Long, List<SubMemoryBlock>> getSubBlockMap() throws IOException {
		List<SubMemoryBlock> subBlocks = new ArrayList<>(subBlockTable.getRecordCount());
		RecordIterator it = subBlockTable.iterator();
		while (it.hasNext()) {
			DBRecord record = it.next();
			subBlocks.add(createSubBlock(record));
		}
		return subBlocks.stream().collect(Collectors.groupingBy(SubMemoryBlock::getParentBlockID));
	}

	private int getSegment(Address addr) {
		if (addr instanceof SegmentedAddress) {
			return ((SegmentedAddress) addr).getSegment();
		}
		return 0;
	}

	private void updateAddressMapForAllAddresses(Address startAddress, long length)
			throws AddressOverflowException {
		AddressSet set = new AddressSet(startAddress, startAddress.addNoWrap(length - 1));
		addrMap.getKeyRanges(set, true);
	}

	private SubMemoryBlock createSubBlock(DBRecord record) throws IOException {
		byte byteValue = record.getByteValue(V3_SUB_TYPE_COL);

		switch (byteValue) {
			case V3_SUB_TYPE_BIT_MAPPED:
				return new BitMappedSubMemoryBlock(this, record);
			case V3_SUB_TYPE_BYTE_MAPPED:
				return new ByteMappedSubMemoryBlock(this, record);
			case V3_SUB_TYPE_BUFFER:
				return new BufferSubMemoryBlock(this, record);
			case V3_SUB_TYPE_UNINITIALIZED:
				return new UninitializedSubMemoryBlock(this, record);
			case V3_SUB_TYPE_FILE_BYTES:
				return new FileBytesSubMemoryBlock(this, record);
			default:
				throw new AssertException("Unhandled sub block type: " + byteValue);
		}
	}

	private SubMemoryBlock createBufferSubBlock(long parentKey, long offset, long length,
			InputStream is) throws IOException {
		DBBuffer buffer = createBuffer(length, is);
		DBRecord record =
			createSubBlockRecord(parentKey, offset, length, V3_SUB_TYPE_BUFFER, buffer.getId(), 0);
		return new BufferSubMemoryBlock(this, record);
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

	@Override
	DBBuffer createBuffer(int length, byte initialValue) throws IOException {
		DBBuffer buffer = handle.createBuffer(length);
		buffer.fill(0, length - 1, initialValue);
		return buffer;
	}

}
