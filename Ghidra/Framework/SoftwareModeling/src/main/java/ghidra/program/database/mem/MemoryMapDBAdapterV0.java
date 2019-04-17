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

import db.DBBuffer;
import db.DBHandle;
import db.Record;
import db.RecordIterator;
import db.Table;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.util.exception.VersionException;

/**
 * Adapter for version 0
 */
class MemoryMapDBAdapterV0 extends MemoryMapDBAdapter {

	static final String V0_TABLE_NAME = "Memory Block";

	private final static int VERSION = 0;

	protected final static int V0_NAME_COL = 0;
	protected final static int V0_BUFFER_ID_COL = 1;
	protected final static int V0_COMMENTS_COL = 2;
	protected final static int V0_DESCRIPTION_COL = 3;
	protected final static int V0_SOURCE_NAME_COL = 4;
	protected final static int V0_SOURCE_OFFSET_COL = 5;
	protected final static int V0_IS_READ_COL = 6;
	protected final static int V0_IS_WRITE_COL = 7;
	protected final static int V0_IS_EXECUTE_COL = 8;
	protected final static int V0_START_ADDR_COL = 9;
	protected final static int V0_LENGTH_COL = 10;
	protected final static int V0_TYPE_COL = 11;
	protected final static int V0_BASE_ADDR_COL = 12;
	protected final static int V0_SOURCE_BLOCK_ID_COL = 13;
	protected final static int V0_SEGMENT_COL = 14;	// added in version 1

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

	private MemoryBlockDB[] blocks;
	private DBHandle handle;

	/**
	 * @param handle
	 */
	MemoryMapDBAdapterV0(DBHandle handle, MemoryMapDB memMap) throws VersionException, IOException {
		this(handle, memMap, VERSION);
	}

	protected MemoryMapDBAdapterV0(DBHandle handle, MemoryMapDB memMap, int expectedVersion)
			throws VersionException, IOException {
		this.handle = handle;
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
		blocks = new MemoryBlockDB[recCount];

		AddressFactory addrFactory = memMap.getAddressFactory();
		int i = 0;
		RecordIterator it = table.iterator();
		while (it.hasNext()) {
			Record rec = it.next();
			int permissions = 0;
			if (rec.getBooleanValue(V0_IS_READ_COL)) {
				permissions |= MemoryBlock.READ;
			}
			if (rec.getBooleanValue(V0_IS_WRITE_COL)) {
				permissions |= MemoryBlock.WRITE;
			}
			if (rec.getBooleanValue(V0_IS_EXECUTE_COL)) {
				permissions |= MemoryBlock.EXECUTE;
			}
			Address start = addrFactory.oldGetAddressFromLong(rec.getLongValue(V0_START_ADDR_COL));
			long startAddr = addrMap.getKey(start, false);

			long overlayAddr = rec.getLongValue(V0_BASE_ADDR_COL);
			try {
				Address ov = addrFactory.oldGetAddressFromLong(overlayAddr);
				overlayAddr = addrMap.getKey(ov, false);
			}
			catch (Exception e) {
			}

			int segment = 0;
			if (expectedVersion == 1 && (start instanceof SegmentedAddress)) {
				segment = rec.getIntValue(V0_SEGMENT_COL);
//				((SegmentedAddress)start).normalize(segment);
			}

			// Convert to new record format
			Record blockRec = MemoryMapDBAdapter.BLOCK_SCHEMA.createRecord(i);

			blockRec.setString(MemoryMapDBAdapter.NAME_COL, rec.getString(V0_NAME_COL));
			blockRec.setString(MemoryMapDBAdapter.COMMENTS_COL, rec.getString(V0_COMMENTS_COL));
			blockRec.setString(MemoryMapDBAdapter.SOURCE_COL, rec.getString(V0_SOURCE_NAME_COL));
			blockRec.setByteValue(MemoryMapDBAdapter.PERMISSIONS_COL, (byte) permissions);
			blockRec.setLongValue(MemoryMapDBAdapter.START_ADDR_COL, startAddr);
			blockRec.setShortValue(MemoryMapDBAdapter.BLOCK_TYPE_COL,
				rec.getShortValue(V0_TYPE_COL));
			blockRec.setLongValue(MemoryMapDBAdapter.OVERLAY_ADDR_COL, overlayAddr);
			blockRec.setLongValue(MemoryMapDBAdapter.LENGTH_COL, rec.getLongValue(V0_LENGTH_COL));
			blockRec.setIntValue(MemoryMapDBAdapter.CHAIN_BUF_COL,
				rec.getIntValue(V0_BUFFER_ID_COL));
			blockRec.setIntValue(MemoryMapDBAdapter.SEGMENT_COL, segment);

			blocks[i++] = MemoryMapDBAdapter.getMemoryBlock(this, blockRec, null, memMap);
		}
		Arrays.sort(blocks);
	}

	/**
	 * @see ghidra.program.database.mem.MemoryMapDBAdapter#refreshMemory()
	 */
	@Override
	void refreshMemory() throws IOException {
	}

	/**
	 * @see ghidra.program.database.mem.MemoryMapDBAdapter#getMemoryBlocks()
	 */
	@Override
	MemoryBlockDB[] getMemoryBlocks() {
		return blocks;
	}

	/**
	 * @see ghidra.program.database.mem.MemoryMapDBAdapter#splitBlock(ghidra.program.database.mem2.MemoryBlockDB, long)
	 */
	@Override
	MemoryBlockDB splitBlock(MemoryBlockDB block, long offset) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	MemoryBlockDB createInitializedBlock(String name, Address startAddr, InputStream is,
			long length, int permissions)
			throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	MemoryBlockDB createInitializedBlock(String name, Address startAddr, DBBuffer buf,
			int permissions)
			throws IOException {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.mem.MemoryMapDBAdapter#joinBlocks(ghidra.program.database.mem2.MemoryBlockDB, ghidra.program.database.mem2.MemoryBlockDB)
	 */
	@Override
	MemoryBlockDB joinBlocks(MemoryBlockDB block1, MemoryBlockDB block2) throws IOException {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.mem.MemoryMapDBAdapter#setBlockSize(ghidra.program.database.mem2.MemoryBlockDB, long)
	 */
	void setBlockSize(MemoryBlockDB block, long size) {

		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.mem.MemoryMapDBAdapter#deleteMemoryBlock(ghidra.program.database.mem2.MemoryBlockDB)
	 */
	@Override
	void deleteMemoryBlock(MemoryBlockDB block) throws IOException {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.mem.MemoryMapDBAdapter#deleteTable(db.DBHandle)
	 */
	@Override
	void deleteTable(DBHandle dbHandle) throws IOException {
		dbHandle.deleteTable(V0_TABLE_NAME);
	}

	/**
	 * @see ghidra.program.database.mem.MemoryMapDBAdapter#updateBlockRecord(db.Record)
	 */
	@Override
	void updateBlockRecord(Record record) throws IOException {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.mem.MemoryMapDBAdapter#createBuffer(int, byte)
	 */
	@Override
	DBBuffer createBuffer(int length, byte initialValue) throws IOException {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.mem.MemoryMapDBAdapter#createBlock(ghidra.program.model.mem.MemoryBlockType, java.lang.String, ghidra.program.model.address.Address, long, ghidra.program.model.address.Address, boolean)
	 */
	@Override
	MemoryBlockDB createBlock(MemoryBlockType blockType, String name, Address startAddr,
			long length, Address overlayAddr, boolean initializeBytes, int permissions)
			throws IOException {
		throw new UnsupportedOperationException();
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
