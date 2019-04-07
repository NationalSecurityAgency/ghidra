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
import java.util.ConcurrentModificationException;

import db.DBBuffer;
import db.Record;
import ghidra.framework.store.LockException;
import ghidra.program.database.map.AddressMapDB;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.DuplicateNameException;

/**
 * Database implementation of a memory block.  Each block has a corresponding record in
 * the memory map table which includes a buffer id for a DBBuffer that contains the actual
 * bytes in the memory block.
 */

class MemoryBlockDB implements MemoryBlock {

	private static final MemoryAccessException UNITIALIZED_EXCEPTION =
		new MemoryAccessException("Cannot access uninitialized memory!");

	private MemoryMapDBAdapter adapter;
	protected Record record;
	protected MemoryMapDB memMap;
	protected AddressMapDB addrMap;
	private int id;
	protected Address startAddress;
	protected long length;
	private volatile boolean invalid;
	private DBBuffer buf;
	protected MemoryBlockType blockType;
	private boolean isInitialized;

	/**
	 * Constructs a new MemoryBlockDB 
	 * @param adapter the memory map database adapter
	 * @param record the record for this block
	 * @param buf the DBBuffer containing the bytes for this block
	 * @param memMap the memory map manager.
	 * @throws IOException if a database io error occurs.
	 */
	MemoryBlockDB(MemoryMapDBAdapter adapter, Record record, DBBuffer buf, MemoryMapDB memMap)
			throws IOException {
		this.adapter = adapter;
		this.memMap = memMap;
		this.addrMap = memMap.getAddressMap();
		this.buf = buf;
		id = (int) record.getKey();
		refresh(record);
	}

	void refresh(Record lRecord) throws IOException {
		this.record = lRecord;
		if (id != lRecord.getKey()) {
			throw new AssertException("Incorrect block record");
		}

		startAddress =
			addrMap.decodeAddress(lRecord.getLongValue(MemoryMapDBAdapter.START_ADDR_COL), false);
		if (startAddress instanceof SegmentedAddress) {
			SegmentedAddress imageBase = (SegmentedAddress) addrMap.getImageBase();
			int baseSegment = imageBase.getSegment();
			int segment = lRecord.getIntValue(MemoryMapDBAdapter.SEGMENT_COL);
			startAddress = ((SegmentedAddress) startAddress).normalize(segment + baseSegment);
		}
		int dbBlockType = lRecord.getShortValue(MemoryMapDBAdapter.BLOCK_TYPE_COL);
		blockType = getBlockType(dbBlockType);
		isInitialized = (dbBlockType == MemoryMapDBAdapter.INITIALIZED);
		length = lRecord.getLongValue(MemoryMapDBAdapter.LENGTH_COL);
		int bufferID = lRecord.getIntValue(MemoryMapDBAdapter.CHAIN_BUF_COL);
		buf = adapter.getBuffer(bufferID);
	}

	private MemoryBlockType getBlockType(int dbType) {
		switch (dbType) {
			case MemoryMapDBAdapter.INITIALIZED:
			case MemoryMapDBAdapter.UNINITIALIZED:
				return startAddress.getAddressSpace().isOverlaySpace() ? MemoryBlockType.OVERLAY
						: MemoryBlockType.DEFAULT;
			case MemoryMapDBAdapter.BIT_MAPPED:
				return MemoryBlockType.BIT_MAPPED;
			case MemoryMapDBAdapter.BYTE_MAPPED:
				return MemoryBlockType.BYTE_MAPPED;
		}
		return MemoryBlockType.DEFAULT;
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#getData()
	 */
	@Override
	public InputStream getData() {
		return new MemoryBlockInputStream(this);
	}

	/**
	 * Returns the id for this memory block
	 */
	int getID() {
		return id;
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#contains(ghidra.program.model.address.Address)
	 */
	@Override
	public boolean contains(Address addr) {
		if (addr.hasSameAddressSpace(startAddress)) {
			long offset = addr.subtract(startAddress);
			return offset >= 0 && offset < length;
		}
		return false;
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#getStart()
	 */
	@Override
	public Address getStart() {
		return startAddress;
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#getEnd()
	 */
	@Override
	public Address getEnd() {
		return startAddress.add(length - 1);
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#getSize()
	 */
	@Override
	public long getSize() {
		return length;
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#getName()
	 */
	@Override
	public String getName() {
		return record.getString(MemoryMapDBAdapter.NAME_COL);
	}

	@Override
	public String toString() {
		return getName() + "[" + getStart() + ":" + getEnd() + "]";
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#setName(java.lang.String)
	 */
	@Override
	public void setName(String name) throws DuplicateNameException, LockException {
		memMap.lock.acquire();
		String oldName = getName();
		try {
			checkValid();
			try {
				if (getStart().getAddressSpace().isOverlaySpace()) {
					memMap.overlayBlockRenamed(oldName, name);
				}
				record.setString(MemoryMapDBAdapter.NAME_COL, name);
				adapter.updateBlockRecord(record);
			}
			catch (IOException e) {
				memMap.dbError(e);
			}
			memMap.fireBlockChanged(this);
		}
		finally {
			memMap.lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#getComment()
	 */
	@Override
	public String getComment() {
		return record.getString(MemoryMapDBAdapter.COMMENTS_COL);
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#setComment(java.lang.String)
	 */
	@Override
	public void setComment(String comment) {
		memMap.lock.acquire();
		try {
			checkValid();
			try {
				record.setString(MemoryMapDBAdapter.COMMENTS_COL, comment);
				adapter.updateBlockRecord(record);
				memMap.fireBlockChanged(this);
			}
			catch (IOException e) {
				memMap.dbError(e);
			}
		}
		finally {
			memMap.lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#isRead()
	 */
	@Override
	public boolean isRead() {
		return (record.getByteValue(MemoryMapDBAdapter.PERMISSIONS_COL) & READ) != 0;
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#getPermissions()
	 */
	@Override
	public int getPermissions() {
		return record.getByteValue(MemoryMapDBAdapter.PERMISSIONS_COL);
	}

	@Override
	public boolean isInitialized() {
		return isInitialized || memMap.getLiveMemoryHandler() != null;
	}

	private void setPermissionBit(int permBitMask, boolean enable) {
		byte p = record.getByteValue(MemoryMapDBAdapter.PERMISSIONS_COL);
		if (enable) {
			p |= permBitMask;
		}
		else {
			p &= ~permBitMask;
		}
		record.setByteValue(MemoryMapDBAdapter.PERMISSIONS_COL, p);
		try {
			adapter.updateBlockRecord(record);
		}
		catch (IOException e) {
			memMap.dbError(e);
		}
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#setRead(boolean)
	 */
	@Override
	public void setRead(boolean r) {
		memMap.lock.acquire();
		try {
			checkValid();
			setPermissionBit(READ, r);
			memMap.fireBlockChanged(this);
		}
		finally {
			memMap.lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#isWrite()
	 */
	@Override
	public boolean isWrite() {
		return (record.getByteValue(MemoryMapDBAdapter.PERMISSIONS_COL) & WRITE) != 0;
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#setWrite(boolean)
	 */
	@Override
	public void setWrite(boolean w) {
		memMap.lock.acquire();
		try {
			checkValid();
			setPermissionBit(WRITE, w);
			memMap.fireBlockChanged(this);
		}
		finally {
			memMap.lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#isExecute()
	 */
	@Override
	public boolean isExecute() {
		return (record.getByteValue(MemoryMapDBAdapter.PERMISSIONS_COL) & EXECUTE) != 0;
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#setExecute(boolean)
	 */
	@Override
	public void setExecute(boolean x) {
		memMap.lock.acquire();
		try {
			checkValid();
			setPermissionBit(EXECUTE, x);
			memMap.fireBlockChanged(this);
		}
		finally {
			memMap.lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#isVolatile()
	 */
	@Override
	public boolean isVolatile() {
		return (record.getByteValue(MemoryMapDBAdapter.PERMISSIONS_COL) & VOLATILE) != 0;
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#setVolatile(boolean)
	 */
	@Override
	public void setVolatile(boolean v) {
		memMap.lock.acquire();
		try {
			checkValid();
			setPermissionBit(VOLATILE, v);
			memMap.fireBlockChanged(this);
		}
		finally {
			memMap.lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#getSourceName()
	 */
	@Override
	public String getSourceName() {
		return record.getString(MemoryMapDBAdapter.SOURCE_COL);
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#setSourceName(java.lang.String)
	 */
	@Override
	public void setSourceName(String sourceName) {
		memMap.lock.acquire();
		try {
			checkValid();
			try {
				record.setString(MemoryMapDBAdapter.SOURCE_COL, sourceName);
				adapter.updateBlockRecord(record);
			}
			catch (IOException e) {
				memMap.dbError(e);
			}
			memMap.fireBlockChanged(this);
		}
		finally {
			memMap.lock.release();
		}
	}

	protected long getBlockOffset(Address addr) throws MemoryAccessException {
		if (!addr.hasSameAddressSpace(startAddress)) {
			throw new MemoryAccessException("Address not contained in block: " + addr);
		}
		long offset = addr.subtract(startAddress);
		if (offset < 0 || offset >= length) {
			throw new MemoryAccessException("Address not contained in block: " + addr);
		}
		return offset;
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#getByte(ghidra.program.model.address.Address)
	 */
	@Override
	public byte getByte(Address addr) throws MemoryAccessException {

		long offset = getBlockOffset(addr);
		if (memMap.getLiveMemoryHandler() != null) {
			return memMap.getByte(addr);
		}
		checkBlockType();
		try {
			return getByte(offset);
		}
		catch (IOException e) {
			memMap.dbError(e);
		}
		return 0; // should not happen
	}

	byte getByte(long offset) throws IOException {
		checkValid();
		try {
			return buf.getByte((int) offset);
		}
		catch (Exception e) {
			checkValid();  // may have changed without lock
			if (e instanceof IOException) {
				throw (IOException) e;
			}
			if (e instanceof RuntimeException) {
				throw (RuntimeException) e;
			}
			throw new RuntimeException("Unexpected Error", e);
		}
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#getBytes(ghidra.program.model.address.Address, byte[])
	 */
	@Override
	public int getBytes(Address addr, byte[] b) throws MemoryAccessException {
		return getBytes(addr, b, 0, b.length);
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#getBytes(ghidra.program.model.address.Address,
	 *      byte[], int, int)
	 */
	@Override
	public int getBytes(Address addr, byte[] b, int off, int size) throws MemoryAccessException {
		long offset = getBlockOffset(addr);
		int len = (int) Math.min(size, length - offset);
		if (memMap.getLiveMemoryHandler() != null) {
			return memMap.getBytes(addr, b, off, len);
		}
		checkValid();
		checkBlockType();
		try {
			buf.get((int) offset, b, off, len);
		}
		catch (Exception e) {
			checkValid();  // may have changed without lock
			if (e instanceof IOException) {
				memMap.dbError((IOException) e);
			}
			if (e instanceof RuntimeException) {
				throw (RuntimeException) e;
			}
			throw new RuntimeException("Unexpected Error", e);
		}
		return len;
	}

	int getBytes(long offset, byte[] b, int off, int size) throws IOException {
		int len = (int) Math.min(size, length - offset);
		checkValid();
		try {
			buf.get((int) offset, b, off, len);
		}
		catch (Exception e) {
			checkValid();  // may have changed without lock
			if (e instanceof IOException) {
				throw (IOException) e;
			}
			if (e instanceof RuntimeException) {
				throw (RuntimeException) e;
			}
			throw new RuntimeException("Unexpected Error", e);
		}
		return len;
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#putByte(ghidra.program.model.address.Address, byte)
	 */
	@Override
	public void putByte(Address addr, byte b) throws MemoryAccessException {
		long offset = getBlockOffset(addr);
		if (memMap.getLiveMemoryHandler() != null) {
			memMap.setByte(addr, b);
			return;
		}
		memMap.lock.acquire();
		try {
			checkValid();
			checkBlockType();
			memMap.checkMemoryWrite(addr);
			try {
				buf.putByte((int) offset, b);
			}
			catch (IOException e) {
				memMap.dbError(e);
			}
			memMap.fireBytesChanged(addr, 1);
		}
		finally {
			memMap.lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#putBytes(ghidra.program.model.address.Address,
	 *      byte[])
	 */
	@Override
	public int putBytes(Address addr, byte[] b) throws MemoryAccessException {
		return putBytes(addr, b, 0, b.length);
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#putBytes(ghidra.program.model.address.Address, byte[], int, int)
	 */
	@Override
	public int putBytes(Address addr, byte[] b, int off, int size) throws MemoryAccessException {

		int len = 0;

		long offset = getBlockOffset(addr);
		len = (int) Math.min(size, length - offset);
		if (len > 0) {
			if (memMap.getLiveMemoryHandler() != null) {
				memMap.setBytes(addr, b, off, len);
				return len;
			}
			memMap.lock.acquire();
			try {
				checkValid();
				checkBlockType();
				memMap.checkMemoryWrite(addr, len);
				try {
					buf.put((int) offset, b, off, len);
				}
				catch (IOException e) {
					memMap.dbError(e);
				}
				memMap.fireBytesChanged(addr, len);
			}
			finally {
				memMap.lock.release();
			}
		}
		return len;
	}

	/**
	 * @see ghidra.program.model.mem.MemoryBlock#getType()
	 */
	@Override
	public MemoryBlockType getType() {
		return blockType;
	}

	void checkValid() {
		if (invalid) {
			throw new ConcurrentModificationException();
		}
	}

	void invalidate() {
		invalid = true;
	}

	/**
	 * Allows sorting blocks by start address
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public int compareTo(MemoryBlock block) {
		MemoryBlockDB blockDB = (MemoryBlockDB) block;
		return startAddress.compareTo(blockDB.startAddress);
	}

	void setStartAddress(Address newStartAddr) throws AddressOverflowException, IOException {
		startAddress = newStartAddr;
		long addr = addrMap.getKey(newStartAddr, true);

		// ensure that end address key has also been generated
		Address endAddr = newStartAddr.addNoWrap(length - 1);
		addrMap.getKey(endAddr, true);

		record.setLongValue(MemoryMapDBAdapter.START_ADDR_COL, addr);
		if (newStartAddr instanceof SegmentedAddress) {
			SegmentedAddress imageBase = (SegmentedAddress) addrMap.getImageBase();
			int baseSegment = imageBase.getSegment();
			int segment = ((SegmentedAddress) startAddress).getSegment();
			record.setIntValue(MemoryMapDBAdapter.SEGMENT_COL, segment - baseSegment);
		}
		adapter.updateBlockRecord(record);
	}

	void join(MemoryBlockDB memBlock2) throws IOException {

		length += memBlock2.length;
		record.setLongValue(MemoryMapDBAdapter.LENGTH_COL, length);
		if (buf != null) {
			buf.append(memBlock2.buf);
			memBlock2.buf = null;
		}
		adapter.updateBlockRecord(record);

		adapter.deleteMemoryBlock(memBlock2);
	}

	/**
	 * the memoryMapDB must refresh the memory blocks after calling this method.
	 */
	MemoryBlockDB split(Address addr) throws IOException {
		long offset = addr.subtract(startAddress);
		long newLength = length - offset;

		length = offset;
		record.setLongValue(MemoryMapDBAdapter.LENGTH_COL, length);
		adapter.updateBlockRecord(record);

		DBBuffer newBuf = null;
		MemoryBlockDB newBlock;
		try {
			if (buf != null) {
				newBuf = buf.split((int) offset);
				newBlock = adapter.createInitializedBlock(getName() + ".split", addr, newBuf,
					getPermissions());
			}
			else {
				newBlock = adapter.createBlock(getType(), getName() + ".split", addr, newLength,
					getOverlayAddress(offset), isInitialized(), getPermissions());
			}
		}
		catch (AddressOverflowException e) {
			// Should not occur
			throw new AssertException(e);
		}
		return newBlock;
	}

	Address getOverlayAddress(long offset) {
		return null;
	}

	void initializeBlock(byte initialValue) throws IOException {
		if (length > Integer.MAX_VALUE) {
			throw new AssertException();
		}
		buf = adapter.createBuffer((int) length, initialValue);
		record.setIntValue(MemoryMapDBAdapter.CHAIN_BUF_COL, buf.getId());
		record.setShortValue(MemoryMapDBAdapter.BLOCK_TYPE_COL,
			(short) MemoryMapDBAdapter.INITIALIZED);
		isInitialized = true;
		adapter.updateBlockRecord(record);
	}

	void uninitializeBlock() throws IOException {
		buf.delete();
		buf = null;
		record.setIntValue(MemoryMapDBAdapter.CHAIN_BUF_COL, -1);
		record.setShortValue(MemoryMapDBAdapter.BLOCK_TYPE_COL,
			(short) MemoryMapDBAdapter.UNINITIALIZED);
		isInitialized = false;
		adapter.updateBlockRecord(record);
	}

	private void checkBlockType() throws MemoryAccessException {
		if (!isInitialized) {
			throw UNITIALIZED_EXCEPTION;
		}
	}

	DBBuffer getBuffer() {
		return buf;
	}

	void delete() throws IOException {
		if (buf != null) {
			buf.delete();
		}
		adapter.deleteMemoryBlock(this);
	}

	@Override
	public boolean isMapped() {
		return false;
	}

	@Override
	public boolean isLoaded() {
		return startAddress.getAddressSpace().isLoadedMemorySpace();
	}

}
