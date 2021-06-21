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

import db.DBBuffer;
import db.DBRecord;
import ghidra.framework.store.LockException;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.map.AddressMapDB;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.util.exception.AssertException;

public class MemoryBlockDB implements MemoryBlock {

	private MemoryMapDBAdapter adapter;
	protected DBRecord record;
	private Address startAddress;
	private long length;
	private List<SubMemoryBlock> subBlocks;
	protected MemoryMapDB memMap;
	private volatile boolean invalid;
	private long id;
	private SubMemoryBlock lastSubBlock;

	private List<MemoryBlockDB> mappedBlocks; // list of mapped blocks which map onto this block

	MemoryBlockDB(MemoryMapDBAdapter adapter, DBRecord record, List<SubMemoryBlock> subBlocks) {
		this.adapter = adapter;
		this.record = record;
		this.memMap = adapter.getMemoryMap();
		id = record.getKey();
		refresh(record, subBlocks);
	}

	/**
	 * Returns the id for this memory block
	 * @return the id for this memory block
	 */
	long getID() {
		return id;
	}

	void refresh(DBRecord lRecord, List<SubMemoryBlock> list) {
		if (id != lRecord.getKey()) {
			throw new AssertException("Incorrect block record");
		}
		this.record = lRecord;
		AddressMap addrMap = memMap.getAddressMap();
		startAddress =
			addrMap.decodeAddress(lRecord.getLongValue(MemoryMapDBAdapter.START_ADDR_COL));
		if (startAddress instanceof SegmentedAddress) {
			SegmentedAddress imageBase = (SegmentedAddress) addrMap.getImageBase();
			int baseSegment = imageBase.getSegment();
			int segment = lRecord.getIntValue(MemoryMapDBAdapter.SEGMENT_COL);
			startAddress = ((SegmentedAddress) startAddress).normalize(segment + baseSegment);
		}
		length = lRecord.getLongValue(MemoryMapDBAdapter.LENGTH_COL);
		lastSubBlock = null;
		Collections.sort(list);
		subBlocks = list;
		mappedBlocks = null;
	}

	/**
	 * Add a block which is mapped onto this block
	 * @param mappedBlock mapped memory block
	 */
	void addMappedBlock(MemoryBlockDB mappedBlock) {
		if (mappedBlocks == null) {
			mappedBlocks = new ArrayList<>();
		}
		mappedBlocks.add(mappedBlock);
	}

	/**
	 * Clear list of blocks mapped onto this block
	 */
	void clearMappedBlockList() {
		mappedBlocks = null;
	}

	/**
	 * Get collection of blocks which map onto this block.
	 * @return collection of blocks which map onto this block or null if none identified
	 */
	Collection<MemoryBlockDB> getMappedBlocks() {
		return mappedBlocks;
	}

	@Override
	public int compareTo(MemoryBlock o) {
		return startAddress.compareTo(o.getStart());
	}

	@Override
	public int getPermissions() {
		return record.getByteValue(MemoryMapDBAdapter.PERMISSIONS_COL);
	}

	@Override
	public InputStream getData() {
		return new MemoryBlockInputStream(this);
	}

	@Override
	public boolean contains(Address addr) {
		if (addr.hasSameAddressSpace(startAddress)) {
			long offset = addr.subtract(startAddress);
			return offset >= 0 && offset < length;
		}
		return false;
	}

	@Override
	public Address getStart() {
		return startAddress;
	}

	@Override
	public Address getEnd() {
		return startAddress.add(length - 1);
	}

	@Override
	public long getSize() {
		return length;
	}

	@Override
	public String getName() {
		String name = record.getString(MemoryMapDBAdapter.NAME_COL);
		if (name == null) {
			name = "";
		}
		return name;
	}

	@Override
	public void setName(String name) throws LockException {
		String oldName = getName();
		memMap.lock.acquire();
		try {
			checkValid();
			if (oldName.equals(name)) {
				return;
			}
			memMap.checkBlockName(name);
			try {
				if (isOverlay()) {
					memMap.overlayBlockRenamed(startAddress.getAddressSpace().getName(), name);
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

	@Override
	public String getComment() {
		return record.getString(MemoryMapDBAdapter.COMMENTS_COL);
	}

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

	@Override
	public boolean isRead() {
		return (record.getByteValue(MemoryMapDBAdapter.PERMISSIONS_COL) & READ) != 0;
	}

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

	@Override
	public boolean isWrite() {
		return (record.getByteValue(MemoryMapDBAdapter.PERMISSIONS_COL) & WRITE) != 0;
	}

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

	@Override
	public boolean isExecute() {
		return (record.getByteValue(MemoryMapDBAdapter.PERMISSIONS_COL) & EXECUTE) != 0;
	}

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

	@Override
	public void setPermissions(boolean read, boolean write, boolean execute) {
		memMap.lock.acquire();
		try {
			checkValid();
			setPermissionBit(READ, read);
			setPermissionBit(WRITE, write);
			setPermissionBit(EXECUTE, execute);
			memMap.fireBlockChanged(this);
		}
		finally {
			memMap.lock.release();
		}
	}

	@Override
	public boolean isVolatile() {
		return (record.getByteValue(MemoryMapDBAdapter.PERMISSIONS_COL) & VOLATILE) != 0;
	}

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

	@Override
	public String getSourceName() {
		return record.getString(MemoryMapDBAdapter.SOURCE_COL);
	}

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

	@Override
	public byte getByte(Address addr) throws MemoryAccessException {
		if (memMap.getLiveMemoryHandler() != null) {
			return memMap.getByte(addr);
		}
		checkValid();
		long offset = getBlockOffset(addr);
		return getByte(offset);
	}

	@Override
	public int getBytes(Address addr, byte[] b) throws MemoryAccessException {
		return getBytes(addr, b, 0, b.length);
	}

	@Override
	public int getBytes(Address addr, byte[] b, int off, int len) throws MemoryAccessException {
		if (memMap.getLiveMemoryHandler() != null) {
			return memMap.getBytes(addr, b, off, len);
		}

		checkValid();
		long offset = getBlockOffset(addr);
		return getBytes(offset, b, off, len);
	}

	@Override
	public void putByte(Address addr, byte b) throws MemoryAccessException {
		if (memMap.getLiveMemoryHandler() != null) {
			memMap.setByte(addr, b);
			return;
		}
		long offset = getBlockOffset(addr);
		memMap.lock.acquire();
		try {
			checkValid();
			memMap.checkMemoryWrite(this, addr, 1);
			putByte(offset, b);
			memMap.fireBytesChanged(addr, 1);
		}
		finally {
			memMap.lock.release();
		}
	}

	@Override
	public int putBytes(Address addr, byte[] b) throws MemoryAccessException {
		return putBytes(addr, b, 0, b.length);
	}

	@Override
	public int putBytes(Address addr, byte[] b, int off, int len) throws MemoryAccessException {
		if (memMap.getLiveMemoryHandler() != null) {
			memMap.setBytes(addr, b, off, len);
			return len;
		}
		memMap.lock.acquire();
		try {
			checkValid();
			memMap.checkMemoryWrite(this, addr, len);

			long offset = getBlockOffset(addr);
			int n = putBytes(offset, b, off, len);

			memMap.fireBytesChanged(addr, n);
			return n;
		}
		finally {
			memMap.lock.release();
		}
	}

	@Override
	public boolean isInitialized() {
		return subBlocks.get(0).isInitialized();
	}

	@Override
	public boolean isMapped() {
		return subBlocks.get(0).isMapped();
	}

	@Override
	public boolean isLoaded() {
		return startAddress.getAddressSpace().isLoadedMemorySpace();
	}

	void checkValid() {
		if (invalid) {
			throw new ConcurrentModificationException();
		}
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

	@Override
	public MemoryBlockType getType() {
		return subBlocks.get(0).getType();
	}

	@Override
	public boolean isOverlay() {
		return startAddress.getAddressSpace().isOverlaySpace();
	}

	public byte getByte(long offset) throws MemoryAccessException {
		SubMemoryBlock subBlock = getSubBlock(offset);
		try {
			return subBlock.getByte(offset);
		}
		catch (IOException e) {
			checkValid(); 		 // may have changed without lock
			memMap.dbError(e);
		}
		return 0;
	}

	public int getBytes(long offset, byte[] b, int off, int len) throws MemoryAccessException {
		if (off < 0 || off + len > b.length) {
			throw new ArrayIndexOutOfBoundsException();
		}
		if (offset < 0 || offset >= length) {
			throw new ArrayIndexOutOfBoundsException();
		}

		len = (int) Math.min(len, length - offset);

		int totalCopied = 0;

		try {
			while (totalCopied < len) {
				SubMemoryBlock subBlock = getSubBlock(offset + totalCopied);
				totalCopied += subBlock.getBytes(offset + totalCopied, b, off + totalCopied,
					len - totalCopied);
			}
		}
		catch (IOException e) {
			checkValid();
			memMap.dbError(e);
		}

		return totalCopied;
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

	private void putByte(long offset, byte b) throws MemoryAccessException {
		SubMemoryBlock subBlock = getSubBlock(offset);
		memMap.lock.acquire();
		try {
			subBlock.putByte(offset, b);
		}
		catch (IOException e) {
			memMap.dbError(e);
		}
		finally {
			memMap.lock.release();
		}
	}

	private int putBytes(long offset, byte[] b, int off, int len) throws MemoryAccessException {
		if (off < 0 || off + len > b.length) {
			throw new ArrayIndexOutOfBoundsException();
		}
		if (offset < 0 || offset >= length) {
			throw new ArrayIndexOutOfBoundsException();
		}

		len = (int) Math.min(len, length - offset);

		int totalCopied = 0;
		try {
			while (totalCopied < len) {
				SubMemoryBlock subBlock = getSubBlock(offset + totalCopied);
				totalCopied += subBlock.putBytes(offset + totalCopied, b, off + totalCopied,
					len - totalCopied);
			}
		}
		catch (IOException e) {
			checkValid();
			memMap.dbError(e);
		}

		return totalCopied;
	}

	private SubMemoryBlock getSubBlock(long offset) {
		if (lastSubBlock != null && lastSubBlock.contains(offset)) {
			return lastSubBlock;
		}
		lastSubBlock = findBlock(0, subBlocks.size() - 1, offset);
		return lastSubBlock;
	}

	private SubMemoryBlock findBlock(int minIndex, int maxIndex, long offset) {
		if (minIndex > maxIndex) {
			throw new IllegalArgumentException("address or offset out of bounds");
		}

		int index = (maxIndex + minIndex) / 2;
		SubMemoryBlock block = subBlocks.get(index);
		if (block.contains(offset)) {
			return block;
		}
		long startingOffset = block.getStartingOffset();
		if (offset < startingOffset) {
			return findBlock(minIndex, index - 1, offset);
		}
		return findBlock(index + 1, maxIndex, offset);
	}

	public void invalidate() {
		invalid = true;
	}

	void delete() throws IOException {
		for (SubMemoryBlock subBlock : subBlocks) {
			subBlock.delete();
		}
		adapter.deleteMemoryBlock(getID());
		invalidate();
	}

	void setStartAddress(Address newStartAddr) throws IOException, AddressOverflowException {
		startAddress = newStartAddr;

		// ensure that end address key has also been generated
		AddressSet set = new AddressSet(startAddress, startAddress.addNoWrap(length - 1));
		AddressMapDB addrMap = adapter.getMemoryMap().getAddressMap();
		addrMap.getKeyRanges(set, true);

		record.setLongValue(MemoryMapDBAdapter.START_ADDR_COL, addrMap.getKey(newStartAddr, true));
		if (newStartAddr instanceof SegmentedAddress) {
			SegmentedAddress imageBase = (SegmentedAddress) memMap.getAddressMap().getImageBase();
			int baseSegment = imageBase.getSegment();
			int segment = ((SegmentedAddress) startAddress).getSegment();
			record.setIntValue(MemoryMapDBAdapter.SEGMENT_COL, segment - baseSegment);
		}
		adapter.updateBlockRecord(record);
	}

	MemoryBlockDB split(Address addr) throws IOException {
		lastSubBlock = null;
		long offset = addr.subtract(startAddress);
		long newLength = length - offset;

		length = offset;
		record.setLongValue(MemoryMapDBAdapter.LENGTH_COL, length);
		adapter.updateBlockRecord(record);

		List<SubMemoryBlock> splitBlocks = new ArrayList<>();

		int index = getIndexOfSubBlockToSplit(offset);
		SubMemoryBlock subMemoryBlock = subBlocks.get(index);
		if (subMemoryBlock.getStartingOffset() == offset) {
			// move the sub blocks after the split point to the new split off memory block
			List<SubMemoryBlock> subList = subBlocks.subList(index, subBlocks.size());
			splitBlocks.addAll(subList);
			subList.clear();
		}
		else {
			SubMemoryBlock split = subMemoryBlock.split(offset);
			splitBlocks.add(split);
			// move the sub blocks after the split point to the new split off memory block
			List<SubMemoryBlock> subList = subBlocks.subList(index + 1, subBlocks.size());
			splitBlocks.addAll(subList);
			subList.clear();
		}
		return adapter.createBlock(getName() + ".split", addr, newLength, getPermissions(),
			splitBlocks);
	}

	private int getIndexOfSubBlockToSplit(long offset) {
		for (int i = 0; i < subBlocks.size(); i++) {
			if (subBlocks.get(i).contains(offset)) {
				return i;
			}
		}
		throw new IllegalArgumentException("offset " + offset + " not in this block");
	}

	void initializeBlock(byte initialValue) throws IOException {
		lastSubBlock = null;
		for (SubMemoryBlock subBlock : subBlocks) {
			subBlock.delete();
		}
		subBlocks.clear();

		int numFullBlocks = (int) (length / Memory.GBYTE);
		int lastSubBlockSize = (int) (length % Memory.GBYTE);
		long blockOffset = 0;
		for (int i = 0; i < numFullBlocks; i++) {
			createBufferSubBlock(initialValue, blockOffset, (int) Memory.GBYTE);
			blockOffset += Memory.GBYTE;
		}
		if (lastSubBlockSize > 0) {
			createBufferSubBlock(initialValue, blockOffset, lastSubBlockSize);
		}
	}

	private void createBufferSubBlock(byte initialValue, long blockOffset, int size)
			throws IOException {
		DBBuffer buffer = adapter.createBuffer(size, initialValue);
		DBRecord subBlockRecord = adapter.createSubBlockRecord(id, blockOffset, size,
			MemoryMapDBAdapter.SUB_TYPE_BUFFER, buffer.getId(), 0);

		BufferSubMemoryBlock sub = new BufferSubMemoryBlock(adapter, subBlockRecord);
		subBlocks.add(sub);
	}

	void join(MemoryBlockDB memBlock2) throws IOException {
		lastSubBlock = null;
		length += memBlock2.length;
		record.setLongValue(MemoryMapDBAdapter.LENGTH_COL, length);
		int n = subBlocks.size();
		subBlocks.addAll(memBlock2.subBlocks);
		possiblyMergeSubBlocks(n - 1, n);
		sequenceSubBlocks();
		adapter.deleteMemoryBlock(memBlock2.id);
		adapter.updateBlockRecord(record);

	}

	private void sequenceSubBlocks() throws IOException {
		long startingOffset = 0;
		for (SubMemoryBlock subBlock : subBlocks) {
			subBlock.setParentIdAndStartingOffset(id, startingOffset);
			startingOffset += subBlock.subBlockLength;
		}
	}

	private void possiblyMergeSubBlocks(int lastOld, int firstNew) throws IOException {
		SubMemoryBlock sub1 = subBlocks.get(lastOld);
		SubMemoryBlock sub2 = subBlocks.get(firstNew);
		if (sub1.join(sub2)) {
			subBlocks.remove(firstNew);
		}
	}

	void uninitializeBlock() throws IOException {
		lastSubBlock = null;
		for (SubMemoryBlock subBlock : subBlocks) {
			subBlock.delete();
		}
		subBlocks.clear();
		DBRecord subRecord = adapter.createSubBlockRecord(id, 0, length,
			MemoryMapDBAdapter.SUB_TYPE_UNITIALIZED, 0, 0);
		subBlocks.add(new UninitializedSubMemoryBlock(adapter, subRecord));

	}

	// used for upgrade from old versions
	DBBuffer getBuffer() {
		if (subBlocks.size() > 1) {
			throw new IllegalStateException(
				"Old blocks to be upgraded should only have one sub block");
		}
		SubMemoryBlock subMemoryBlock = subBlocks.get(0);
		if (subMemoryBlock instanceof BufferSubMemoryBlock) {
			return ((BufferSubMemoryBlock) subMemoryBlock).buf;
		}
		throw new IllegalStateException("Old blocks to be upgraded not expected type");

	}

	@Override
	public List<MemoryBlockSourceInfo> getSourceInfos() {
		List<MemoryBlockSourceInfo> infos = new ArrayList<>(subBlocks.size());
		for (SubMemoryBlock subBlock : subBlocks) {
			infos.add(subBlock.getSourceInfo(this));
		}
		return infos;
	}

	boolean uses(FileBytes fileBytes) {
		for (SubMemoryBlock subBlock : subBlocks) {
			if (subBlock.uses(fileBytes)) {
				return true;
			}
		}
		return false;
	}

}
