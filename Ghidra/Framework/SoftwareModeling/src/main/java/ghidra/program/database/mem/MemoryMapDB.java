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

import db.DBConstants;
import db.DBHandle;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.store.LockException;
import ghidra.program.database.ManagerDB;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.code.CodeManager;
import ghidra.program.database.map.AddressMapDB;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.util.ChangeManager;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * The database memory map manager.
 */
public class MemoryMapDB implements Memory, ManagerDB, LiveMemoryListener {

	private ProgramDB program;
	private AddressMapDB addrMap;
	private MemoryMapDBAdapter adapter;
	private FileBytesAdapter fileBytesAdapter;

	private static final DataConverter BIG_ENDIAN = BigEndianDataConverter.INSTANCE;
	private static final DataConverter LITTLE_ENDIAN = LittleEndianDataConverter.INSTANCE;

	private DataConverter defaultEndian;
	private List<MemoryBlockDB> blocks;// sorted list of blocks
	private AddressSet addrSet = new AddressSet();
	private AddressSet initializedLoadedAddrSet = new AddressSet();
	private AddressSet allInitializedAddrSet = new AddressSet();
	private AddressSetView executeSet = null;

	private MemoryBlock lastBlock;// the last accessed block
	private LiveMemoryHandler liveMemory;

	// lazy hashmap of block names to blocks, must be reloaded if blocks are removed or added
	private HashMap<String, MemoryBlock> nameBlockMap = new HashMap<String, MemoryBlock>();
	private final static MemoryBlock NoBlock = new MemoryBlockStub();  // placeholder for no block, not given out

	Lock lock;

	private static Comparator<Object> BLOCK_ADDRESS_COMPARATOR = (o1, o2) -> {
		MemoryBlock block = (MemoryBlock) o1;
		Address addr = (Address) o2;
		return block.getStart().compareTo(addr);
	};

	/**
	 * Constructs a new MemoryMapDB
	 * @param handle the open database handle.
	 * @param addrMap the address map.
	 * @param openMode the open mode for the program.
	 * @param isBigEndian endianess flag
	 * @param lock the program synchronization lock
	 * @param monitor Task monitor for upgrading
	 * @throws IOException if a database io error occurs.
	 * @throws VersionException if the database version is different from the expected version
	 */
	public MemoryMapDB(DBHandle handle, AddressMapDB addrMap, int openMode, boolean isBigEndian,
			Lock lock, TaskMonitor monitor) throws IOException, VersionException {
		this.addrMap = addrMap;
		this.lock = lock;
		defaultEndian = isBigEndian ? BIG_ENDIAN : LITTLE_ENDIAN;
		adapter = MemoryMapDBAdapter.getAdapter(handle, openMode, this, monitor);
		fileBytesAdapter = FileBytesAdapter.getAdapter(handle, openMode, monitor);
		initializeBlocks();
		buildAddressSets();
	}

	// for testing
	MemoryMapDB(DBHandle handle, AddressMapDB addrMap, int openMode, boolean isBigEndian,
			Lock lock) {
		this.addrMap = addrMap;
		this.lock = lock;
		defaultEndian = isBigEndian ? BIG_ENDIAN : LITTLE_ENDIAN;
	}

	// for testing
	void init(MemoryMapDBAdapter memoryAdapter, FileBytesAdapter bytesAdapter) {
		this.adapter = memoryAdapter;
		this.fileBytesAdapter = bytesAdapter;
	}

	@Override
	public Program getProgram() {
		return program;
	}

	@Override
	public void invalidateCache(boolean all) throws IOException {
		lock.acquire();
		try {
			reloadAll();
		}
		finally {
			lock.release();
		}
	}

	private void buildAddressSets() {
		addrSet = new AddressSet();
		initializedLoadedAddrSet = new AddressSet();
		allInitializedAddrSet = new AddressSet();
		// we have to process the non-mapped blocks first because to process the mapped
		// blocks we need the address sets for the non-mapped blocks to be complete
		for (MemoryBlockDB block : blocks) {
			block.clearMappedBlockList();
			if (!block.isMapped()) {
				addBlockAddresses(block, false);
			}
		}
		// process all mapped blocks after non-mapped-blocks above
		for (MemoryBlockDB block : blocks) {
			if (block.isMapped()) {
				addBlockAddresses(block, false);
			}
		}
	}

	/**
	 * Update the <code>allInitializedAddrSet</code> and <code>initializedLoadedAddrSet</code>
	 * with relevant initialized addresses from the specified memory block.  If block is not 
	 * a mapped-block and it may be a source to existing mapped-blocks then 
	 * <code>scanAllMappedBlocksIfNeeded</code> should be passed as <code>true</code> unless
	 * all mapped blocks will be processed separately.
	 * @param block memory block
	 * @param scanAllMappedBlocksIfNeeded if true and block is initialized and not a mapped block all
	 * mapped blocks will be processed for possible introduction of newly initialized mapped regions. 
	 */
	private void addBlockAddresses(MemoryBlockDB block, boolean scanAllMappedBlocksIfNeeded) {
		AddressSet blockSet = new AddressSet(block.getStart(), block.getEnd());
		addrSet = addrSet.union(blockSet);
		if (block.isMapped()) {

			// Identify source-blocks which block maps onto and add as a mapped-block to each of these
			AddressRange mappedRange = block.getSourceInfos().get(0).getMappedRange().get();
			for (MemoryBlockDB b : getBlocks(mappedRange.getMinAddress(),
				mappedRange.getMaxAddress())) {
				b.addMappedBlock(block);
			}

			AddressSet mappedSet = getMappedIntersection(block, allInitializedAddrSet);
			allInitializedAddrSet = allInitializedAddrSet.union(mappedSet);
			initializedLoadedAddrSet = initializedLoadedAddrSet.union(
				getMappedIntersection(block, initializedLoadedAddrSet));
		}
		else if (block.isInitialized()) {
			allInitializedAddrSet = allInitializedAddrSet.union(blockSet);
			if (block.isLoaded()) {
				initializedLoadedAddrSet = initializedLoadedAddrSet.union(blockSet);
			}
			if (scanAllMappedBlocksIfNeeded) {
				// If only adding one initialized non-mapped-block we must scan all mapped-blocks
				// which may utilize block as a byte source
				for (MemoryBlockDB b : blocks) {
					b.clearMappedBlockList();
				}
				for (MemoryBlockDB b : blocks) {
					if (b.isMapped()) {
						addBlockAddresses(b, false);
					}
				}
			}
		}
	}

	/**
	 * Update initialized address set for those mapped blocks which map onto the 
	 * specified block which has just completed a transition of its' initialized state.
	 * @param block block whose initialized state has changed
	 * @param isInitialized true if block transitioned from uninitialized to initialized,
	 * else transition is from initialized to uninitialized.
	 */
	private void updateMappedAddresses(MemoryBlockDB block, boolean isInitialized) {

		Collection<MemoryBlockDB> mappedBlocks = block.getMappedBlocks();
		if (mappedBlocks == null) {
			return;
		}

		AddressSet blockSet = new AddressSet(block.getStart(), block.getEnd());
		boolean isLoaded = block.getStart().isLoadedMemoryAddress();

		for (MemoryBlockDB mappedBlock : block.getMappedBlocks()) {
			AddressSet mappedSet = getMappedIntersection(mappedBlock, blockSet);
			if (isInitialized) {
				allInitializedAddrSet = allInitializedAddrSet.union(mappedSet);
				if (isLoaded) {
					initializedLoadedAddrSet = initializedLoadedAddrSet.union(mappedSet);
				}
			}
			else {
				allInitializedAddrSet = allInitializedAddrSet.subtract(mappedSet);
				if (isLoaded) {
					initializedLoadedAddrSet = initializedLoadedAddrSet.union(mappedSet);
				}
			}
		}
	}

	private void reloadAll() throws IOException {
		synchronized (this) {
			fileBytesAdapter.refresh();
			adapter.refreshMemory();
			initializeBlocks();
			buildAddressSets();
		}
		if (liveMemory != null) {
			liveMemory.clearCache();
		}
		addrMap.memoryMapChanged(this);
	}

	private synchronized void initializeBlocks() {
		List<MemoryBlockDB> newBlocks = adapter.getMemoryBlocks();
		lastBlock = null;
		blocks = newBlocks;
		nameBlockMap = new HashMap<>();
		executeSet = null;
		addrMap.memoryMapChanged(this);
	}

	public void setLanguage(Language newLanguage) {
		defaultEndian = newLanguage.isBigEndian() ? BIG_ENDIAN : LITTLE_ENDIAN;
	}

	/**
	 * Set the program.
	 */
	@Override
	public void setProgram(ProgramDB program) {
		this.program = program;
		try {
			reloadAll();
		}
		catch (IOException e) {
			dbError(e);
		}
	}

	@Override
	public void programReady(int openMode, int currentRevision, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (openMode == DBConstants.UPGRADE) {
			// Ensure that the key has been generated for the end address of each block
			// This will allow undefined data to be returned for all address contained
			// within any 32-bit block (see CodeManager handling of AddressMap.INVALID_ADDRESS_KEY).
			for (MemoryBlock block : blocks) {
				addrMap.getKey(block.getEnd(), true);
			}
		}
	}

	void dbError(IOException e) {
		program.dbError(e);
	}

	/**
	 * Returns the address factory for the program.
	 * @return program address factory
	 */
	AddressFactory getAddressFactory() {
		return addrMap.getAddressFactory();
	}

	/**
	 * Returns the AddressMap from the program.
	 * @return program address map
	 */
	AddressMapDB getAddressMap() {
		return addrMap;
	}

	@Override
	public AddressSetView getInitializedAddressSet() {
		return getLoadedAndInitializedAddressSet();
	}

	@Override
	public AddressSetView getAllInitializedAddressSet() {
		return new AddressSetViewAdapter(allInitializedAddrSet);
	}

	@Override
	public AddressSetView getLoadedAndInitializedAddressSet() {
		if (liveMemory != null) {
			return this;//all memory is initialized!
		}
		return new AddressSetViewAdapter(initializedLoadedAddrSet);
	}

	void checkMemoryWrite(MemoryBlockDB block, Address start, long length)
			throws MemoryAccessException {

		if (!block.contains(start)) {
			throw new MemoryAccessException(
				block.getName() + " does not contain address " + start.toString(true));
		}

		try {
			Address endAddr = start.addNoWrap(length - 1);
			if (!block.contains(start)) {
				throw new MemoryAccessException(block.getName() + " does not contain range " +
					start.toString(true) + "-" + endAddr);
			}
			
			if (block.isMapped()) {
				checkMemoryWriteMappedBlock(block, start, endAddr);
			}
			else {
				checkMemoryWriteNonMappedBlock(block, start, endAddr);
			}
		}
		catch (AddressOverflowException e) {
			throw new MemoryAccessException("invalid address range specified for address " +
				start.toString(true) + " (length: " + length + ")");
		}
	}

	private void checkMemoryWriteMappedBlock(MemoryBlockDB mappedBlock, Address start,
			Address endAddr)
			throws AddressOverflowException, MemoryAccessException {
		long startOffset = start.subtract(mappedBlock.getStart());
		long endOffset = endAddr.subtract(mappedBlock.getStart());

		// determine source block(s) for mapped block
		MemoryBlockSourceInfo info = mappedBlock.getSourceInfos().get(0);
		AddressRange mappedRange = info.getMappedRange().get();
		Address mappedRangeMinAddr = mappedRange.getMinAddress();

		Address mappedStartAddress, mappedEndAddress;
		if (mappedBlock.getType() == MemoryBlockType.BIT_MAPPED) {
			mappedStartAddress = mappedRangeMinAddr.addNoWrap(startOffset / 8);
			mappedEndAddress = mappedRangeMinAddr.addNoWrap(endOffset / 8);
		}
		else { // BYTE_MAPPED
			ByteMappingScheme byteMappingScheme = info.getByteMappingScheme().get();
			mappedStartAddress =
				byteMappingScheme.getMappedSourceAddress(mappedRangeMinAddr, startOffset);
			mappedEndAddress =
				byteMappingScheme.getMappedSourceAddress(mappedRangeMinAddr, endOffset);
		}
		
		for (MemoryBlockDB b : getBlocks(mappedStartAddress, mappedEndAddress)) {
			Address minAddr = Address.min(b.getEnd(), mappedEndAddress);
			Address maxAddr = Address.max(b.getStart(), mappedStartAddress);
			checkMemoryWrite(b, minAddr, maxAddr.subtract(minAddr) + 1);
		}
	}

	private void checkMemoryWriteNonMappedBlock(MemoryBlockDB nonMappedBlock, Address start,
			Address endAddr)
			throws MemoryAccessException {
		// TODO: could contain uninitialized region which is illegal to write to although block.isInitialized
		// may not be of much help since it reflects the first sub-block only - seems like mixing is a bad idea
		
		checkRangeForInstructions(start, endAddr);
		
		// Check all mapped-block address ranges which map onto the range to be modified
		Collection<MemoryBlockDB> mappedBlocks = nonMappedBlock.getMappedBlocks();
		if (mappedBlocks != null) {
			for (MemoryBlockDB mappedBlock : mappedBlocks) {

				// Determine source intersection with mapped block
				MemoryBlockSourceInfo info = mappedBlock.getSourceInfos().get(0);
				AddressRange mappedRange = info.getMappedRange().get();
				mappedRange = mappedRange.intersectRange(start, endAddr);
				if (mappedRange == null) {
					continue; // no intersection with range of interest
				}
				AddressRange range = getMappedRange(mappedBlock, mappedRange);
				if (range == null) {
					continue; // unexpected
				}
				checkRangeForInstructions(range.getMinAddress(), range.getMaxAddress());
			}
		}
	}

	@Override
	public MemoryBlock getBlock(Address addr) {
		return getBlockDB(addr);
	}

	@Override
	public synchronized MemoryBlock getBlock(String blockName) {
		// find block that might have been cached from previous call
		MemoryBlock memoryBlock = nameBlockMap.get(blockName);
		if (memoryBlock != null) {
			if (memoryBlock == NoBlock) {
				// found placeholder, have searched and found nothing before
				return null;
			}
			return memoryBlock;
		}

		for (MemoryBlock block : blocks) {
			if (block.getName().equals(blockName)) {
				nameBlockMap.put(blockName, block);
				return block;
			}
		}

		// store placeholder there is no memory block with that name
		nameBlockMap.put(blockName, NoBlock);
		return null;
	}

	private synchronized MemoryBlock getBlockDB(Address addr) {
		if (lastBlock != null) {
			if (lastBlock.contains(addr)) {
				return lastBlock;
			}
		}
		List<MemoryBlockDB> tmpBlocks = blocks;
		int index = Collections.binarySearch(tmpBlocks, addr, BLOCK_ADDRESS_COMPARATOR);
		if (index >= 0) {
			lastBlock = tmpBlocks.get(index);
			return lastBlock;
		}
		index = -index - 2;
		if (index >= 0) {
			MemoryBlock block = tmpBlocks.get(index);
			if (block.contains(addr)) {
				lastBlock = block;
				return block;
			}
		}
		return null;
	}

	void fireBlockAdded(MemoryBlock newBlock) {
		AddressRange range = new AddressRangeImpl(newBlock.getStart(), newBlock.getEnd());
		program.getTreeManager().addMemoryBlock(newBlock.getName(), range);
		program.setChanged(ChangeManager.DOCR_MEMORY_BLOCK_ADDED, newBlock.getStart(),
			newBlock.getEnd(), null, null);
		program.fireEvent(new DomainObjectChangeRecord(DomainObject.DO_OBJECT_RESTORED));
	}

	void fireBlockSplit() {
		program.fireEvent(new DomainObjectChangeRecord(DomainObject.DO_OBJECT_RESTORED));
	}

	void fireBlockRemoved(Address blockStartAddr) {
		program.setChanged(ChangeManager.DOCR_MEMORY_BLOCK_REMOVED, blockStartAddr, null);
		program.fireEvent(new DomainObjectChangeRecord(DomainObject.DO_OBJECT_RESTORED));
	}

	void fireBlockMoved(MemoryBlockDB block, Address oldStartAddr) {
		program.setChanged(ChangeManager.DOCR_MEMORY_BLOCKS_JOINED, oldStartAddr, block);
		program.fireEvent(new DomainObjectChangeRecord(DomainObject.DO_OBJECT_RESTORED));
	}

	/**
	 * Two blocks have been joined producing newBlock.  The block which was
	 * eliminated can be identified using the oldBlockStartAddr.
	 * @param newBlock new joined memory block
	 * @param oldBlockStartAddr original start address of affected block
	 */
	void fireBlocksJoined(MemoryBlock newBlock, Address oldBlockStartAddr) {
		program.setChanged(ChangeManager.DOCR_MEMORY_BLOCKS_JOINED, oldBlockStartAddr, newBlock);
	}

	void fireBlockSplit(MemoryBlockDB originalBlock, MemoryBlockDB newBlock) {
		program.setChanged(ChangeManager.DOCR_MEMORY_BLOCK_SPLIT, null, null, originalBlock,
			newBlock);
	}

	void fireBlockChanged(MemoryBlock block) {
		if (program != null) {
			program.setChanged(ChangeManager.DOCR_MEMORY_BLOCK_CHANGED, block, null);
		}

		// name could have changed
		nameBlockMap = new HashMap<>();

		// don't regenerate now, do lazily later if needed
		executeSet = null;
	}

	void fireBytesChanged(Address addr, int count) {
		lock.acquire();
		try {
			Address end = addr.addNoWrap(count - 1);

			program.getCodeManager().memoryChanged(addr, end);
			program.setChanged(ChangeManager.DOCR_MEMORY_BYTES_CHANGED, addr, end, null, null);

		}
		catch (AddressOverflowException e) {
			// shouldn't happen
			throw new AssertException(e.getMessage());
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean isBigEndian() {
		return defaultEndian == BIG_ENDIAN;
	}

	@Override
	public void setLiveMemoryHandler(LiveMemoryHandler handler) {
		lock.acquire();
		try {
			if (liveMemory != null) {
				liveMemory.removeLiveMemoryListener(this);
			}
			liveMemory = handler;
			if (liveMemory != null) {
				liveMemory.addLiveMemoryListener(this);
			}
			program.invalidate();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public LiveMemoryHandler getLiveMemoryHandler() {
		return liveMemory;
	}

	@Override
	public MemoryBlock createInitializedBlock(String name, Address start, long size,
			byte initialValue, TaskMonitor monitor, boolean overlay)
			throws LockException, MemoryConflictException, AddressOverflowException,
			CancelledException {

		InputStream fillStream = null;
		if (initialValue != 0) {
			final int fillByte = initialValue & 0xff;
			fillStream = new InputStream() {
				@Override
				public int read() throws IOException {
					return fillByte;
				}
			};
		}
		return createInitializedBlock(name, start, fillStream, size, monitor, overlay);
	}

	private Address createOverlaySpace(String name, Address start, long dataLength)
			throws MemoryConflictException, AddressOverflowException, LockException {

		start.addNoWrap(dataLength - 1);// just tests the AddressOverflow condition.

		AddressSpace ovSpace = program.addOverlaySpace(name, start.getAddressSpace(),
			start.getOffset(), start.getOffset() + (dataLength - 1));

		Address ovAddr = ovSpace.getAddress(start.getOffset());
		return ovAddr;
	}

	@Override
	public MemoryBlock createInitializedBlock(String name, Address start, InputStream is,
			long length, TaskMonitor monitor, boolean overlay) throws MemoryConflictException,
			AddressOverflowException, CancelledException, LockException {
		checkBlockName(name);
		lock.acquire();
		try {
			checkBlockSize(length, true);

			program.checkExclusiveAccess();
			if (monitor != null && is != null) {
				is = new MonitoredInputStream(is, monitor);
			}
			if (overlay) {
				start = createOverlaySpace(name, start, length);
			}
			else {
				checkRange(start, length);
			}
			try {
				MemoryBlockDB newBlock =
					adapter.createInitializedBlock(name, start, is, length, MemoryBlock.READ);
				initializeBlocks();
				addBlockAddresses(newBlock, !overlay);
				fireBlockAdded(newBlock);
				return newBlock;
			}
			catch (IOCancelledException e) {
				// this assumes the adapter has already cleaned up any partially created buffers.
				if (overlay) {
					checkRemoveAddressSpace(start.getAddressSpace());
				}
				throw new CancelledException();
			}
			catch (IOException e) {
				program.dbError(e);
			}

			return null;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public MemoryBlock createInitializedBlock(String name, Address start, FileBytes fileBytes,
			long offset, long length, boolean overlay) throws LockException,
			MemoryConflictException, AddressOverflowException, IndexOutOfBoundsException {

		checkBlockName(name);
		lock.acquire();
		try {
			checkBlockSize(length, true);
			program.checkExclusiveAccess();
			checkFileBytesRange(fileBytes, offset, length);

			if (overlay) {
				start = createOverlaySpace(name, start, length);
			}
			else {
				checkRange(start, length);
			}
			try {
				MemoryBlockDB newBlock = adapter.createFileBytesBlock(name, start, length,
					fileBytes, offset, MemoryBlock.READ);
				initializeBlocks();
				addBlockAddresses(newBlock, !overlay);
				fireBlockAdded(newBlock);
				return newBlock;
			}
			catch (IOException e) {
				program.dbError(e);
			}

			return null;
		}
		finally {
			lock.release();
		}
	}

	private void checkFileBytesRange(FileBytes fileBytes, long offset, long length) {
		if (length <= 0) {
			throw new IllegalArgumentException("Length must be > 0, got " + length);
		}
		if (offset < 0 || offset >= fileBytes.getSize()) {
			long limit = fileBytes.getSize() - 1;
			throw new IndexOutOfBoundsException(
				"Offset must be in range [0," + limit + "], got " + offset);
		}
		if (offset + length > fileBytes.getSize()) {
			throw new IndexOutOfBoundsException(
				"Specified length extends beyond file bytes length");
		}

	}

	@Override
	public MemoryBlock createUninitializedBlock(String name, Address start, long size,
			boolean overlay) throws MemoryConflictException, AddressOverflowException,
			LockException {

		checkBlockName(name);
		lock.acquire();
		try {
			checkBlockSize(size, false);

			program.checkExclusiveAccess();

			if (overlay) {
				start = createOverlaySpace(name, start, size);
			}
			else {
				checkRange(start, size);
			}
			try {
				MemoryBlockDB newBlock = adapter.createBlock(MemoryBlockType.DEFAULT, name, start,
					size, null, false, MemoryBlock.READ, 0);
				initializeBlocks();
				addBlockAddresses(newBlock, false);
				fireBlockAdded(newBlock);
				return newBlock;
			}
			catch (IOException e) {
				program.dbError(e);
			}
		}
		finally {
			lock.release();
		}
		return null;
	}

	@Override
	public MemoryBlock createBitMappedBlock(String name, Address start, Address mappedAddress,
			long length, boolean overlay) throws MemoryConflictException, AddressOverflowException,
			LockException, IllegalArgumentException {

		checkBlockName(name);
		lock.acquire();
		try {
			checkBlockSize(length, false);
			program.checkExclusiveAccess();
			mappedAddress.addNoWrap((length - 1) / 8);// just to check if length fits in address space
			if (overlay) {
				start = createOverlaySpace(name, start, length);
			}
			else {
				checkRange(start, length);
			}
			try {
				MemoryBlockDB newBlock = adapter.createBlock(MemoryBlockType.BIT_MAPPED, name,
					start, length, mappedAddress, false, MemoryBlock.READ, 0);
				initializeBlocks();
				addBlockAddresses(newBlock, false);
				fireBlockAdded(newBlock);
				return newBlock;
			}
			catch (IOException e) {
				program.dbError(e);
			}
		}
		finally {
			lock.release();
		}
		return null;
	}

	@Override
	public MemoryBlock createByteMappedBlock(String name, Address start, Address mappedAddress,
			long length, ByteMappingScheme byteMappingScheme, boolean overlay)
			throws MemoryConflictException, AddressOverflowException, LockException {

		checkBlockName(name);

		int mappingScheme = 0; // use for 1:1 mapping
		if (byteMappingScheme == null) {
			byteMappingScheme = new ByteMappingScheme(mappingScheme); // 1:1 mapping
		}
		else if (!byteMappingScheme.isOneToOneMapping()) {
			mappingScheme = byteMappingScheme.getEncodedMappingScheme();
		}

		lock.acquire();
		try {
			checkBlockSize(length, false);
			program.checkExclusiveAccess();
			byteMappingScheme.getMappedSourceAddress(mappedAddress, length - 1); // source fit check
			if (overlay) {
				start = createOverlaySpace(name, start, length);
			}
			else {
				checkRange(start, length);
			}
			try {
				MemoryBlockDB newBlock = adapter.createBlock(MemoryBlockType.BYTE_MAPPED, name,
					start, length, mappedAddress, false, MemoryBlock.READ, mappingScheme);
				initializeBlocks();
				addBlockAddresses(newBlock, false);
				fireBlockAdded(newBlock);
				return newBlock;
			}
			catch (IOException e) {
				program.dbError(e);
			}
		}
		finally {
			lock.release();
		}
		return null;
	}

	/**
	 * Check new block name for validity
	 * @param name new block name
	 * @throws IllegalArgumentException if invalid block name specified
	 */
	void checkBlockName(String name) throws IllegalArgumentException {
		if (!Memory.isValidMemoryBlockName(name)) {
			throw new IllegalArgumentException("Invalid block name: " + name);
		}
	}

	@Override
	public MemoryBlock createBlock(MemoryBlock block, String name, Address start, long length)
			throws MemoryConflictException, AddressOverflowException, LockException {
		checkBlockName(name);
		lock.acquire();
		try {
			checkBlockSize(length, block.isInitialized());
			program.checkExclusiveAccess();
			checkRange(start, length);
			try {
				Address mappedAddr = null;
				int mappingScheme = 0;
				if (block.isMapped()) {
					MemoryBlockSourceInfo info = block.getSourceInfos().get(0);
					if (block.getType() == MemoryBlockType.BYTE_MAPPED) {
						mappingScheme = info.getByteMappingScheme().get().getEncodedMappingScheme();
					}
					mappedAddr = info.getMappedRange().get().getMinAddress();
				}
				MemoryBlockDB newBlock = adapter.createBlock(block.getType(), name, start, length,
					mappedAddr, block.isInitialized(), block.getPermissions(), mappingScheme);
				initializeBlocks();
				addBlockAddresses(newBlock, !block.isMapped() && block.isInitialized());
				fireBlockAdded(newBlock);
				return newBlock;
			}
			catch (IOException e) {
				program.dbError(e);
			}
			return null;

		}
		finally {
			lock.release();
		}
	}

	@Override
	public long getSize() {
		return addrSet.getNumAddresses();
	}

	@Override
	public MemoryBlock[] getBlocks() {
		lock.acquire();
		try {
			return blocks.toArray(new MemoryBlock[blocks.size()]);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void moveBlock(MemoryBlock block, Address newStartAddr, TaskMonitor monitor)
			throws MemoryBlockException, MemoryConflictException, AddressOverflowException,
			NotFoundException, LockException {
		lock.acquire();
		try {
			program.checkExclusiveAccess();
			if (liveMemory != null) {
				throw new MemoryBlockException(
					"Memory move operation not permitted while live memory is active");
			}
			checkBlock(block);
			MemoryBlockDB memBlock = (MemoryBlockDB) block;

			Address oldStartAddr = block.getStart();
			if (block.isOverlay()) {
				throw new IllegalArgumentException("Overlay blocks cannot be moved");
			}
			if (newStartAddr.getAddressSpace().isOverlaySpace()) {
				throw new IllegalArgumentException("Can not move a block into an overlay space.");
			}

			program.setEventsEnabled(false);// ensure that no domain object change
			// events go out that would cause screen updates;
			// the code manager will be locked until the remove is done
			try {
				Address newEndAddr = newStartAddr.addNoWrap(block.getSize() - 1);
				AddressSet set = new AddressSet(addrSet);
				set.deleteRange(block.getStart(), block.getEnd());
				if (set.intersects(newStartAddr, newEndAddr)) {
					throw new MemoryConflictException(
						"Block move conflicts with other existing memory block");
				}
				try {
					memBlock.setStartAddress(newStartAddr);
					reloadAll();
				}
				catch (IOException e) {
					program.dbError(e);
				}
				program.moveAddressRange(oldStartAddr, newStartAddr, memBlock.getSize(), monitor);
			}
			finally {
				program.invalidate();
				program.setEventsEnabled(true);
			}
			fireBlockMoved(memBlock, oldStartAddr);

		}
		finally {
			lock.release();
		}
	}

	@Override
	public void split(MemoryBlock block, Address addr)
			throws MemoryBlockException, NotFoundException, LockException {
		lock.acquire();
		try {
			program.checkExclusiveAccess();
			if (liveMemory != null) {
				throw new MemoryBlockException(
					"Memory split operation not permitted while live memory is active");
			}
			checkBlock(block);
			MemoryBlockDB memBlock = (MemoryBlockDB) block;
			if (!memBlock.contains(addr)) {
				throw new IllegalArgumentException("Block must contain split address");
			}
			if (addr.equals(memBlock.getStart())) {
				throw new IllegalArgumentException("Split cannot be done on block start address");
			}
			if (memBlock.isOverlay()) {
				throw new IllegalArgumentException("Split cannot be done on an overlay block");
			}
			if (memBlock.isMapped()) {
				if (memBlock.getType() == MemoryBlockType.BIT_MAPPED) {
					throw new IllegalArgumentException(
						"Split cannot be done on a bit-mapped block");
				}
				ByteMappingScheme byteMappingScheme =
					memBlock.getSourceInfos().get(0).getByteMappingScheme().get();
				if (!byteMappingScheme.isOneToOneMapping()) {
					throw new IllegalArgumentException(
						"Split cannot be done on a byte-mapped block with " + byteMappingScheme);
				}
			}
			if (memBlock.getType() == MemoryBlockType.BIT_MAPPED) {
				throw new IllegalArgumentException("Split cannot be done on a bit mapped block");
			}
			try {
				memBlock.split(addr);
				initializeBlocks();
				fireBlockSplit();
			}
			catch (IOException e) {
				program.dbError(e);
			}

		}
		finally {
			lock.release();
		}

	}

	@Override
	public MemoryBlock join(MemoryBlock blockOne, MemoryBlock blockTwo)
			throws MemoryBlockException, NotFoundException, LockException {
		lock.acquire();
		try {
			// swap if second block is before first block
			if (blockOne.getStart().compareTo(blockTwo.getStart()) > 0) {
				MemoryBlock tmp = blockOne;
				blockOne = blockTwo;
				blockTwo = tmp;
			}

			checkPreconditionsForJoining(blockOne, blockTwo);

			MemoryBlockDB memBlock1 = (MemoryBlockDB) blockOne;
			MemoryBlockDB memBlock2 = (MemoryBlockDB) blockTwo;

			Address block1Addr = blockOne.getStart();
			Address block2Addr = blockTwo.getStart();

			MemoryBlock newBlock = null;
			try {
				memBlock1.join(memBlock2);
				reloadAll();
				newBlock = getBlockDB(block1Addr);
				fireBlocksJoined(newBlock, block2Addr);

			}
			catch (IOException e) {
				program.dbError(e);
			}
			return newBlock;
		}
		finally {
			lock.release();
		}

	}

	private void checkPreconditionsForJoining(MemoryBlock block1, MemoryBlock block2)
			throws MemoryBlockException, LockException {

		program.checkExclusiveAccess();
		if (liveMemory != null) {
			throw new MemoryBlockException(
				"Memory join operation not permitted while live memory is active");
		}

		checkBlockForJoining(block1);
		checkBlockForJoining(block2);

		if (block1.isInitialized() != block2.isInitialized()) {
			throw new MemoryBlockException(
				"Both blocks must be either initialized or uninitialized");
		}

		if (!(block1.getEnd().isSuccessor(block2.getStart()))) {
			throw new MemoryBlockException("Blocks are not contiguous");
		}

	}

	private void checkBlockForJoining(MemoryBlock block) {
		checkBlock(block);
		if (block.isOverlay()) {
			throw new IllegalArgumentException("Cannot join overlay blocks");
		}
		if (block.isMapped()) {
			throw new IllegalArgumentException("Cannot join mapped blocks");
		}
	}

	private void checkBlock(MemoryBlock block) {
		if (!(block instanceof MemoryBlockDB)) {
			throw new IllegalArgumentException("Blocks do not belong to this program");
		}
		MemoryBlockDB blockDB = (MemoryBlockDB) block;
		if (blockDB.memMap != this) {
			throw new IllegalArgumentException("Blocks do not belong to this program");
		}
		blockDB.checkValid();
	}

	@Override
	public MemoryBlock convertToInitialized(MemoryBlock unitializedBlock, byte initialValue)
			throws MemoryBlockException, NotFoundException, LockException {
		lock.acquire();
		try {
			checkBlock(unitializedBlock);
			program.checkExclusiveAccess();
			if (unitializedBlock.isInitialized()) {
				throw new IllegalArgumentException(
					"Only an Uninitialized Block may be converted to an Initialized Block");
			}
			if (unitializedBlock.getType() != MemoryBlockType.DEFAULT) {
				throw new IllegalArgumentException("Block is of a type that cannot be initialized");
			}
			long size = unitializedBlock.getSize();
			if (size > MAX_BLOCK_SIZE) {
				throw new MemoryBlockException("Block too large to initialize");
			}
			MemoryBlockDB memBlock = (MemoryBlockDB) unitializedBlock;
			try {
				memBlock.initializeBlock(initialValue);
				allInitializedAddrSet.addRange(memBlock.getStart(), memBlock.getEnd());
				initializedLoadedAddrSet.addRange(memBlock.getStart(), memBlock.getEnd());
				if (!memBlock.isMapped()) {
					// update initialized sets for all blocks mapped to memBlock
					updateMappedAddresses(memBlock, true);
				}
				fireBlockChanged(memBlock);
				fireBytesChanged(memBlock.getStart(), (int) memBlock.getSize());
				return memBlock;
			}
			catch (IOException e) {
				program.dbError(e);
			}
			return null;

		}
		finally {
			lock.release();
		}

	}

	@Override
	public MemoryBlock convertToUninitialized(MemoryBlock initializedBlock)
			throws MemoryBlockException, NotFoundException, LockException {
		lock.acquire();
		try {
			program.checkExclusiveAccess();
			checkBlock(initializedBlock);
			if (!initializedBlock.isInitialized()) {
				throw new IllegalArgumentException(
					"Only an Initialized Block may be converted to an Uninitialized Block");
			}
			if (initializedBlock.getType() != MemoryBlockType.DEFAULT) {
				throw new IllegalArgumentException(
					"Block is of a type that cannot be uninitialized");
			}
			MemoryBlockDB memBlock = (MemoryBlockDB) initializedBlock;
			try {
// FIXME: clear instructions in initializedBlock or any block which maps to it
				memBlock.uninitializeBlock();
				allInitializedAddrSet.deleteRange(memBlock.getStart(), memBlock.getEnd());
				initializedLoadedAddrSet.deleteRange(memBlock.getStart(), memBlock.getEnd());
				if (!memBlock.isMapped()) {
					// update initialized sets for all blocks mapped to memBlock
					updateMappedAddresses(memBlock, false);
				}
				fireBlockChanged(memBlock);
				fireBytesChanged(memBlock.getStart(), (int) memBlock.getSize());
				return memBlock;
			}
			catch (IOException e) {
				program.dbError(e);
			}
			return null;

		}
		finally {
			lock.release();
		}

	}

	@Override
	public Address findBytes(Address addr, byte[] bytes, byte[] masks, boolean forward,
			TaskMonitor monitor) {
		if (monitor == null) {
			monitor = TaskMonitor.DUMMY;
		}

		AddressIterator it = initializedLoadedAddrSet.getAddresses(addr, forward);
		byte[] b = new byte[bytes.length];
		if (forward) {
			while (it.hasNext() && !monitor.isCancelled()) {
				Address addr2 = it.next();
				int moffset = match(addr2, bytes, masks, b, forward);
				if (moffset < 0) {
					try {
						Address jumpAddr = addr2.addNoWrap(-moffset);
						if (jumpAddr.hasSameAddressSpace(addr2)) {
							it = initializedLoadedAddrSet.getAddresses(jumpAddr, forward);
						}
						monitor.incrementProgress(-moffset);
					}
					catch (AddressOverflowException e) {
						// ignore
					}
					continue;
				}
				if (moffset == 1) {
					return addr2;
				}

				monitor.incrementProgress(moffset);
			}
		}
		else {
			while (it.hasNext() && !monitor.isCancelled()) {
				Address addr2 = it.next();
				int moffset = match(addr2, bytes, masks, b, forward);
				if (moffset == 1) {
					return addr2;
				}

				monitor.incrementProgress(moffset);
			}
		}
		return null;
	}

	@Override
	public Address findBytes(Address startAddr, Address endAddr, byte[] bytes, byte[] masks,
			boolean forward, TaskMonitor monitor) {
		if (monitor == null) {
			monitor = TaskMonitor.DUMMY;
		}
		AddressIterator it = allInitializedAddrSet.getAddresses(startAddr, forward);
		byte[] b = new byte[bytes.length];
		if (forward) {
			while (it.hasNext() && !monitor.isCancelled()) {
				Address addr2 = it.next();
				if (addr2.compareTo(endAddr) > 0) {
					return null;
				}
				int moffset = match(addr2, bytes, masks, b, forward);
				if (moffset < 0) {
					try {
						Address jumpAddr = addr2.addNoWrap(-moffset);
						if (jumpAddr.hasSameAddressSpace(addr2)) {
							it = allInitializedAddrSet.getAddresses(jumpAddr, forward);
						}
						monitor.incrementProgress(-moffset);
					}
					catch (AddressOverflowException e) {
						moffset = -moffset;
						for (int i = 0; i < moffset; i++) {
							if (it.hasNext()) {
								it.next();
							}
							else {
								break;
							}
						}
						monitor.incrementProgress(moffset);
					}
					continue;
				}
				if (moffset == 1) {
					return addr2;
				}

				// No match, and we're going to move to the next address so increment our
				// progress by 1.
				monitor.incrementProgress(1);
			}
		}
		else {
			while (it.hasNext() && !monitor.isCancelled()) {
				Address addr2 = it.next();
				if (addr2.compareTo(endAddr) < 0) {
					return null;
				}
				int moffset = match(addr2, bytes, masks, b, forward);
				if (moffset == 1) {
					return addr2;
				}

				// If we're here, then no match was found so just increment to the monitor
				// by 1 (one address).
				monitor.incrementProgress(1);
			}
		}
		return null;
	}

	/**
	 * Tests if the memory contains a sequence of contiguous bytes that match the
	 * given byte array at all bit positions where the mask contains an "on" bit.
	 * The test will be something like
	 *
	 * for(int i=0;i<bytes.length;i++) {
	 *     if (bytes[i] != memory.getByte(addr+i) &amp; masks[i]) {
	 *         return false;
	 *     }
	 * }
	 * return false;
	 *
	 * @param addr The beginning address in memory to test against.
	 * @param bytes the array of bytes to test for.
	 * @param masks the array of masks. (One for each byte in the byte array)
	 * @param forward if true, the matching is going forward, otherwise backward
	 *
	 * @return 1 if there is a match
	 *         0 if there is no match
	 *        -i if no match is found, this is the number of bytes that can be safely skipped
	 */
	private int match(Address addr, byte[] bytes, byte[] masks, byte[] data, boolean forward) {
		try {
			if (getBytes(addr, data) < data.length) {
				return 0;
			}

			//
			// if there is no mask, check is simpler
			//
			if (masks == null) {
				// check if the bytes pattern entirely matches the data
				if (Arrays.equals(data, bytes)) {
					return 1;
				}

				if (!forward) {
					return 0;
				}

				// check to see if the first byte of the pattern
				// matches any byte in the buffer
				//  if it does, return it's negative offset
				for (int j = 1; j < bytes.length; j++) {
					int off = 0;
					for (; off < (data.length - j); off++) {
						if (bytes[off] != data[j + off]) {
							break;
						}
					}
					if (off + j == data.length) {
						return -j;
					}
				}
				return -bytes.length;
			}

			// first check if the pattern entirely matches the bytes
			int i;
			for (i = 0; i < bytes.length; i++) {
				if ((data[i] & masks[i]) != (bytes[i] & masks[i])) {
					break;
				}
			}
			if (i == bytes.length) {
				return 1;
			}

			if (!forward) {
				return 0;
			}

			// check to see if the first byte of the pattern
			// matches any byte in the buffer
			//  if it does, return it's negative offset
			for (int j = 1; j < bytes.length; j++) {
				int off = 0;
				for (; off < (data.length - j); off++) {
					if ((bytes[off] & masks[off]) != (data[j + off] & masks[off])) {
						break;
					}
				}
				if (off + j == data.length) {
					return -j;
				}
			}
			return -bytes.length;
		}
		catch (Exception e) {
			return 0;
		}
	}

	@Override
	public byte getByte(Address addr) throws MemoryAccessException {
		lock.acquire();
		try {
			if (liveMemory != null) {
				return liveMemory.getByte(addr);
			}
			MemoryBlock block = getBlockDB(addr);
			if (block == null) {
				throw new MemoryAccessException(
					"Address " + addr.toString(true) + " does not exist in memory");
			}
			return block.getByte(addr);
		}
		finally {
			lock.release();
		}

	}

	@Override
	public int getBytes(Address addr, byte[] dest) throws MemoryAccessException {
		return getBytes(addr, dest, 0, dest.length);
	}

	@Override
	public int getBytes(Address addr, byte[] dest, int dIndex, int size)
			throws MemoryAccessException {
		if (liveMemory != null) {
			return liveMemory.getBytes(addr, dest, dIndex, size);
		}
		int numRead = 0;
		long lastRead = 0;
		while (numRead < size) {
			try {
				addr = addr.addNoWrap(lastRead);
				MemoryBlock block = getBlock(addr);
				if (block == null) {
					break;
				}
				if (block.isInitialized() || block.isMapped()) {
					lastRead = block.getBytes(addr, dest, numRead + dIndex, size - numRead);
				}
				else {
					break;
				}
				numRead += lastRead;
			}
			catch (AddressOverflowException e) {
				break;
			}
		}
		if (numRead == 0 && size > 0) {
			throw new MemoryAccessException("Unable to read bytes at " + addr.toString(true));
		}
		return numRead;
	}

	@Override
	public short getShort(Address addr) throws MemoryAccessException {
		byte[] byteBuf = new byte[2];
		int n = getBytes(addr, byteBuf, 0, 2);
		if (n != 2) {
			throw new MemoryAccessException("Could not get short at " + addr.toString(true));
		}
		return defaultEndian.getShort(byteBuf);
	}

	@Override
	public short getShort(Address addr, boolean isBigEndian) throws MemoryAccessException {
		byte[] byteBuf = new byte[2];
		int n = getBytes(addr, byteBuf, 0, 2);
		if (n != 2) {
			throw new MemoryAccessException("Could not get short at " + addr.toString(true));
		}
		if (isBigEndian) {
			return BIG_ENDIAN.getShort(byteBuf);
		}
		return LITTLE_ENDIAN.getShort(byteBuf);
	}

	@Override
	public int getShorts(Address addr, short[] dest) throws MemoryAccessException {
		return getShorts(addr, dest, 0, dest.length);
	}

	@Override
	public int getShorts(Address addr, short[] dest, int dIndex, int nElem)
			throws MemoryAccessException {
		byte[] byteBuf = new byte[2 * nElem];
		int n = getBytes(addr, byteBuf, 0, byteBuf.length);
		if (n < 2) {
			throw new MemoryAccessException("Could not read shorts at " + addr.toString(true));
		}
		// round down
		n = n / 2;
		for (int i = 0; i < 2 * n; i += 2) {
			dest[dIndex + i / 2] = defaultEndian.getShort(byteBuf, i);
		}
		return n;
	}

	@Override
	public int getShorts(Address addr, short[] dest, int dIndex, int nElem, boolean isBigEndian)
			throws MemoryAccessException {
		byte[] byteBuf = new byte[2 * nElem];
		int n = getBytes(addr, byteBuf, 0, byteBuf.length);
		if (n < 2) {
			throw new MemoryAccessException("Could not read shorts at " + addr.toString(true));
		}
		// round down
		n = n / 2;
		if (isBigEndian) {
			for (int i = 0; i < 2 * n; i += 2) {
				dest[dIndex + i / 2] = BIG_ENDIAN.getShort(byteBuf, i);
			}
		}
		else {
			for (int i = 0; i < 2 * n; i += 2) {
				dest[dIndex + i / 2] = LITTLE_ENDIAN.getShort(byteBuf, i);
			}
		}
		return n;
	}

	@Override
	public int getInt(Address addr) throws MemoryAccessException {
		byte[] byteBuf = new byte[4];
		int n = getBytes(addr, byteBuf, 0, 4);
		if (n != 4) {
			throw new MemoryAccessException("Could not get int at " + addr.toString(true));
		}
		return defaultEndian.getInt(byteBuf);
	}

	@Override
	public int getInt(Address addr, boolean isBigEndian) throws MemoryAccessException {
		byte[] byteBuf = new byte[4];
		int n = getBytes(addr, byteBuf, 0, 4);
		if (n != 4) {
			throw new MemoryAccessException("Could not get int at " + addr.toString(true));
		}
		if (isBigEndian) {
			return BIG_ENDIAN.getInt(byteBuf);
		}
		return LITTLE_ENDIAN.getInt(byteBuf);
	}

	@Override
	public int getInts(Address addr, int[] dest) throws MemoryAccessException {
		return getInts(addr, dest, 0, dest.length);
	}

	@Override
	public int getInts(Address addr, int[] dest, int dIndex, int nElem)
			throws MemoryAccessException {
		byte[] byteBuf = new byte[4 * nElem];
		int n = getBytes(addr, byteBuf, 0, byteBuf.length);
		if (n < 4) {
			throw new MemoryAccessException("Could not read ints at " + addr.toString(true));
		}
		// round down
		n = n / 4;
		for (int i = 0; i < 4 * n; i += 4) {
			dest[dIndex + i / 4] = defaultEndian.getInt(byteBuf, i);
		}
		return n;
	}

	@Override
	public int getInts(Address addr, int[] dest, int dIndex, int nElem, boolean isBigEndian)
			throws MemoryAccessException {
		byte[] byteBuf = new byte[4 * nElem];
		int n = getBytes(addr, byteBuf, 0, byteBuf.length);
		if (n < 4) {
			throw new MemoryAccessException("Could not read ints at " + addr.toString(true));
		}
		// round down
		n = n / 4;
		if (isBigEndian) {
			for (int i = 0; i < 4 * n; i += 4) {
				dest[dIndex + i / 4] = BIG_ENDIAN.getInt(byteBuf, i);
			}
		}
		else {
			for (int i = 0; i < 4 * n; i += 4) {
				dest[dIndex + i / 4] = LITTLE_ENDIAN.getInt(byteBuf, i);
			}
		}
		return n;
	}

	@Override
	public long getLong(Address addr) throws MemoryAccessException {
		byte[] byteBuf = new byte[8];
		int n = getBytes(addr, byteBuf, 0, 8);
		if (n != 8) {
			throw new MemoryAccessException("Could not get long at " + addr.toString(true));
		}
		return defaultEndian.getLong(byteBuf);
	}

	@Override
	public long getLong(Address addr, boolean isBigEndian) throws MemoryAccessException {
		byte[] byteBuf = new byte[8];
		int n = getBytes(addr, byteBuf, 0, 8);
		if (n != 8) {
			throw new MemoryAccessException("Could not get long at " + addr.toString(true));
		}
		if (isBigEndian) {
			return BIG_ENDIAN.getLong(byteBuf);
		}
		return LITTLE_ENDIAN.getLong(byteBuf);
	}

	@Override
	public int getLongs(Address addr, long[] dest) throws MemoryAccessException {
		return getLongs(addr, dest, 0, dest.length);
	}

	@Override
	public int getLongs(Address addr, long[] dest, int dIndex, int nElem)
			throws MemoryAccessException {
		byte[] byteBuf = new byte[8 * nElem];
		int n = getBytes(addr, byteBuf, 0, byteBuf.length);
		if (n < 8) {
			throw new MemoryAccessException("Could not read longs at " + addr.toString(true));
		}
		// round down
		n = n / 8;
		for (int i = 0; i < 8 * n; i += 8) {
			dest[dIndex + i / 8] = defaultEndian.getLong(byteBuf, i);
		}
		return n;
	}

	@Override
	public int getLongs(Address addr, long[] dest, int dIndex, int nElem, boolean isBigEndian)
			throws MemoryAccessException {
		byte[] byteBuf = new byte[8 * nElem];
		int n = getBytes(addr, byteBuf, 0, byteBuf.length);
		if (n < 8) {
			throw new MemoryAccessException("Could not read longs at " + addr.toString(true));
		}
		// round down
		n = n / 8;
		if (isBigEndian) {
			for (int i = 0; i < 8 * n; i += 8) {
				dest[dIndex + i / 8] = BIG_ENDIAN.getLong(byteBuf, i);
			}
		}
		else {
			for (int i = 0; i < 8 * n; i += 8) {
				dest[dIndex + i / 8] = LITTLE_ENDIAN.getLong(byteBuf, i);
			}
		}
		return n;
	}

	@Override
	public void setByte(Address addr, byte value) throws MemoryAccessException {
		if (liveMemory != null) {
			liveMemory.putByte(addr, value);
			fireBytesChanged(addr, 1);
			return;
		}
		lock.acquire();
		try {
			MemoryBlock block = getBlock(addr);
			if (block == null) {
				throw new MemoryAccessException(
					"Address " + addr.toString(true) + " does not exist in memory");
			}
			block.putByte(addr, value);

		}
		finally {
			lock.release();
		}

	}

	@Override
	public void setBytes(Address addr, byte[] source) throws MemoryAccessException {
		setBytes(addr, source, 0, source.length);
	}

	@Override
	public void setBytes(Address address, byte[] source, int sIndex, int size)
			throws MemoryAccessException {
		if (liveMemory != null) {
			int cnt = liveMemory.putBytes(address, source, sIndex, size);
			fireBytesChanged(address, cnt);
			return;
		}

		lock.acquire();
		try {
			Address addr = address;
			int n = size;
			// loop first just to make sure the operation can complete before making any changes
			while (n > 0) {
				MemoryBlock block = getBlock(addr);
				if (block == null) {
					throw new MemoryAccessException(
						"Address " + addr.toString(true) + " does not exist in memory");
				}
				n -= block.getSize() - addr.subtract(block.getStart());
				if (n <= 0) {
					break;
				}
				try {
					addr = block.getEnd().addNoWrap(1);
				}
				catch (AddressOverflowException e) {
					throw new MemoryAccessException("Attempted to write beyond address space");
				}
			}

			addr = address;
			n = size;
			int offset = sIndex;
			while (n > 0) {
				MemoryBlock block = getBlock(addr);
				int cnt = block.putBytes(addr, source, offset, n);
				offset += cnt;
				n -= cnt;
				if (n <= 0) {
					break;
				}
				addr = block.getEnd().add(1);
			}

		}
		finally {
			lock.release();
		}

	}

	@Override
	public void setShort(Address addr, short value) throws MemoryAccessException {
		byte[] byteBuf = new byte[2];
		defaultEndian.getBytes(value, byteBuf);
		setBytes(addr, byteBuf, 0, 2);
	}

	@Override
	public void setShort(Address addr, short value, boolean isBigEndian)
			throws MemoryAccessException {
		byte[] byteBuf = new byte[2];
		if (isBigEndian) {
			BIG_ENDIAN.getBytes(value, byteBuf);
		}
		else {
			LITTLE_ENDIAN.getBytes(value, byteBuf);
		}
		setBytes(addr, byteBuf, 0, 2);
	}

	@Override
	public void setInt(Address addr, int value) throws MemoryAccessException {
		byte[] byteBuf = new byte[4];
		defaultEndian.getBytes(value, byteBuf);
		setBytes(addr, byteBuf, 0, 4);
	}

	@Override
	public void setInt(Address addr, int value, boolean isBigEndian) throws MemoryAccessException {
		byte[] byteBuf = new byte[4];
		if (isBigEndian) {
			BIG_ENDIAN.getBytes(value, byteBuf);
		}
		else {
			LITTLE_ENDIAN.getBytes(value, byteBuf);
		}
		setBytes(addr, byteBuf, 0, 4);
	}

	@Override
	public void setLong(Address addr, long value) throws MemoryAccessException {
		byte[] byteBuf = new byte[8];
		defaultEndian.getBytes(value, byteBuf);
		setBytes(addr, byteBuf, 0, 8);
	}

	@Override
	public void setLong(Address addr, long value, boolean isBigEndian)
			throws MemoryAccessException {
		byte[] byteBuf = new byte[8];
		if (isBigEndian) {
			BIG_ENDIAN.getBytes(value, byteBuf);
		}
		else {
			LITTLE_ENDIAN.getBytes(value, byteBuf);
		}
		setBytes(addr, byteBuf, 0, 8);
	}

	@Override
	public boolean contains(Address addr) {
		return addrSet.contains(addr);
	}

	@Override
	public boolean contains(Address start, Address end) {
		return addrSet.contains(start, end);
	}

	@Override
	public boolean contains(AddressSetView set) {
		return addrSet.contains(set);
	}

	@Override
	public boolean isEmpty() {
		return addrSet.isEmpty();
	}

	@Override
	public Address getMinAddress() {
		return addrSet.getMinAddress();
	}

	@Override
	public Address getMaxAddress() {
		return addrSet.getMaxAddress();
	}

	@Override
	public int getNumAddressRanges() {
		return addrSet.getNumAddressRanges();
	}

	@Override
	public AddressRangeIterator getAddressRanges() {
		return addrSet.getAddressRanges();
	}

	@Override
	public Iterator<AddressRange> iterator() {
		return getAddressRanges();
	}

	@Override
	public AddressRangeIterator getAddressRanges(boolean startAtFront) {
		return addrSet.getAddressRanges(startAtFront);
	}

	@Override
	public long getNumAddresses() {
		return addrSet.getNumAddresses();
	}

	@Override
	public AddressIterator getAddresses(boolean forward) {
		return addrSet.getAddresses(forward);
	}

	@Override
	public AddressIterator getAddresses(Address start, boolean forward) {
		return addrSet.getAddresses(start, forward);
	}

	@Override
	public boolean intersects(AddressSetView set) {
		return addrSet.intersects(set);
	}

	@Override
	public boolean intersects(Address start, Address end) {
		return addrSet.intersects(start, end);
	}

	@Override
	public AddressSet intersect(AddressSetView set) {
		return addrSet.intersect(set);
	}

	@Override
	public AddressSet intersectRange(Address start, Address end) {
		return addrSet.intersectRange(start, end);
	}

	@Override
	public AddressSet union(AddressSetView set) {
		return addrSet.union(set);
	}

	@Override
	public AddressSet subtract(AddressSetView set) {
		return addrSet.subtract(set);
	}

	@Override
	public AddressSet xor(AddressSetView set) {
		return addrSet.xor(set);
	}

	@Override
	public boolean hasSameAddresses(AddressSetView set) {
		return addrSet.hasSameAddresses(set);
	}

	@Override
	public void removeBlock(MemoryBlock block, TaskMonitor monitor) throws LockException {
		lock.acquire();
		try {
			program.checkExclusiveAccess();
			checkBlock(block);
			MemoryBlockDB memBlock = (MemoryBlockDB) block;

			Address startAddress = block.getStart();

			program.setEventsEnabled(false);// ensure that no domain object change
			// events go out that would cause screen updates;
			// the code manager will be locked until the remove is done

			try {
				program.deleteAddressRange(startAddress, memBlock.getEnd(), monitor);
				memBlock.delete();
				reloadAll();
			}
			catch (IOException e) {
				program.dbError(e);
			}
			finally {
				program.setEventsEnabled(true);
			}

			fireBlockRemoved(startAddress);
			if (startAddress.getAddressSpace().isOverlaySpace()) {
				checkRemoveAddressSpace(startAddress.getAddressSpace());
			}
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Tests if the given addressSpace (overlay space) is used by any blocks.  If not, it
	 * removes the space.
	 * @param addressSpace overlay address space to be removed
	 */
	private void checkRemoveAddressSpace(AddressSpace addressSpace) {
		lock.acquire();
		try {
			program.removeOverlaySpace(addressSpace);
		}
		catch (LockException e) {
			throw new AssertException();
		}
		finally {
			lock.release();
		}

	}

	private void checkRange(Address start, long size)
			throws MemoryConflictException, AddressOverflowException {
		AddressSpace space = start.getAddressSpace();
		if (!space.isMemorySpace()) {
			throw new IllegalArgumentException(
				"Invalid memory address for block: " + start.toString(true));
		}
		AddressSpace mySpace = addrMap.getAddressFactory().getAddressSpace(space.getName());
		if (mySpace == null || !mySpace.equals(space)) {
			throw new IllegalArgumentException(
				"Block may not be created with unrecognized address space");
		}
		if (space.isOverlaySpace()) {
			throw new IllegalArgumentException("Block may not be created with an Overlay space");
		}
		if (size == 0) {
			throw new IllegalArgumentException("Block must have a non-zero length");
		}
		Address end = start.addNoWrap(size - 1);
		if (space == program.getAddressFactory().getDefaultAddressSpace()) {
			Address imageBase = addrMap.getImageBase();
			if (start.compareTo(imageBase) < 0 && end.compareTo(imageBase) >= 0) {
				throw new MemoryConflictException(
					"Block may not span image base address (" + imageBase + ")");
			}
		}
		if (addrSet.intersects(start, end)) {
			throw new MemoryConflictException(
				"Part of range (" + start + ", " + end + ") already exists in memory.");
		}
	}

	/**
	 * Gets the intersected set of addresses between a mapped memory block, and some other
	 * address set.
	 *
	 * @param mappedBlock The mapped memory block to use in the intersection.
	 * @param set Some other address set to use in the intersection.
	 * @return The intersected set of addresses between 'mappedMemoryBlock' and other address set
	 */
	private AddressSet getMappedIntersection(MemoryBlock mappedBlock, AddressSet set) {
		AddressSet mappedIntersection = new AddressSet();
		List<MemoryBlockSourceInfo> sourceInfos = mappedBlock.getSourceInfos();
		// mapped blocks can only ever have one sourceInfo
		MemoryBlockSourceInfo info = sourceInfos.get(0);
		AddressRange range = info.getMappedRange().get();
		AddressSet resolvedIntersection = set.intersect(new AddressSet(range));
		for (AddressRange resolvedRange : resolvedIntersection) {
			AddressRange mappedRange = getMappedRange(mappedBlock, resolvedRange);
			if (mappedRange != null) {
				mappedIntersection.add(mappedRange);
			}
		}
		return mappedIntersection;
	}

	/**
	 * Converts the given address range back from the source range back to the mapped range.
	 * NOTE: It is important that the specified mappedSourceRange is restricted to the 
	 * mapped source area of the specified mappedBlock.
	 * @param mappedBlock mapped memory block
	 * @param mappedSourceRange source range which maps into mappedBlock.
	 * @return mapped range or null if source range not mapped to block
	 */
	private AddressRange getMappedRange(MemoryBlock mappedBlock, AddressRange mappedSourceRange) {
		Address start, end;

		long sourceRangeLength = mappedSourceRange.getLength();
		if (sourceRangeLength <= 0) {
			throw new AssertException("invalid mapped source range length");
		}
		MemoryBlockSourceInfo info = mappedBlock.getSourceInfos().get(0);

		long startOffset =
			mappedSourceRange.getMinAddress().subtract(info.getMappedRange().get().getMinAddress());
		boolean isBitMapped = mappedBlock.getType() == MemoryBlockType.BIT_MAPPED;
		try {
			if (isBitMapped) {
				startOffset *= 8;
				start = mappedBlock.getStart().addNoWrap(startOffset);
				long endOffset = startOffset + (sourceRangeLength * 8) - 1;
				// since end may only partially consume a byte we must limit end address
				end = (endOffset < mappedBlock.getSize())
						? mappedBlock.getStart().addNoWrap(endOffset)
						: mappedBlock.getEnd();
			}
			else { // Byte mapped
				ByteMappingScheme byteMappingScheme = info.getByteMappingScheme().get();
				start =
					byteMappingScheme.getMappedAddress(mappedBlock, startOffset, false);
				long endOffset = startOffset + sourceRangeLength - 1;
				end = byteMappingScheme.getMappedAddress(mappedBlock, endOffset, true);
				if (start == null || start.compareTo(end) > 0) {
					return null; // mappedSourceRange corresponds to non-mapped/skipped bytes
				}
			}
		}
		catch (AddressOverflowException e) {
			throw new AddressOutOfBoundsException(e.getMessage());
		}
		return new AddressRangeImpl(start, end);
	}

	@Override
	public void deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
		// never do anything here!!!
	}

	@Override
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException {
		// never do anything here!!!
	}

	@Override
	public final String toString() {
		lock.acquire();
		try {
			if (blocks == null || blocks.isEmpty()) {
				return "[empty]\n";
			}
			StringBuffer buffer = new StringBuffer();
			for (MemoryBlock block : blocks) {
				buffer.append("[");
				buffer.append(block.getStart());
				buffer.append(", ");
				buffer.append(block.getEnd());
				buffer.append("] ");
			}
			return buffer.toString();
		}
		finally {
			lock.release();
		}
	}

	public void overlayBlockRenamed(String oldOverlaySpaceName, String name)
			throws LockException {
		program.renameOverlaySpace(oldOverlaySpaceName, name);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof Memory) {
			return obj == this;
		}
		if (obj instanceof AddressSetView) {
			lock.acquire();
			try {
				return addrSet.equals(obj);
			}
			finally {
				lock.release();
			}
		}
		return false;
	}

	@Override
	public int hashCode() {
		return super.hashCode();
	}

	@Override
	public AddressSetView getExecuteSet() {
		AddressSetView set = executeSet;

		if (set == null) {
			set = computeExecuteSet();
		}
		return set;
	}

	/**
	 * @return executable address set
	 */
	private AddressSetView computeExecuteSet() {
		lock.acquire();
		try {
			AddressSet set = new AddressSet();
			for (MemoryBlock block : blocks) {
				if (block.isExecute()) {
					set.addRange(block.getStart(), block.getEnd());
				}
			}
			executeSet = new AddressSetViewAdapter(set);
			return executeSet;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void memoryChanged(Address addr, int size) {
		fireBytesChanged(addr, size);
	}

	@Override
	public AddressRangeIterator getAddressRanges(Address start, boolean forward) {
		return addrSet.getAddressRanges(start, forward);
	}

	@Override
	public AddressRange getFirstRange() {
		return addrSet.getFirstRange();
	}

	@Override
	public AddressRange getLastRange() {
		return addrSet.getLastRange();
	}

	@Override
	public AddressRange getRangeContaining(Address address) {
		return addrSet.getRangeContaining(address);
	}

	@Override
	public Iterator<AddressRange> iterator(boolean forward) {
		return addrSet.iterator(forward);
	}

	@Override
	public Iterator<AddressRange> iterator(Address start, boolean forward) {
		return addrSet.iterator(start, forward);
	}

	@Override
	public Address findFirstAddressInCommon(AddressSetView set) {
		return addrSet.findFirstAddressInCommon(set);
	}

	@Override
	public AddressSourceInfo getAddressSourceInfo(Address address) {
		MemoryBlock block = getBlock(address);
		if (block != null) {
			return new AddressSourceInfo(this, address, block);
		}
		return null;
	}

	private void checkBlockSize(long newBlockLength, boolean initialized) {
		if (newBlockLength > MAX_BLOCK_SIZE) {
			throw new IllegalStateException(
				"New memory block NOT added: exceeds the maximum memory block byte size of " +
					MAX_BLOCK_SIZE_GB + " GByte(s)");
		}

		long newSize = getNumAddresses() + newBlockLength;
		if (newSize < 0 || newSize > Memory.MAX_BINARY_SIZE) {
			throw new IllegalStateException(
				"New memory block NOT added: would cause total number of initialized program " +
					"bytes to exceed the maximum program size of " + MAX_BINARY_SIZE_GB +
					" GBytes");
		}
	}

	@Override
	public FileBytes createFileBytes(String filename, long offset, long size, InputStream is,
			TaskMonitor monitor) throws IOException, CancelledException {
		lock.acquire();
		try {
			if (monitor != null && is != null) {
				is = new MonitoredInputStream(is, monitor);
			}
			return fileBytesAdapter.createFileBytes(filename, offset, size, is);
		}
		catch (IOCancelledException e) {
			throw new CancelledException();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public List<FileBytes> getAllFileBytes() {
		List<FileBytes> allFileBytes = fileBytesAdapter.getAllFileBytes();
		return Collections.unmodifiableList(allFileBytes);
	}

	private void checkFileBytes(FileBytes fileBytes) {
		if (fileBytes.adapter != fileBytesAdapter) {
			throw new IllegalArgumentException(
				"Attempted to delete FileBytes that doesn't belong to this program");
		}
		fileBytes.checkValid();
	}

	@Override
	public boolean deleteFileBytes(FileBytes fileBytes) throws IOException {
		lock.acquire();
		try {
			checkFileBytes(fileBytes);
			if (inUse(fileBytes)) {
				return false;
			}
			// TODO: may need to generate a domain object event
			return fileBytesAdapter.deleteFileBytes(fileBytes);
		}
		finally {
			lock.release();
		}
	}

	private boolean inUse(FileBytes fileBytes) {
		for (MemoryBlockDB block : blocks) {
			if (block.uses(fileBytes)) {
				return true;
			}
		}
		return false;
	}

	FileBytes getLayeredFileBytes(long fileBytesID) throws IOException {
		List<FileBytes> allFileBytes = fileBytesAdapter.getAllFileBytes();
		for (FileBytes layeredFileBytes : allFileBytes) {
			if (layeredFileBytes.getId() == fileBytesID) {
				return layeredFileBytes;
			}
		}
		throw new IOException("No File Bytes found for ID: " + fileBytesID);
	}

	/**
	 * Returns a list of all memory blocks that contain any addresses in the given range
	 * @param start the start address
	 * @param end the end address
	 * @return  a list of all memory blocks that contain any addresses in the given range
	 */
	List<MemoryBlockDB> getBlocks(Address start, Address end) {
		List<MemoryBlockDB> list = new ArrayList<>();

		List<MemoryBlockDB> tmpBlocks = blocks;
		int index = Collections.binarySearch(tmpBlocks, start, BLOCK_ADDRESS_COMPARATOR);
		if (index < 0) {
			index = -index - 2;
		}
		if (index >= 0) {
			MemoryBlockDB block = tmpBlocks.get(index);
			if (block.contains(start)) {
				list.add(block);
			}
		}

		while (++index < tmpBlocks.size()) {
			MemoryBlockDB block = tmpBlocks.get(index);
			if (block.getStart().compareTo(end) > 0) {
				break;
			}
			list.add(block);
		}

		return list;
	}

	void checkRangeForInstructions(Address start, Address end) throws MemoryAccessException {
		CodeManager codeManager = program.getCodeManager();
		Instruction instr = codeManager.getInstructionContaining(start);
		if (instr != null) {
			throw new MemoryAccessException(
				"Memory change conflicts with instruction at " + instr.getMinAddress());
		}
		if (!end.equals(start)) {
			instr = codeManager.getInstructionAfter(start);
			if (instr != null) {
				if (instr.getMinAddress().compareTo(end) <= 0) {
					throw new MemoryAccessException(
						"Memory change conflicts with instruction at " + instr.getMinAddress());
				}
			}
		}
	}

}
