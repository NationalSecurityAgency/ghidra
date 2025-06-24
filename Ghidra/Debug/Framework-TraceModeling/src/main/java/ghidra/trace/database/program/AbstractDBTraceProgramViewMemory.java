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
package ghidra.trace.database.program;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.*;

import ghidra.framework.store.LockException;
import ghidra.program.database.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.database.memory.DBTraceMemorySpace;
import ghidra.trace.model.Trace;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.program.TraceProgramViewMemory;
import ghidra.trace.util.MemoryAdapter;
import ghidra.util.LockHold;
import ghidra.util.MathUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractDBTraceProgramViewMemory
		implements TraceProgramViewMemory, MemoryAdapter {
	protected final DBTraceProgramView program;
	protected final DBTraceMemoryManager memoryManager;

	private volatile AddressSetView addressSet;
	private volatile boolean addressSetValid;
	private boolean forceFullView = false;
	private long snap;

	private static final int CACHE_PAGE_COUNT = 3;
	protected final ByteCache cache = new ByteCache(CACHE_PAGE_COUNT) {
		@Override
		protected int doLoad(Address address, ByteBuffer buf) throws MemoryAccessException {
			DBTraceMemorySpace space =
				program.trace.getMemoryManager().getMemorySpace(address.getAddressSpace(), false);
			if (space == null) {
				int len = buf.remaining();
				buf.position(buf.limit());
				return len;
			}
			return space.getViewBytes(program.snap, address, buf);
		}
	};

	public AbstractDBTraceProgramViewMemory(DBTraceProgramView program) {
		this.program = program;
		this.memoryManager = program.trace.getMemoryManager();
		setSnap(program.snap);
	}

	protected abstract AddressSetView computeAddressSet();

	protected void invalidateAddressSet() {
		addressSetValid = false;
		program.fireObjectRestored();
	}

	protected AddressSetView getOrComputeAddressSet() {
		if (!addressSetValid) {
			addressSet = computeAddressSet();
			addressSetValid = true;
		}
		return addressSet;
	}

	@Override
	public void setForceFullView(boolean forceFullView) {
		this.forceFullView = forceFullView;
		invalidateAddressSet();
	}

	@Override
	public boolean isForceFullView() {
		return forceFullView;
	}

	void setSnap(long snap) {
		this.snap = snap;
		if (!forceFullView) {
			invalidateAddressSet();
		}
	}

	@Override
	public TraceProgramView getProgram() {
		return program;
	}

	@Override
	public Trace getTrace() {
		return program.trace;
	}

	@Override
	public long getSnap() {
		return snap;
	}

	@Override
	public AddressSetView getLoadedAndInitializedAddressSet() {
		return getOrComputeAddressSet();
	}

	@Override
	public AddressSetView getAllInitializedAddressSet() {
		return getOrComputeAddressSet();
	}

	@Override
	public AddressSetView getInitializedAddressSet() {
		return getOrComputeAddressSet();
	}

	@Override
	public boolean isBigEndian() {
		return program.getLanguage().isBigEndian();
	}

	@Override
	public MemoryBlock createInitializedBlock(String name, Address start, InputStream is,
			long length, TaskMonitor monitor, boolean overlay)
			throws LockException, MemoryConflictException, AddressOverflowException,
			CancelledException {
		// TODO: Create a region?
		// TODO: Copy contents in?
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock createInitializedBlock(String name, Address start, FileBytes fileBytes,
			long offset, long size, boolean overlay)
			throws LockException, MemoryConflictException, AddressOverflowException {
		// TODO: Create a region?
		// TODO: Copy contents in?
		//   NOTE: Would not be backed by the fileBytes, but a copy
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock createInitializedBlock(String name, Address start, long size,
			byte initialValue, TaskMonitor monitor, boolean overlay)
			throws LockException, MemoryConflictException, AddressOverflowException,
			CancelledException {
		// TODO: Create a region?
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock createUninitializedBlock(String name, Address start, long size,
			boolean overlay)
			throws LockException, MemoryConflictException, AddressOverflowException {
		throw new UnsupportedOperationException("All trace memory is initialized");
	}

	@Override
	public MemoryBlock createBitMappedBlock(String name, Address start, Address mappedAddress,
			long length, boolean overlay) throws LockException, MemoryConflictException,
			AddressOverflowException, IllegalArgumentException {
		throw new UnsupportedOperationException("Mapped blocks are not supported in traces");
	}

	@Override
	public MemoryBlock createByteMappedBlock(String name, Address start, Address mappedAddress,
			long length, ByteMappingScheme byteMappingScheme, boolean overlay)
			throws LockException, MemoryConflictException, AddressOverflowException,
			IllegalArgumentException {
		throw new UnsupportedOperationException("Mapped blocks are not supported in traces");
	}

	@Override
	public MemoryBlock createBlock(MemoryBlock block, String name, Address start, long length)
			throws LockException, MemoryConflictException, AddressOverflowException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeBlock(MemoryBlock block, TaskMonitor monitor) throws LockException {
		// TODO: Remove region?
		throw new UnsupportedOperationException();
	}

	@Override
	public long getSize() {
		return getOrComputeAddressSet().getNumAddresses();
	}

	@Override
	public void moveBlock(MemoryBlock block, Address newStartAddr, TaskMonitor monitor)
			throws LockException, MemoryBlockException, MemoryConflictException,
			AddressOverflowException, NotFoundException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void split(MemoryBlock block, Address addr)
			throws MemoryBlockException, LockException, NotFoundException {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock join(MemoryBlock blockOne, MemoryBlock blockTwo)
			throws LockException, MemoryBlockException, NotFoundException {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock convertToInitialized(MemoryBlock uninitializedBlock, byte initialValue)
			throws LockException, MemoryBlockException, NotFoundException {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock convertToUninitialized(MemoryBlock itializedBlock)
			throws MemoryBlockException, NotFoundException, LockException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Address findBytes(Address addr, byte[] bytes, byte[] masks, boolean forward,
			TaskMonitor monitor) {
		final Address startAddr;
		final Address endAddr;
		if (forward) {
			startAddr = addr;
			endAddr = getMaxAddress();
		}
		else {
			startAddr = getMinAddress();
			endAddr = addr;
		}
		return findBytes(startAddr, endAddr, bytes, masks, forward, monitor);
	}

	@Override
	public Address findBytes(Address startAddr, Address endAddr, byte[] bytes, byte[] masks,
			boolean forward, TaskMonitor monitor) {
		ByteBuffer bufBytes = ByteBuffer.wrap(bytes);
		ByteBuffer bufMasks = masks == null ? null : ByteBuffer.wrap(masks);

		Address minAddr = forward ? startAddr : endAddr;
		Address maxAddr = forward ? endAddr : startAddr;
		Iterator<AddressRange> it =
			program.getAddressFactory().getAddressSet(minAddr, maxAddr).iterator(forward);
		while (it.hasNext()) {
			AddressRange range = it.next();
			DBTraceMemorySpace space = memoryManager.getMemorySpace(range.getAddressSpace(), false);
			if (space == null) {
				continue;
			}
			// TODO: findBytes must heed fork, or there should exist a variant that does....
			// Lest I have to implement the forked search here.
			Address found =
				space.findBytes(snap, range, bufBytes, bufMasks, forward, monitor);
			if (found != null) {
				return found;
			}
		}
		return null;
	}

	@Override
	public byte getByte(Address addr) throws MemoryAccessException {
		try (LockHold hold = program.trace.lockRead()) {
			return cache.read(addr);
		}
	}

	@Override
	public int getBytes(Address addr, byte[] b, int off, int len) throws MemoryAccessException {
		try (LockHold hold = program.trace.lockRead()) {
			if (cache.canCache(addr, len)) {
				return cache.read(addr, ByteBuffer.wrap(b, off, len));
			}
			AddressSpace as = addr.getAddressSpace();
			DBTraceMemorySpace space = program.trace.getMemoryManager().getMemorySpace(as, false);
			if (space == null) {
				throw new MemoryAccessException("Space does not exist");
			}
			len = MathUtilities.unsignedMin(len, as.getMaxAddress().subtract(addr) + 1);
			return space.getViewBytes(program.snap, addr, ByteBuffer.wrap(b, off, len));
		}
	}

	@Override
	public void setByte(Address addr, byte value) throws MemoryAccessException {
		DBTraceMemorySpace space = memoryManager.getMemorySpace(addr.getAddressSpace(), true);
		if (space.putBytes(snap, addr, ByteBuffer.wrap(new byte[] { value })) != 1) {
			throw new MemoryAccessException();
		}
	}

	@Override
	public void setBytes(Address addr, byte[] source, int sIndex, int size)
			throws MemoryAccessException {
		DBTraceMemorySpace space = memoryManager.getMemorySpace(addr.getAddressSpace(), true);
		if (space.putBytes(snap, addr, ByteBuffer.wrap(source, sIndex, size)) != size) {
			throw new MemoryAccessException();
		}
	}

	@Override
	public FileBytes createFileBytes(String filename, long offset, long size, InputStream is,
			TaskMonitor monitor) throws IOException, CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<FileBytes> getAllFileBytes() {
		return Collections.emptyList();
	}

	@Override
	public AddressSourceInfo getAddressSourceInfo(Address address) {
		MemoryBlock block = getBlock(address);
		return block == null ? null : new AddressSourceInfo(this, address, block);
	}

	@Override
	public boolean deleteFileBytes(FileBytes fileBytes) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean contains(Address addr) {
		return getOrComputeAddressSet().contains(addr);
	}

	@Override
	public boolean contains(Address start, Address end) {
		return getOrComputeAddressSet().contains(start, end);
	}

	@Override
	public boolean contains(AddressSetView set) {
		return getOrComputeAddressSet().contains(set);
	}

	@Override
	public boolean isEmpty() {
		return getOrComputeAddressSet().isEmpty();
	}

	@Override
	public Address getMinAddress() {
		return getOrComputeAddressSet().getMinAddress();
	}

	@Override
	public Address getMaxAddress() {
		return getOrComputeAddressSet().getMaxAddress();
	}

	@Override
	public int getNumAddressRanges() {
		return getOrComputeAddressSet().getNumAddressRanges();
	}

	@Override
	public AddressRangeIterator getAddressRanges() {
		return getOrComputeAddressSet().getAddressRanges();
	}

	@Override
	public AddressRangeIterator getAddressRanges(boolean forward) {
		return getOrComputeAddressSet().getAddressRanges(forward);
	}

	@Override
	public AddressRangeIterator getAddressRanges(Address start, boolean forward) {
		return getOrComputeAddressSet().getAddressRanges(start, forward);
	}

	@Override
	public Iterator<AddressRange> iterator() {
		return getOrComputeAddressSet().iterator();
	}

	@Override
	public Iterator<AddressRange> iterator(boolean forward) {
		return getOrComputeAddressSet().iterator(forward);
	}

	@Override
	public Iterator<AddressRange> iterator(Address start, boolean forward) {
		return getOrComputeAddressSet().iterator(start, forward);
	}

	@Override
	public long getNumAddresses() {
		return getOrComputeAddressSet().getNumAddresses();
	}

	@Override
	public AddressIterator getAddresses(boolean forward) {
		return getOrComputeAddressSet().getAddresses(forward);
	}

	@Override
	public AddressIterator getAddresses(Address start, boolean forward) {
		return getOrComputeAddressSet().getAddresses(start, forward);
	}

	@Override
	public boolean intersects(AddressSetView addrSet) {
		return getOrComputeAddressSet().intersects(addrSet);
	}

	@Override
	public boolean intersects(Address start, Address end) {
		return getOrComputeAddressSet().intersects(start, end);
	}

	@Override
	public AddressSet intersect(AddressSetView view) {
		return getOrComputeAddressSet().intersect(view);
	}

	@Override
	public AddressSet intersectRange(Address start, Address end) {
		return getOrComputeAddressSet().intersectRange(start, end);
	}

	@Override
	public AddressSet union(AddressSetView addrSet) {
		return getOrComputeAddressSet().union(addrSet);
	}

	@Override
	public AddressSet subtract(AddressSetView addrSet) {
		return getOrComputeAddressSet().subtract(addrSet);
	}

	@Override
	public AddressSet xor(AddressSetView addrSet) {
		return getOrComputeAddressSet().xor(addrSet);
	}

	@Override
	public boolean hasSameAddresses(AddressSetView view) {
		return getOrComputeAddressSet().hasSameAddresses(view);
	}

	@Override
	public AddressRange getFirstRange() {
		return getOrComputeAddressSet().getFirstRange();
	}

	@Override
	public AddressRange getLastRange() {
		return getOrComputeAddressSet().getLastRange();
	}

	@Override
	public AddressRange getRangeContaining(Address address) {
		return getOrComputeAddressSet().getRangeContaining(address);
	}

	@Override
	public Address findFirstAddressInCommon(AddressSetView set) {
		return getOrComputeAddressSet().findFirstAddressInCommon(set);
	}
}
