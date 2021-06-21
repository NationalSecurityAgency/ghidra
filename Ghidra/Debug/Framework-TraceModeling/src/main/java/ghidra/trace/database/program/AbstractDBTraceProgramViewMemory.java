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

import com.google.common.cache.RemovalNotification;

import ghidra.framework.store.LockException;
import ghidra.program.database.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.trace.database.memory.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.program.TraceProgramViewMemory;
import ghidra.trace.util.MemoryAdapter;
import ghidra.util.MathUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractDBTraceProgramViewMemory
		implements TraceProgramViewMemory, MemoryAdapter {
	protected final DBTraceProgramView program;
	protected final DBTraceMemoryManager memoryManager;

	protected AddressSetView addressSet;
	protected long snap;

	public AbstractDBTraceProgramViewMemory(DBTraceProgramView program) {
		this.program = program;
		this.memoryManager = program.trace.getMemoryManager();
		setSnap(program.snap);
	}

	protected void blockRemoved(
			RemovalNotification<DBTraceMemoryRegion, DBTraceProgramViewMemoryBlock> rn) {
		// Nothing
	}

	protected abstract void recomputeAddressSet();

	void setSnap(long snap) {
		this.snap = snap;
		recomputeAddressSet();
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
	public synchronized AddressSetView getLoadedAndInitializedAddressSet() {
		return addressSet;
	}

	@Override
	public synchronized AddressSetView getAllInitializedAddressSet() {
		return addressSet;
	}

	@Override
	public synchronized AddressSetView getInitializedAddressSet() {
		return addressSet;
	}

	@Override
	public AddressSetView getExecuteSet() {
		AddressSet result = new AddressSet();
		for (DBTraceMemoryRegion region : memoryManager.getRegionsInternal()) {
			if (!region.isExecute() || !program.isRegionVisible(region, region.getLifespan())) {
				continue;
			}
			result.add(region.getRange());
		}
		return result;
	}

	@Override
	public boolean isBigEndian() {
		return program.getLanguage().isBigEndian();
	}

	@Override
	public void setLiveMemoryHandler(LiveMemoryHandler handler) {
		throw new UnsupportedOperationException();
	}

	@Override
	public LiveMemoryHandler getLiveMemoryHandler() {
		return null;
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
	public synchronized long getSize() {
		return addressSet.getNumAddresses();
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
	public MemoryBlock convertToInitialized(MemoryBlock unitializedBlock, byte initialValue)
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
		MemoryBlock block = getBlock(addr);
		if (block == null) {
			return 0; // Memory assumed initialized to 0
		}
		return block.getByte(addr);
	}

	@Override
	public int getBytes(Address addr, byte[] dest, int destIndex, int size)
			throws MemoryAccessException {
		MemoryBlock block = getBlock(addr);
		if (block == null) {
			int avail = MathUtilities.unsignedMin(Math.max(0, size),
				addr.getAddressSpace().getMaxAddress().subtract(addr));
			Arrays.fill(dest, destIndex, avail, (byte) 0);
			return avail;
		}
		return block.getBytes(addr, dest, destIndex, size);
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
		return addressSet.contains(addr);
	}

	@Override
	public boolean contains(Address start, Address end) {
		return addressSet.contains(start, end);
	}

	@Override
	public boolean contains(AddressSetView set) {
		return addressSet.contains(set);
	}

	@Override
	public boolean isEmpty() {
		return addressSet.isEmpty();
	}

	@Override
	public Address getMinAddress() {
		return addressSet.getMinAddress();
	}

	@Override
	public Address getMaxAddress() {
		return addressSet.getMaxAddress();
	}

	@Override
	public int getNumAddressRanges() {
		return addressSet.getNumAddressRanges();
	}

	@Override
	public AddressRangeIterator getAddressRanges() {
		return addressSet.getAddressRanges();
	}

	@Override
	public AddressRangeIterator getAddressRanges(boolean forward) {
		return addressSet.getAddressRanges(forward);
	}

	@Override
	public AddressRangeIterator getAddressRanges(Address start, boolean forward) {
		return addressSet.getAddressRanges(start, forward);
	}

	@Override
	public Iterator<AddressRange> iterator() {
		return addressSet.iterator();
	}

	@Override
	public Iterator<AddressRange> iterator(boolean forward) {
		return addressSet.iterator(forward);
	}

	@Override
	public Iterator<AddressRange> iterator(Address start, boolean forward) {
		return addressSet.iterator(start, forward);
	}

	@Override
	public long getNumAddresses() {
		return addressSet.getNumAddresses();
	}

	@Override
	public AddressIterator getAddresses(boolean forward) {
		return addressSet.getAddresses(forward);
	}

	@Override
	public AddressIterator getAddresses(Address start, boolean forward) {
		return addressSet.getAddresses(start, forward);
	}

	@Override
	public boolean intersects(AddressSetView addrSet) {
		return addressSet.intersects(addrSet);
	}

	@Override
	public boolean intersects(Address start, Address end) {
		return addressSet.intersects(start, end);
	}

	@Override
	public AddressSet intersect(AddressSetView view) {
		return addressSet.intersect(view);
	}

	@Override
	public AddressSet intersectRange(Address start, Address end) {
		return addressSet.intersectRange(start, end);
	}

	@Override
	public AddressSet union(AddressSetView addrSet) {
		return addressSet.union(addrSet);
	}

	@Override
	public AddressSet subtract(AddressSetView addrSet) {
		return addressSet.subtract(addrSet);
	}

	@Override
	public AddressSet xor(AddressSetView addrSet) {
		return addressSet.xor(addrSet);
	}

	@Override
	public boolean hasSameAddresses(AddressSetView view) {
		return addressSet.hasSameAddresses(view);
	}

	@Override
	public AddressRange getFirstRange() {
		return addressSet.getFirstRange();
	}

	@Override
	public AddressRange getLastRange() {
		return addressSet.getLastRange();
	}

	@Override
	public AddressRange getRangeContaining(Address address) {
		return addressSet.getRangeContaining(address);
	}

	@Override
	public Address findFirstAddressInCommon(AddressSetView set) {
		return addressSet.findFirstAddressInCommon(set);
	}

	protected synchronized void addRange(AddressRange range) {
		addressSet = addressSet.union(new AddressSet(range));
	}

	protected synchronized void removeRange(AddressRange range) {
		addressSet = addressSet.subtract(new AddressSet(range));
	}

	protected synchronized void changeRange(AddressRange remove, AddressRange add) {
		AddressSet temp = new AddressSet(addressSet);
		temp.delete(remove);
		temp.add(add);
		addressSet = temp;
	}
}
