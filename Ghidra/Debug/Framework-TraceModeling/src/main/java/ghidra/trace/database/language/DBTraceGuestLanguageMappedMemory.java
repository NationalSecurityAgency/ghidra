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
package ghidra.trace.database.language;

import static ghidra.lifecycle.Unfinished.TODO;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;

import ghidra.framework.store.LockException;
import ghidra.program.database.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.database.memory.DBTraceMemorySpace;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Document me
 * 
 * Note this is the bare minimum to support {@link DumbMemBufferImpl}
 */
public class DBTraceGuestLanguageMappedMemory implements Memory {
	protected final DBTraceMemoryManager manager;
	protected final DBTraceGuestLanguage guest;
	protected final long snap;

	public DBTraceGuestLanguageMappedMemory(DBTraceMemoryManager manager,
			DBTraceGuestLanguage guest, long snap) {
		this.manager = manager;
		this.guest = guest;
		this.snap = snap;
	}

	@Override
	public boolean contains(Address addr) {
		return TODO();
	}

	@Override
	public boolean contains(Address start, Address end) {
		return TODO();
	}

	@Override
	public boolean contains(AddressSetView rangeSet) {
		return TODO();
	}

	@Override
	public boolean isEmpty() {
		return TODO();
	}

	@Override
	public Address getMinAddress() {
		return TODO();
	}

	@Override
	public Address getMaxAddress() {
		return TODO();
	}

	@Override
	public int getNumAddressRanges() {
		return TODO();
	}

	@Override
	public AddressRangeIterator getAddressRanges() {
		return TODO();
	}

	@Override
	public AddressRangeIterator getAddressRanges(boolean forward) {
		return TODO();
	}

	@Override
	public AddressRangeIterator getAddressRanges(Address start, boolean forward) {
		return TODO();
	}

	@Override
	public Iterator<AddressRange> iterator() {
		return TODO();
	}

	@Override
	public Iterator<AddressRange> iterator(boolean forward) {
		return TODO();
	}

	@Override
	public Iterator<AddressRange> iterator(Address start, boolean forward) {
		return TODO();
	}

	@Override
	public long getNumAddresses() {
		return TODO();
	}

	@Override
	public AddressIterator getAddresses(boolean forward) {
		return TODO();
	}

	@Override
	public AddressIterator getAddresses(Address start, boolean forward) {
		return TODO();
	}

	@Override
	public boolean intersects(AddressSetView addrSet) {
		return TODO();
	}

	@Override
	public boolean intersects(Address start, Address end) {
		return TODO();
	}

	@Override
	public AddressSet intersect(AddressSetView view) {
		return TODO();
	}

	@Override
	public AddressSet intersectRange(Address start, Address end) {
		return TODO();
	}

	@Override
	public AddressSet union(AddressSetView addrSet) {
		return TODO();
	}

	@Override
	public AddressSet subtract(AddressSetView addrSet) {
		return TODO();
	}

	@Override
	public AddressSet xor(AddressSetView addrSet) {
		return TODO();
	}

	@Override
	public boolean hasSameAddresses(AddressSetView view) {
		return TODO();
	}

	@Override
	public AddressRange getFirstRange() {
		return TODO();
	}

	@Override
	public AddressRange getLastRange() {
		return TODO();
	}

	@Override
	public AddressRange getRangeContaining(Address address) {
		return TODO();
	}

	@Override
	public Address findFirstAddressInCommon(AddressSetView set) {
		return TODO();
	}

	@Override
	public Program getProgram() {
		return null;
	}

	@Override
	public AddressSetView getLoadedAndInitializedAddressSet() {
		return TODO();
	}

	@Override
	public AddressSetView getAllInitializedAddressSet() {
		return TODO();
	}

	@Override
	public AddressSetView getInitializedAddressSet() {
		return TODO();
	}

	@Override
	public AddressSetView getExecuteSet() {
		return TODO();
	}

	@Override
	public boolean isBigEndian() {
		return guest.getLanguage().isBigEndian();
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
			CancelledException, IllegalArgumentException {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock createInitializedBlock(String name, Address start, long size,
			byte initialValue, TaskMonitor monitor, boolean overlay)
			throws LockException, IllegalArgumentException, MemoryConflictException,
			AddressOverflowException, CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock createInitializedBlock(String name, Address start, FileBytes fileBytes,
			long offset, long size, boolean overlay) throws LockException, IllegalArgumentException,
			MemoryConflictException, AddressOverflowException {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock createUninitializedBlock(String name, Address start, long size,
			boolean overlay) throws LockException, IllegalArgumentException,
			MemoryConflictException, AddressOverflowException {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock createBitMappedBlock(String name, Address start, Address mappedAddress,
			long length, boolean overlay) throws LockException, MemoryConflictException,
			AddressOverflowException, IllegalArgumentException {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock createByteMappedBlock(String name, Address start, Address mappedAddress,
			long length, ByteMappingScheme byteMappingScheme, boolean overlay)
			throws LockException, MemoryConflictException, AddressOverflowException,
			IllegalArgumentException {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock createBlock(MemoryBlock block, String name, Address start, long length)
			throws LockException, IllegalArgumentException, MemoryConflictException,
			AddressOverflowException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeBlock(MemoryBlock block, TaskMonitor monitor) throws LockException {
		throw new UnsupportedOperationException();
	}

	@Override
	public long getSize() {
		return TODO();
	}

	@Override
	public MemoryBlock getBlock(Address addr) {
		return TODO();
	}

	@Override
	public MemoryBlock getBlock(String blockName) {
		return TODO();
	}

	@Override
	public MemoryBlock[] getBlocks() {
		return TODO();
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
		return TODO();
	}

	@Override
	public Address findBytes(Address startAddr, Address endAddr, byte[] bytes, byte[] masks,
			boolean forward, TaskMonitor monitor) {
		return TODO();
	}

	protected int getBytes(ByteBuffer buffer, Address guestStart) {
		int startPos = buffer.position();
		while (buffer.hasRemaining()) {
			int offset = buffer.position() - startPos;
			Address guestCur = guestStart.add(offset);
			Entry<Address, DBTraceGuestLanguageMappedRange> floorEntry =
				guest.rangesByGuestAddress.floorEntry(guestCur);
			if (floorEntry == null) {
				return offset;
			}
			DBTraceGuestLanguageMappedRange range = floorEntry.getValue();
			Address hostCur = range.mapGuestToHost(guestCur);
			if (hostCur == null) {
				return offset;
			}
			int lenToRead = (int) Math.min(buffer.remaining(),
				range.getGuestRange().getMaxAddress().subtract(guestStart) + 1);
			DBTraceMemorySpace hostSpace = manager.getMemorySpace(hostCur.getAddressSpace(), false);
			if (hostSpace == null) {
				// TODO: Finish or skip and continue? Going with skip and continue for now
				buffer.position(buffer.position() + lenToRead);
				continue;
			}
			int savedLimit = buffer.limit();
			try {
				buffer.limit(buffer.position() + lenToRead);
				hostSpace.getBytes(snap, hostCur, buffer);
			}
			finally {
				buffer.limit(savedLimit);
			}
		}
		return buffer.position() - startPos;
	}

	protected ByteBuffer getBytesInFull(Address address, int len) throws MemoryAccessException {
		ByteBuffer buf = ByteBuffer.allocate(len);
		if (getBytes(buf, address) != len) {
			throw new MemoryAccessException("Could not read enough bytes");
		}
		if (!isBigEndian()) {
			buf.order(ByteOrder.LITTLE_ENDIAN);
		}
		return buf;
	}

	@Override
	public byte getByte(Address addr) throws MemoryAccessException {
		byte[] val = new byte[1];
		if (getBytes(addr, val) < 1) {
			throw new MemoryAccessException("Guest address " + addr.toString() +
				" is not mapped, or the mapped address does not exist in host memory");
		}
		return val[0];
	}

	@Override
	public int getBytes(Address addr, byte[] dest) throws MemoryAccessException {
		return getBytes(addr, dest, 0, dest.length);
	}

	@Override
	public int getBytes(Address addr, byte[] dest, int destIndex, int size)
			throws MemoryAccessException {
		return getBytes(ByteBuffer.wrap(dest, destIndex, size), addr);
	}

	@Override
	public short getShort(Address addr) throws MemoryAccessException {
		return getBytesInFull(addr, Short.BYTES).getShort(0);
	}

	@Override
	public short getShort(Address addr, boolean bigEndian) throws MemoryAccessException {
		return getBytesInFull(addr, Short.BYTES)
				.order(bigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN)
				.getShort(0);
	}

	@Override
	public int getShorts(Address addr, short[] dest) throws MemoryAccessException {
		return getShorts(addr, dest, 0, dest.length);
	}

	@Override
	public int getShorts(Address addr, short[] dest, int dIndex, int nElem)
			throws MemoryAccessException {
		ByteBuffer buf = ByteBuffer.allocate(nElem * 2);
		int countBytes = getBytes(buf, addr);
		buf.flip();
		buf.asShortBuffer().get(dest, dIndex, countBytes / 2);
		return countBytes / 2;
	}

	@Override
	public int getShorts(Address addr, short[] dest, int dIndex, int nElem, boolean isBigEndian)
			throws MemoryAccessException {
		ByteBuffer buf = ByteBuffer.allocate(nElem * 2);
		int countBytes = getBytes(buf, addr);
		buf.flip();
		buf.order(isBigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
		buf.asShortBuffer().get(dest, dIndex, countBytes / 2);
		return countBytes / 2;
	}

	@Override
	public int getInt(Address addr) throws MemoryAccessException {
		return TODO();
	}

	@Override
	public int getInt(Address addr, boolean bigEndian) throws MemoryAccessException {
		return TODO();
	}

	@Override
	public int getInts(Address addr, int[] dest) throws MemoryAccessException {
		return TODO();
	}

	@Override
	public int getInts(Address addr, int[] dest, int dIndex, int nElem)
			throws MemoryAccessException {
		return TODO();
	}

	@Override
	public int getInts(Address addr, int[] dest, int dIndex, int nElem, boolean isBigEndian)
			throws MemoryAccessException {
		return TODO();
	}

	@Override
	public long getLong(Address addr) throws MemoryAccessException {
		return TODO();
	}

	@Override
	public long getLong(Address addr, boolean bigEndian) throws MemoryAccessException {
		return TODO();
	}

	@Override
	public int getLongs(Address addr, long[] dest) throws MemoryAccessException {
		return TODO();
	}

	@Override
	public int getLongs(Address addr, long[] dest, int dIndex, int nElem)
			throws MemoryAccessException {
		return TODO();
	}

	@Override
	public int getLongs(Address addr, long[] dest, int dIndex, int nElem, boolean isBigEndian)
			throws MemoryAccessException {
		return TODO();
	}

	@Override
	public void setByte(Address addr, byte value) throws MemoryAccessException {
		TODO();
	}

	@Override
	public void setBytes(Address addr, byte[] source) throws MemoryAccessException {
		TODO();
	}

	@Override
	public void setBytes(Address addr, byte[] source, int sIndex, int size)
			throws MemoryAccessException {
		TODO();
	}

	@Override
	public void setShort(Address addr, short value) throws MemoryAccessException {
		TODO();
	}

	@Override
	public void setShort(Address addr, short value, boolean bigEndian)
			throws MemoryAccessException {
		TODO();
	}

	@Override
	public void setInt(Address addr, int value) throws MemoryAccessException {
		TODO();
	}

	@Override
	public void setInt(Address addr, int value, boolean bigEndian) throws MemoryAccessException {
		TODO();
	}

	@Override
	public void setLong(Address addr, long value) throws MemoryAccessException {
		TODO();
	}

	@Override
	public void setLong(Address addr, long value, boolean bigEndian) throws MemoryAccessException {
		TODO();
	}

	@Override
	public FileBytes createFileBytes(String filename, long offset, long size, InputStream is,
			TaskMonitor monitor) throws IOException, CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<FileBytes> getAllFileBytes() {
		return List.of();
	}

	@Override
	public boolean deleteFileBytes(FileBytes fileBytes) throws IOException {
		return false;
	}

	@Override
	public AddressSourceInfo getAddressSourceInfo(Address address) {
		return TODO();
	}
}
