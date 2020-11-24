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
package ghidra.program.model.mem;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.List;

import ghidra.framework.store.LockException;
import ghidra.program.database.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

/**
 * MemoryStub can be extended for use by tests. It throws an UnsupportedOperationException
 * for all methods in the Memory interface. Any method that is needed for your test can then
 * be overridden so it can provide its own test implementation and return value.
 */
public class MemoryStub extends AddressSet implements Memory {
	byte[] myMemoryBytes;
	MemoryBlock myMemoryBlock;

	public MemoryStub() {
		this(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 });
	}

	public MemoryStub(byte[] bytes) {
		super();
		this.myMemoryBytes = bytes;
		AddressSpace space = new GenericAddressSpace("Mem", 32, AddressSpace.TYPE_RAM, 0);
		Address start = space.getAddress(0);
		Address end = space.getAddress(bytes.length - 1);
		addRange(start, end);
		myMemoryBlock = new MemoryBlockStub(start, end);
	}

	@Override
	public boolean isEmpty() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Address getMinAddress() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Address getMaxAddress() {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getNumAddressRanges() {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressRangeIterator getAddressRanges() {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressRangeIterator getAddressRanges(boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressRangeIterator getAddressRanges(Address start, boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Iterator<AddressRange> iterator() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Iterator<AddressRange> iterator(boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Iterator<AddressRange> iterator(Address start, boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public long getNumAddresses() {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressIterator getAddresses(boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressIterator getAddresses(Address start, boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean intersects(AddressSetView addrSet) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean intersects(Address start, Address end) {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressSet xor(AddressSetView addrSet) {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressRange getFirstRange() {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressRange getLastRange() {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressRange getRangeContaining(Address address) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Program getProgram() {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressSetView getLoadedAndInitializedAddressSet() {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressSetView getAllInitializedAddressSet() {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressSetView getInitializedAddressSet() {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressSetView getExecuteSet() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isBigEndian() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setLiveMemoryHandler(LiveMemoryHandler handler) {
		throw new UnsupportedOperationException();
	}

	@Override
	public LiveMemoryHandler getLiveMemoryHandler() {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock createInitializedBlock(String name, Address start, InputStream is,
			long length, TaskMonitor monitor, boolean overlay) {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock createInitializedBlock(String name, Address start, long size,
			byte initialValue, TaskMonitor monitor, boolean overlay) {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock createUninitializedBlock(String name, Address start, long size,
			boolean overlay) {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock createBitMappedBlock(String name, Address start, Address mappedAddress,
			long length, boolean overlay)
			throws LockException, MemoryConflictException, AddressOverflowException {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock createByteMappedBlock(String name, Address start, Address mappedAddress,
			long length, ByteMappingScheme byteMappingScheme, boolean overlay) throws LockException,
			MemoryConflictException, AddressOverflowException, IllegalArgumentException {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock createBlock(MemoryBlock block, String name, Address start, long length)
			throws LockException, MemoryConflictException, AddressOverflowException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeBlock(MemoryBlock block, TaskMonitor monitor) throws LockException {
		throw new UnsupportedOperationException();
	}

	@Override
	public long getSize() {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock getBlock(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock getBlock(String blockName) {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock[] getBlocks() {
		throw new UnsupportedOperationException();
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
	public MemoryBlock convertToUninitialized(MemoryBlock initializedBlock)
			throws MemoryBlockException, NotFoundException, LockException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Address findBytes(Address addr, byte[] bytes, byte[] masks, boolean forward,
			TaskMonitor monitor) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Address findBytes(Address startAddr, Address endAddr, byte[] bytes, byte[] masks,
			boolean forward, TaskMonitor monitor) {
		throw new UnsupportedOperationException();
	}

	@Override
	public byte getByte(Address addr) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getBytes(Address addr, byte[] dest) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getBytes(Address addr, byte[] dest, int dIndex, int size)
			throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public short getShort(Address addr) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public short getShort(Address addr, boolean bigEndian) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getShorts(Address addr, short[] dest) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getShorts(Address addr, short[] dest, int dIndex, int nElem)
			throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getShorts(Address addr, short[] dest, int dIndex, int nElem, boolean isBigEndian)
			throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getInt(Address addr) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getInt(Address addr, boolean bigEndian) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getInts(Address addr, int[] dest) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getInts(Address addr, int[] dest, int dIndex, int nElem)
			throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getInts(Address addr, int[] dest, int dIndex, int nElem, boolean isBigEndian)
			throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public long getLong(Address addr) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public long getLong(Address addr, boolean bigEndian) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getLongs(Address addr, long[] dest) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getLongs(Address addr, long[] dest, int dIndex, int nElem)
			throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getLongs(Address addr, long[] dest, int dIndex, int nElem, boolean isBigEndian)
			throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setByte(Address addr, byte value) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setBytes(Address addr, byte[] source) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setBytes(Address addr, byte[] source, int sIndex, int size)
			throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setShort(Address addr, short value) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setShort(Address addr, short value, boolean bigEndian)
			throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setInt(Address addr, int value) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setInt(Address addr, int value, boolean bigEndian) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setLong(Address addr, long value) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setLong(Address addr, long value, boolean bigEndian) throws MemoryAccessException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Address findFirstAddressInCommon(AddressSetView set) {
		throw new UnsupportedOperationException();
	}

	@Override
	public FileBytes createFileBytes(String filename, long offset, long size, InputStream is,
			TaskMonitor monitor) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<FileBytes> getAllFileBytes() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean deleteFileBytes(FileBytes descriptor) {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock createInitializedBlock(String name, Address start, FileBytes fileBytes,
			long offset, long size, boolean overlay) {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressSourceInfo getAddressSourceInfo(Address address) {
		throw new UnsupportedOperationException();
	}
}
