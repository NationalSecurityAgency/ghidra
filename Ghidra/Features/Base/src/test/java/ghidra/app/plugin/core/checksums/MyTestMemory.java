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
package ghidra.app.plugin.core.checksums;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import ghidra.framework.store.LockException;
import ghidra.program.database.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

public class MyTestMemory extends AddressSet implements Memory {
	byte[] myMemoryBytes;
	MemoryBlock myMemoryBlock;

	public MyTestMemory(byte[] bytes) {
		super();
		this.myMemoryBytes = bytes;
		AddressSpace space = new GenericAddressSpace("Mem", 32, AddressSpace.TYPE_RAM, 0);
		Address start = space.getAddress(0);
		Address end = space.getAddress(bytes.length - 1);
		addRange(start, end);
		myMemoryBlock = new MyTestMemoryBlock(start, end);
	}

	@Override
	public AddressSetView getLoadedAndInitializedAddressSet() {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressSetView getInitializedAddressSet() {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressSetView getAllInitializedAddressSet() {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressSourceInfo getAddressSourceInfo(Address address) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isBigEndian() {
		return false;
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
			long length, TaskMonitor monitor, boolean overlay)
			throws MemoryConflictException, AddressOverflowException, CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock createInitializedBlock(String name, Address start, long size,
			byte initialValue, TaskMonitor monitor, boolean overlay)
			throws MemoryConflictException, AddressOverflowException, CancelledException {
		throw new UnsupportedOperationException();
	}

	public MemoryBlock createInitializedBlock(String name, Address start, byte[] data) {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock createUninitializedBlock(String name, Address start, long size,
			boolean overlay) throws MemoryConflictException, AddressOverflowException {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock createBitMappedBlock(String name, Address start, Address overlayAddress,
			long length, boolean overlay) throws MemoryConflictException, AddressOverflowException {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock createByteMappedBlock(String name, Address start, Address mappedAddress,
			long length, ByteMappingScheme byteMappingScheme, boolean overlay) throws LockException,
			MemoryConflictException, AddressOverflowException, IllegalArgumentException {
		throw new UnsupportedOperationException();
	}

	@Override
	public FileBytes createFileBytes(String filename, long offset, long size, InputStream is,
			TaskMonitor monitor) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean deleteFileBytes(FileBytes descriptor) {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<FileBytes> getAllFileBytes() {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock createBlock(MemoryBlock block, String name, Address start, long length)
			throws MemoryConflictException, AddressOverflowException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeBlock(MemoryBlock block, TaskMonitor monitor) {
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
	public MemoryBlock getBlock(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock[] getBlocks() {
		return new MemoryBlock[] {};
	}

	@Override
	public void moveBlock(MemoryBlock block, Address newStartAddr, TaskMonitor monitor)
			throws MemoryConflictException, AddressOverflowException, NotFoundException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void split(MemoryBlock block, Address addr) throws NotFoundException {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock join(MemoryBlock blockOne, MemoryBlock blockTwo)
			throws MemoryBlockException, NotFoundException {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock convertToInitialized(MemoryBlock unitializedBlock, byte initialValue)
			throws MemoryBlockException, NotFoundException {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemoryBlock convertToUninitialized(MemoryBlock initializedBlock)
			throws MemoryBlockException, NotFoundException {
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
		return myMemoryBytes[(int) addr.getOffset()];
	}

	@Override
	public int getBytes(Address addr, byte[] dest) throws MemoryAccessException {
		return getBytes(addr, dest, 0, dest.length);
	}

	@Override
	public int getBytes(Address addr, byte[] dest, int dIndex, int size)
			throws MemoryAccessException {
		int offset = (int) addr.getOffset();
		int len = Math.min(size, myMemoryBytes.length - offset);
		System.arraycopy(myMemoryBytes, offset, dest, dIndex, len);
		return len;
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

	public boolean haveLock() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Program getProgram() {
		throw new UnsupportedOperationException();
	}

	public MemoryBlock createOverlayBlock(String name, Address start, InputStream dataInput,
			long dataLength, TaskMonitor monitor) {
		throw new UnsupportedOperationException();
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.mem.Memory#getExecuteSet()
	 */
	@Override
	public AddressSetView getExecuteSet() {
		AddressSet set = new AddressSet();
		if (myMemoryBlock.isExecute()) {
			set.addRange(myMemoryBlock.getStart(), myMemoryBlock.getEnd());
		}
		return set;
	}

	@Override
	public MemoryBlock createInitializedBlock(String name, Address start, FileBytes fileBytes,
			long offset, long size, boolean overlay) {
		throw new UnsupportedOperationException();
	}

}
