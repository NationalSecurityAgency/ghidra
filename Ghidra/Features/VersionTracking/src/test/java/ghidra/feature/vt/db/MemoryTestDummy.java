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
package ghidra.feature.vt.db;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import ghidra.framework.store.LockException;
import ghidra.program.database.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class MemoryTestDummy extends AddressSet implements Memory {

	MemoryTestDummy(Address start, Address end) {
		super(start, end);
	}

	@Override
	public MemoryBlock convertToInitialized(MemoryBlock unitializedBlock, byte initialValue)
			throws LockException, MemoryBlockException, NotFoundException {
		return null;
	}

	@Override
	public MemoryBlock convertToUninitialized(MemoryBlock initializedBlock)
			throws LockException, MemoryBlockException, NotFoundException {
		return null;
	}

	@Override
	public MemoryBlock createBitMappedBlock(String name, Address start, Address mappedAddress,
			long length, boolean overlay)
			throws LockException, MemoryConflictException, AddressOverflowException {
		return null;
	}

	@Override
	public MemoryBlock createBlock(MemoryBlock block, String name, Address start, long length)
			throws LockException, MemoryConflictException, AddressOverflowException {
		return null;
	}

	@Override
	public MemoryBlock createByteMappedBlock(String name, Address start, Address mappedAddress,
			long length, ByteMappingScheme byteMappingScheme, boolean overlay)
			throws LockException, MemoryConflictException, AddressOverflowException,
			IllegalArgumentException {
		return null;
	}

	@Override
	public MemoryBlock createInitializedBlock(String name, Address start, InputStream is,
			long length, TaskMonitor monitor, boolean overlay)
			throws LockException, MemoryConflictException, AddressOverflowException,
			CancelledException, DuplicateNameException {
		return null;
	}

	@Override
	public MemoryBlock createInitializedBlock(String name, Address start, long size,
			byte initialValue, TaskMonitor monitor, boolean overlay)
			throws LockException, DuplicateNameException, MemoryConflictException,
			AddressOverflowException, CancelledException {
		return null;
	}

	@Override
	public MemoryBlock createUninitializedBlock(String name, Address start, long size,
			boolean overlay) throws LockException, DuplicateNameException, MemoryConflictException,
			AddressOverflowException {
		return null;
	}

	@Override
	public Address findBytes(Address addr, byte[] bytes, byte[] masks, boolean forward,
			TaskMonitor monitor) {
		return null;
	}

	@Override
	public Address findBytes(Address startAddr, Address endAddr, byte[] bytes, byte[] masks,
			boolean forward, TaskMonitor monitor) {
		return null;
	}

	@Override
	public MemoryBlock getBlock(Address addr) {
		return null;
	}

	@Override
	public MemoryBlock getBlock(String blockName) {
		return null;
	}

	@Override
	public MemoryBlock[] getBlocks() {
		return null;
	}

	@Override
	public byte getByte(Address addr) throws MemoryAccessException {
		return 0;
	}

	@Override
	public int getBytes(Address addr, byte[] dest) throws MemoryAccessException {
		return 0;
	}

	@Override
	public int getBytes(Address addr, byte[] dest, int dIndex, int size)
			throws MemoryAccessException {
		return 0;
	}

	@Override
	public AddressSetView getExecuteSet() {
		return null;
	}

	@Override
	public AddressSetView getLoadedAndInitializedAddressSet() {
		return null;
	}

	@Override
	public AddressSetView getInitializedAddressSet() {
		return null;
	}

	@Override
	public AddressSetView getAllInitializedAddressSet() {
		return null;
	}

	@Override
	public int getInt(Address addr) throws MemoryAccessException {
		return 0;
	}

	@Override
	public int getInt(Address addr, boolean bigEndian) throws MemoryAccessException {
		return 0;
	}

	@Override
	public int getInts(Address addr, int[] dest) throws MemoryAccessException {
		return 0;
	}

	@Override
	public int getInts(Address addr, int[] dest, int dIndex, int nElem)
			throws MemoryAccessException {
		return 0;
	}

	@Override
	public int getInts(Address addr, int[] dest, int dIndex, int nElem, boolean isBigEndian)
			throws MemoryAccessException {
		return 0;
	}

	@Override
	public LiveMemoryHandler getLiveMemoryHandler() {
		return null;
	}

	@Override
	public long getLong(Address addr) throws MemoryAccessException {
		return 0;
	}

	@Override
	public long getLong(Address addr, boolean bigEndian) throws MemoryAccessException {
		return 0;
	}

	@Override
	public int getLongs(Address addr, long[] dest) throws MemoryAccessException {
		return 0;
	}

	@Override
	public int getLongs(Address addr, long[] dest, int dIndex, int nElem)
			throws MemoryAccessException {
		return 0;
	}

	@Override
	public int getLongs(Address addr, long[] dest, int dIndex, int nElem, boolean isBigEndian)
			throws MemoryAccessException {
		return 0;
	}

	@Override
	public Program getProgram() {
		return null;
	}

	@Override
	public short getShort(Address addr) throws MemoryAccessException {
		return 0;
	}

	@Override
	public short getShort(Address addr, boolean bigEndian) throws MemoryAccessException {
		return 0;
	}

	@Override
	public int getShorts(Address addr, short[] dest) throws MemoryAccessException {
		return 0;
	}

	@Override
	public int getShorts(Address addr, short[] dest, int dIndex, int nElem)
			throws MemoryAccessException {
		return 0;
	}

	@Override
	public int getShorts(Address addr, short[] dest, int dIndex, int nElem, boolean isBigEndian)
			throws MemoryAccessException {
		return 0;
	}

	@Override
	public long getSize() {
		return 0;
	}

	@Override
	public boolean isBigEndian() {
		return false;
	}

	@Override
	public MemoryBlock join(MemoryBlock blockOne, MemoryBlock blockTwo)
			throws LockException, MemoryBlockException, NotFoundException {
		return null;
	}

	@Override
	public void moveBlock(MemoryBlock block, Address newStartAddr, TaskMonitor monitor)
			throws LockException, MemoryBlockException, MemoryConflictException,
			AddressOverflowException, NotFoundException {
		// no op
	}

	@Override
	public void removeBlock(MemoryBlock block, TaskMonitor monitor) throws LockException {
		// no op
	}

	@Override
	public void setByte(Address addr, byte value) throws MemoryAccessException {
		// no op
	}

	@Override
	public void setBytes(Address addr, byte[] source) throws MemoryAccessException {
		// no op
	}

	@Override
	public void setBytes(Address addr, byte[] source, int sIndex, int size)
			throws MemoryAccessException {
		// no op
	}

	@Override
	public void setInt(Address addr, int value) throws MemoryAccessException {
		// no op
	}

	@Override
	public void setInt(Address addr, int value, boolean bigEndian) throws MemoryAccessException {
		// no op
	}

	@Override
	public void setLiveMemoryHandler(LiveMemoryHandler handler) {
		// no op
	}

	@Override
	public void setLong(Address addr, long value) throws MemoryAccessException {
		// no op
	}

	@Override
	public void setLong(Address addr, long value, boolean bigEndian) throws MemoryAccessException {
		// no op
	}

	@Override
	public void setShort(Address addr, short value) throws MemoryAccessException {
		// no op
	}

	@Override
	public void setShort(Address addr, short value, boolean bigEndian)
			throws MemoryAccessException {
		// no op
	}

	@Override
	public void split(MemoryBlock block, Address addr)
			throws MemoryBlockException, LockException, NotFoundException {
		// no op
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
			long offset, long size, boolean overlay) throws LockException, DuplicateNameException,
			MemoryConflictException, AddressOverflowException {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressSourceInfo getAddressSourceInfo(Address address) {
		throw new UnsupportedOperationException();
	}
}
