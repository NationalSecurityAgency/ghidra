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

import java.util.Optional;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.mem.MemoryBlock;

/** 
 * Class for describing the source of bytes for a memory block.
 */
public class MemoryBlockSourceInfo {

	private final MemoryBlock block;
	private final SubMemoryBlock subBlock;

	MemoryBlockSourceInfo(MemoryBlock block, SubMemoryBlock subBlock) {
		this.block = block;
		this.subBlock = subBlock;
	}

	/**
	 * Returns the length of this block byte source.
	 * @return the length of this block byte source.
	 */
	public long getLength() {
		return subBlock.length;
	}

	/**
	 * Returns the start address where this byte source is mapped.
	 * @return  the start address where this byte source is mapped.
	 */
	public Address getMinAddress() {
		return block.getStart().add(subBlock.startingOffset);
	}

	/**
	 * Returns the end address where this byte source is mapped.
	 * @return  the end address where this byte source is mapped.
	 */
	public Address getMaxAddress() {
		return block.getStart().add(subBlock.startingOffset + subBlock.length - 1);
	}

	/**
	 * Returns a description of this SourceInfo object.
	 * @return  a description of this SourceInfo object.
	 */
	public String getDescription() {
		return subBlock.getDescription();
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + ": StartAddress = " + getMinAddress() + ", length = " +
			getLength();

	}

	/**
	 * Returns an {@link Optional} {@link FileBytes} object if a FileBytes object is the byte
	 * source for this SourceInfo.  Otherwise, the Optional will be empty.
	 * @return  the {@link FileBytes} object if it is the byte source for this section
	 */
	public Optional<FileBytes> getFileBytes() {
		if (subBlock instanceof FileBytesSubMemoryBlock) {
			return Optional.of(((FileBytesSubMemoryBlock) subBlock).getFileBytes());
		}
		return Optional.empty();
	}

	/**
	 * Returns the offset into the {@link FileBytes} object where this section starts getting its bytes or
	 * -1 if this SourceInfo does not have an associated {@link FileBytes}
	 * @return  the offset into the {@link FileBytes} object where this section starts getting its bytes.
	 */
	public long getFileBytesOffset() {
		if (subBlock instanceof FileBytesSubMemoryBlock) {
			return ((FileBytesSubMemoryBlock) subBlock).getFileBytesOffset();
		}
		return -1;
	}

	/**
	 * Returns the offset into the {@link FileBytes} object for the given address or
	 * -1 if this SourceInfo does not have an associated {@link FileBytes} or the address doesn't
	 * belong to this SourceInfo.
	 * 
	 * @param address the address for which to get an offset into the {@link FileBytes} object.
	 * @return  the offset into the {@link FileBytes} object for the given address. 
	 */
	public long getFileBytesOffset(Address address) {
		if (!contains(address)) {
			return -1;
		}
		if (subBlock instanceof FileBytesSubMemoryBlock) {
			long blockOffset = address.subtract(getMinAddress());
			long subBlockOffset = blockOffset - subBlock.startingOffset;
			return ((FileBytesSubMemoryBlock) subBlock).getFileBytesOffset() + subBlockOffset;
		}
		return -1;
	}

	/**
	 * Returns an {@link Optional} {@link AddressRange} for the mapped addresses if this is mapped
	 * memory block (bit mapped or byte mapped). Otherwise, the Optional is empty.
	 * @return an {@link Optional} {@link AddressRange} for the mapped addresses if this is mapped
	 * memory block
	 */
	public Optional<AddressRange> getMappedRange() {
		if (subBlock instanceof BitMappedSubMemoryBlock) {
			BitMappedSubMemoryBlock bitMapped = (BitMappedSubMemoryBlock) subBlock;
			return Optional.of(bitMapped.getMappedRange());
		}
		if (subBlock instanceof ByteMappedSubMemoryBlock) {
			ByteMappedSubMemoryBlock byteMapped = (ByteMappedSubMemoryBlock) subBlock;
			return Optional.of(byteMapped.getMappedRange());
		}
		return Optional.empty();
	}

	/**
	 * Returns the containing Memory Block 
	 * @return the containing Memory Block
	 */
	public MemoryBlock getMemoryBlock() {
		return block;
	}

	/**
	 * Returns true if this SourceInfo object applies to the given address;
	 * @param address the address to test if this is its SourceInfo
	 * @return  true if this SourceInfo object applies to the given address;
	 */
	public boolean contains(Address address) {
		return address.compareTo(getMinAddress()) >= 0 && address.compareTo(getMaxAddress()) <= 0;
	}
}
