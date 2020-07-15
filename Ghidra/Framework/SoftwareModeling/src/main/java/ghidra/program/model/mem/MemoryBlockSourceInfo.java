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

import java.util.Optional;

import ghidra.program.database.mem.ByteMappingScheme;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;

/** 
 * Describes the source of bytes for a memory block.
 */
public interface MemoryBlockSourceInfo {

	/**
	 * Returns the length of this block byte source.
	 * @return the length of this block byte source.
	 */
	long getLength();

	/**
	 * Returns the start address where this byte source is mapped.
	 * @return  the start address where this byte source is mapped.
	 */
	Address getMinAddress();

	/**
	 * Returns the end address where this byte source is mapped.
	 * @return  the end address where this byte source is mapped.
	 */
	Address getMaxAddress();

	/**
	 * Returns a description of this SourceInfo object.
	 * @return  a description of this SourceInfo object.
	 */
	String getDescription();

	/**
	 * Returns an {@link Optional} {@link FileBytes} object if a FileBytes object is the byte
	 * source for this SourceInfo.  Otherwise, the Optional will be empty.
	 * @return  the {@link FileBytes} object if it is the byte source for this section
	 */
	Optional<FileBytes> getFileBytes();

	/**
	 * Returns the offset into the {@link FileBytes} object where this section starts getting its bytes or
	 * -1 if this SourceInfo does not have an associated {@link FileBytes}
	 * @return  the offset into the {@link FileBytes} object where this section starts getting its bytes.
	 */
	long getFileBytesOffset();

	/**
	 * Returns the offset into the {@link FileBytes} object for the given address or
	 * -1 if this MemoryBlockSourceInfo does not have an associated {@link FileBytes} or the address doesn't
	 * belong to this MemoryBlockSourceInfo.
	 * 
	 * @param address the address for which to get an offset into the {@link FileBytes} object.
	 * @return  the offset into the {@link FileBytes} object for the given address. 
	 */
	long getFileBytesOffset(Address address);

	/**
	 * Returns an {@link Optional} {@link AddressRange} for the mapped addresses if this is a mapped
	 * memory block (bit mapped or byte mapped). Otherwise, the Optional is empty.
	 * @return an {@link Optional} {@link AddressRange} for the mapped addresses if this is a mapped
	 * memory block
	 */
	Optional<AddressRange> getMappedRange();

	/**
	 * Returns an {@link Optional} {@link ByteMappingScheme} employed if this is a byte-mapped 
	 * memory block.  Otherwise, the Optional is empty. 
	 * @return an {@link Optional} {@link ByteMappingScheme} employed if this is a byte-mapped memory block. 
	 */
	Optional<ByteMappingScheme> getByteMappingScheme();

	/**
	 * Returns the containing Memory Block 
	 * @return the containing Memory Block
	 */
	MemoryBlock getMemoryBlock();

	/**
	 * Returns true if this SourceInfo object applies to the given address;
	 * @param address the address to test if this is its SourceInfo
	 * @return  true if this SourceInfo object applies to the given address;
	 */
	boolean contains(Address address);

}
