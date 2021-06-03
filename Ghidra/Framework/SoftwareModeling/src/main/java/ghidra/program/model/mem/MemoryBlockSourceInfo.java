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
	 * Returns the offset into the underlying {@link FileBytes} object where this sub-block 
	 * starts getting its bytes from or -1 if this sub-block does not have an associated {@link FileBytes}
	 * or a complex bit/byte-mapping is used.
	 * @return  the offset into the {@link FileBytes} object where this section starts getting its bytes.
	 */
	long getFileBytesOffset();

	/**
	 * Returns the offset into the {@link FileBytes} object for the given address or
	 * -1 if this sub-block if address is out of range or this sub-block does not have 
	 * an associated {@link FileBytes}, or a complex bit/byte-mapping is used.
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

	/**
	 * Determine if this block source contains the specified file offset.
	 * 
	 * @param fileOffset file offset within underlying FileBytes (if applicable) within the loaded 
	 *   range associated with this source info.
	 * @return true if file offset is within the loaded range of the corresponding FileBytes, else 
	 *   false if method is not supported by the sub-block type (e.g., bit/byte-mapped sub-block).
	 */
	default boolean containsFileOffset(long fileOffset) {
		long startOffset = getFileBytesOffset();
		if (startOffset < 0 || fileOffset < 0) {
			return false;
		}
		// NOTE: logic does not handle bit/byte-mapped blocks (assumes 1:1 mapping)
		long endOffset = startOffset + (getLength() - 1);
		return (fileOffset >= startOffset) && (fileOffset <= endOffset);
	}

	/**
	 * Get the Address within this sub-block which corresponds to the specified file offset.
	 *  
	 * @param fileOffset file offset
	 * @return {@link Address} within this sub-block or null if file offset is out of range
	 * or method is not supported by the sub-block type (e.g., bit/byte-mapped sub-block).
	 */
	default Address locateAddressForFileOffset(long fileOffset) {
		long startOffset = getFileBytesOffset();
		if (!containsFileOffset(fileOffset)) {
			return null;
		}
		// NOTE: logic does not handle bit/byte-mapped blocks (assumes 1:1 mapping)
		long offset = fileOffset - startOffset;
		if (offset >= getLength()) {
			return null;
		}
		return getMinAddress().add(offset);
	}

}
