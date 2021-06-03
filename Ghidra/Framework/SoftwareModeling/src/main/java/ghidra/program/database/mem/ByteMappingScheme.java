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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.mem.*;

/**
 * <code>ByteMappingScheme</code> facilitate byte mapping/decimation scheme for a mapped sub-block to
 * an underlying source memory region.
 */
public class ByteMappingScheme {

	// Repeating byte mapping pattern defined by number of source bytes mapped (mappedByteCount) followed 
	// by number of non-mapped source bytes (nonMappedByteCount).  The sum of these two values is 
	// mappedSourceByteCount.  The first byte of this block must correspond to the first mapped
	// byte of this mapping sequence.
	private final int mappedByteCount;
	private final int nonMappedByteCount;
	private final int mappedSourceByteCount;

	/**
	 * Construct byte mapping scheme from an encoded mappingScheme value.
	 * @param encodedMappingScheme encoded mapping scheme value or 0 for a 1:1 default mapping.
	 * A zero value is accepted to ensure backward compatibility with pre-existing byte-mapped blocks
	 * where a 1:1 mapping was employed.
	 * @throws IllegalArgumentException if packed mapping scheme produces an invalid mapping ratio
	 */
	ByteMappingScheme(int encodedMappingScheme) throws IllegalArgumentException {
		if (encodedMappingScheme == 0) {
			// default mode implies 1:1 mapping
			mappedByteCount = 1;
			mappedSourceByteCount = 1;
			nonMappedByteCount = 0;
		}
		else {
			mappedByteCount = getMappedByteCount(encodedMappingScheme);
			mappedSourceByteCount = getMappedSourceByteCount(encodedMappingScheme);
			nonMappedByteCount = mappedSourceByteCount - mappedByteCount;
			validateMappingScheme(mappedByteCount, mappedSourceByteCount);
		}
	}

	/**
	 * Construct byte mapping scheme specified as a ratio of mapped bytes to source bytes.
	 * @param mappedByteCount number of mapped bytes per mappedSourcebyteCount (1..127).  This 
	 * value must be less-than or equal to schemeSrcByteCount.
	 * @param mappedSourceByteCount number of source bytes for mapping ratio (1..127)
	 * @throws IllegalArgumentException if invalid mapping scheme specified
	 */
	public ByteMappingScheme(int mappedByteCount, int mappedSourceByteCount) {
		validateMappingScheme(mappedByteCount, mappedSourceByteCount);
		this.mappedByteCount = mappedByteCount;
		this.mappedSourceByteCount = mappedSourceByteCount;
		this.nonMappedByteCount = mappedSourceByteCount - mappedByteCount;
	}

	@Override
	public String toString() {
		String ratioStr = "1:1";
		if (!isOneToOneMapping()) {
			ratioStr = mappedByteCount + ":" + mappedSourceByteCount;
		}
		return ratioStr + " mapping";
	}

	/**
	 * Get byte mapping scheme as single 14-bit packed value for storage and reconstruction use.
	 * @return mapping scheme as single 14-bit integer value
	 */
	int getEncodedMappingScheme() {
		if (isOneToOneMapping()) {
			// for legacy reasons continue to use 0 to indicate 1:1 default mapping
			return 0;
		}
		return getEncodedMappingScheme(mappedByteCount, mappedSourceByteCount);
	}

	/**
	 * Determine this scheme corresponds to a 1:1 byte mapping 
	 * @return true if 1:1 mapping else false
	 */
	public boolean isOneToOneMapping() {
		return mappedSourceByteCount <= 1;
	}

	/**
	 * Get the mapped-byte-count (left-hand value in mapping ratio)
	 * @return mapped-byte-count
	 */
	public int getMappedByteCount() {
		if (isOneToOneMapping()) {
			return 1;
		}
		return mappedByteCount;
	}

	/**
	 * Get the mapped-source-byte-count (right-hand value in mapping ratio)
	 * @return mapped-source-byte-count
	 */
	public int getMappedSourceByteCount() {
		if (isOneToOneMapping()) {
			return 1;
		}
		return mappedSourceByteCount;
	}

	/**
	 * Calculate the mapped source address for a specified offset with the mapped sub-block.
	 * @param mappedSourceBaseAddress mapped source base address for sub-block
	 * @param offsetInSubBlock byte offset within sub-block to be mapped into source
	 * @return mapped source address
	 * @throws AddressOverflowException if offset in sub-block produces a wrap condition in
	 * the mapped source address space.
	 */
	public Address getMappedSourceAddress(Address mappedSourceBaseAddress,
			long offsetInSubBlock)
			throws AddressOverflowException {
		if (offsetInSubBlock < 0) {
			throw new IllegalArgumentException("negative offset");
		}
		long sourceOffset = offsetInSubBlock;
		if (!isOneToOneMapping()) {
			sourceOffset = (mappedSourceByteCount * (offsetInSubBlock / mappedByteCount)) +
				(offsetInSubBlock % mappedByteCount);
		}
		return mappedSourceBaseAddress.addNoWrap(sourceOffset);
	}

	/**
	 * Calculate the address within a mapped block for a specified mapped source offset.
	 * If the specified mappedSourceOffset corresponds to a non-mapped (i.e., skipped) byte
	 * the address returned will correspond to the last mapped byte.  Care must be used
	 * when using this method.
	 * @param mappedBlock mapped block
	 * @param mappedSourceOffset byte offset within mapped source relative to mapped base source address.
	 * @param skipBack controls return address when mappedSourceOffset corresponds to a non-mapped/skipped byte.
	 * If true the returned address will correspond to the previous mapped address, if false the next mapped
	 * address will be returned.
	 * @return mapped address within block or null if skipBack is false and unable to map within block limits
	 * @throws AddressOverflowException thrown for 1:1 mapping when mappedSourceOffset exceeds length of mappedBlock
	 */
	Address getMappedAddress(MemoryBlock mappedBlock, long mappedSourceOffset, boolean skipBack)
			throws AddressOverflowException {
		if (mappedSourceOffset < 0) {
			throw new IllegalArgumentException("negative source offset");
		}
		long mappedOffset = mappedSourceOffset;
		if (!isOneToOneMapping()) {
			mappedOffset = (mappedByteCount * (mappedSourceOffset / mappedSourceByteCount));
			long offsetLimit = mappedBlock.getSize() - 1;
			long mod = mappedSourceOffset % mappedSourceByteCount;
			if (mod < mappedByteCount) {
				mappedOffset += mod;
			}
			else if (!skipBack) {
				mappedOffset += mappedByteCount;
				if (mappedOffset > offsetLimit) {
					return null;
				}
			}
		}
		return mappedBlock.getStart().addNoWrap(mappedOffset);
	}

	/**
	 * Read bytes into an array from memory utilizing this mapping scheme.
	 * @param memory program memory
	 * @param mappedSourceBaseAddress base source memory address for byte-mapped subblock
	 * @param offsetInSubBlock byte offset from start of subblock where reading should begin
	 * @param b byte array to be filled
	 * @param off offset within byte array b where filling should start
	 * @param len number of bytes to be read
	 * @return actual number of bytes read
	 * @throws MemoryAccessException if read of uninitialized or non-existing memory occurs
	 * @throws AddressOverflowException if address computation error occurs
	 */
	int getBytes(Memory memory, Address mappedSourceBaseAddress, long offsetInSubBlock, byte[] b,
			int off, int len) throws MemoryAccessException, AddressOverflowException {

		if (isOneToOneMapping()) {
			return memory.getBytes(mappedSourceBaseAddress.addNoWrap(offsetInSubBlock), b, off,
				len);
		}

		// NOTE: approach avoids incremental reading by including unmapped bytes in
		// bulk read and filters as needed based upon mapping scheme ratio
		long patternCount = offsetInSubBlock / mappedByteCount;
		int partialByteCount = (int) (offsetInSubBlock % mappedByteCount);
		long mappedOffset = (mappedSourceByteCount * patternCount) + partialByteCount;

		int bufSize = mappedSourceByteCount * ((len / mappedByteCount) + 1);
		byte[] buf = new byte[bufSize];
		int bufCnt = memory.getBytes(mappedSourceBaseAddress.addNoWrap(mappedOffset), buf);
		int bufIndex = 0;

		int cnt = 0;
		int index = off;
		int i = mappedByteCount - partialByteCount;
		boolean skip = false;
		while (bufIndex < bufCnt && cnt < len) {
			if (!skip) {
				b[index++] = buf[bufIndex];
				++cnt;
				if (--i == 0) {
					skip = true;
					i = nonMappedByteCount;
				}
			}
			else if (--i == 0) {
				skip = false;
				i = mappedByteCount;
			}
			++bufIndex;
		}
		return cnt;
	}

	/**
	 * Write an array of bytes to memory utilizing this mapping scheme.  
	 * @param memory program memory
	 * @param mappedSourceBaseAddress base source memory address for byte-mapped subblock
	 * @param offsetInSubBlock byte offset from start of subblock where writing should begin
	 * @param b an array to get bytes from
	 * @param off start source index within byte array b where bytes should be read
	 * @param len number of bytes to be written
	 * @throws MemoryAccessException if write of uninitialized or non-existing memory occurs
	 * @throws AddressOverflowException if address computation error occurs
	 */
	void setBytes(Memory memory, Address mappedSourceBaseAddress, long offsetInSubBlock,
			byte[] b,
			int off, int len) throws MemoryAccessException, AddressOverflowException {

		if (isOneToOneMapping()) {
			memory.setBytes(mappedSourceBaseAddress.addNoWrap(offsetInSubBlock), b, off, len);
			return;
		}

		long patternCount = offsetInSubBlock / mappedByteCount;
		int partialByteCount = (int) (offsetInSubBlock % mappedByteCount);
		long mappedOffset = (mappedSourceByteCount * patternCount) + partialByteCount;

		Address destAddr = mappedSourceBaseAddress.addNoWrap(mappedOffset);

		int index = off;
		int cnt = 0;
		int i = mappedByteCount - partialByteCount;
		while (cnt < len) {
			memory.setBytes(destAddr, b, index, i);
			index += i;
			cnt += i;
			destAddr = destAddr.addNoWrap(i + nonMappedByteCount);
			i = mappedByteCount;
		}
	}

	/**
	 * Validate mapping scheme.  This scheme is specified as a ratio of mapped bytes to source bytes.
	 * @param schemeDestByteCount number of mapped bytes per mappedSourcebyteCount (1..127).  This 
	 * value must be less-than or equal to schemeSrcByteCount.
	 * @param schemeSrcByteCount number of source bytes for mapping ratio (1..127)
	 * @throws IllegalArgumentException if invalid mapping scheme specified
	 */
	static void validateMappingScheme(int schemeDestByteCount, int schemeSrcByteCount) {
		if (schemeDestByteCount <= 0 || schemeDestByteCount > 0x7F || schemeSrcByteCount <= 0 ||
			schemeSrcByteCount > 0x7F ||
			schemeDestByteCount > schemeSrcByteCount) {
			throw new IllegalArgumentException(
				"invalid byte mapping ratio: " + schemeDestByteCount + ":" + schemeSrcByteCount);
		}
	}

	/**
	 * Get encoded mapping scheme as a single value for storage purposes.  This scheme value 
	 * identifies the ratio of mapped bytes to source bytes.  Value is encoded as two 7-bit 
	 * values corresponding to the destination and source byte counts.
	 * @param schemeDestByteCount number of mapped bytes per mappedSourcebyteCount (1..127).  This 
	 * value must be less-than or equal to schemeSrcByteCount.
	 * @param schemeSrcByteCount number of source bytes for mapping ratio (1..127)
	 * @return mapping scheme value
	 * @throws IllegalArgumentException if invalid mapping scheme specified
	 */
	static int getEncodedMappingScheme(int schemeDestByteCount, int schemeSrcByteCount) {
		validateMappingScheme(schemeDestByteCount, schemeSrcByteCount);
		return (schemeDestByteCount << 7) | (schemeSrcByteCount & 0x7F);
	}

	/**
	 * Extract the mapping scheme mapped-byte-count from a mappingScheme value.
	 * @param mappingScheme mapping scheme
	 * @return mapped-byte-count (aka schemeDestByteCount)
	 */
	static int getMappedByteCount(int mappingScheme) {
		int mappedByteCount = 1;
		if (mappingScheme != 0) {
			mappedByteCount = (mappingScheme >> 7) & 0x7F;
		}
		return mappedByteCount;
	}

	/**
	 * Extract the mapping ratio mapped-source-byte-count from a mappingScheme value.
	 * @param mappingScheme mapping scheme
	 * @return mapped-source-byte-count (aka schemeSrcByteCount)
	 */
	static int getMappedSourceByteCount(int mappingScheme) {
		int mappedSourceByteCount = 1;
		if (mappingScheme != 0) {
			mappedSourceByteCount = mappingScheme & 0x7F;
		}
		return mappedSourceByteCount;
	}

}
