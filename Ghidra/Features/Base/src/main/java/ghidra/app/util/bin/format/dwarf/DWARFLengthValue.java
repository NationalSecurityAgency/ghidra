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
package ghidra.app.util.bin.format.dwarf;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

/**
 * A tuple of length (of a thing in a dwarf stream) and size of integers used in the dwarf section.
 *  
 * @param length the length of the following item 
 * @param intSize the size of integers used in the following item
 */
public record DWARFLengthValue(long length, int intSize) {
	/**
	 * Read a variable-length length value from the stream.
	 * <p>
	 * The length value will either occupy 4 (int32) or 12 bytes (int32 flag + int64 length) and
	 * as a side-effect signals the size integer values occupy.
	 * 
	 * @param reader {@link BinaryReader} stream to read from
	 * @param defaultPointerSize size in bytes of pointers in the program 
	 * @return new {@link DWARFLengthValue}, or null if the stream was just zero-padded data
	 * @throws IOException if io error
	 */
	public static DWARFLengthValue read(BinaryReader reader, int defaultPointerSize)
			throws IOException {
		long startOffset = reader.getPointerIndex();
		long length = reader.readNextUnsignedInt();
		int intSize = 4;

		if (length == 0xffff_ffffL /* max uint32 */) {
			// Length of 0xffffffff implies 64-bit DWARF format
			// Mostly untested as there is no easy way to force the compiler
			// to generate this
			length = reader.readNextLong();
			intSize = 8;
		}
		else if (length >= 0xffff_fff0L) {
			// Length of 0xfffffff0 or greater is reserved for DWARF
			throw new IOException(
				"Reserved DWARF length value: %x. Unknown extension.".formatted(length));
		}
		else if (length == 0) {
			if (isAllZerosUntilEOF(reader)) {
				// hack to handle trailing padding at end of section.  (similar to the check for
				// unexpectedTerminator in readDIEs(), when padding occurs inside the bounds
				// of the compile unit's range after the end of the root DIE's children)
				reader.setPointerIndex(reader.length());
				return null;
			}

			// Test for special case of weird BE MIPS 64bit length value.
			// Instead of following DWARF std (a few lines above with length == MAX_INT),
			// it writes a raw 64bit long (BE). The upper 32 bits (already read as length) will 
			// always be 0 since super-large binaries from that system weren't really possible.
			// The next 32 bits will be the remainder of the value.
			if (reader.isBigEndian() && defaultPointerSize == 8) {
				length = reader.readNextUnsignedInt();
				intSize = 8;
			}

			if (length == 0) {
				throw new IOException("Invalid DWARF length 0 at 0x%x".formatted(startOffset));
			}
		}

		return new DWARFLengthValue(length, intSize);
	}

	private static boolean isAllZerosUntilEOF(BinaryReader reader) throws IOException {
		reader = reader.clone();
		while (reader.hasNext()) {
			if (reader.readNextByte() != 0) {
				return false;
			}
		}
		return true;
	}

}
