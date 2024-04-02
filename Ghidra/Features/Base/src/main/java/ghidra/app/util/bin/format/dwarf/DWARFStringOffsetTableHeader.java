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
import ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute;
import ghidra.app.util.bin.format.dwarf.attribs.DWARFForm;
import ghidra.app.util.bin.format.dwarf.sectionprovider.DWARFSectionNames;

/**
 * Table of offsets that point into the string table.  These tables are stored sequentially in the
 * {@link DWARFSectionNames#DEBUG_STROFFSETS .debug_str_offsets} section.
 * <p>
 * Elements in the table are referred to by index via {@link DWARFForm#DW_FORM_strx} and friends.
 * <p>
 * The table's {@link #getFirstElementOffset()} is referred to by a compUnit's 
 * {@link DWARFAttribute#DW_AT_str_offsets_base} value.
 */
public class DWARFStringOffsetTableHeader extends DWARFIndirectTableHeader {

	/**
	 * Reads a string offset table header (found in the .debug_str_offsets section)
	 * 
	 * @param dprog {@link DWARFProgram}
	 * @param reader {@link BinaryReader}
	 * @return new {@link DWARFStringOffsetTableHeader} instance
	 * @throws IOException if error reading
	 */
	public static DWARFStringOffsetTableHeader readV5(BinaryReader reader, int defaultIntSize)
			throws IOException {
		// length : dwarf_length
		// version : 2 bytes
		// padding : 2 bytes
		// offsets : array of elements are are dwarf_format_int sized

		long startOffset = reader.getPointerIndex();
		DWARFLengthValue lengthInfo = DWARFLengthValue.read(reader, defaultIntSize);
		if (lengthInfo == null) {
			return null;
		}

		long endOffset = reader.getPointerIndex() + lengthInfo.length();

		short version = reader.readNextShort();
		if (version != 5) {
			throw new DWARFException("Unsupported DWARF version [%d]".formatted(version));
		}

		/* int padding = */ reader.readNextShort();

		long offsetArrayStart = reader.getPointerIndex();
		reader.setPointerIndex(endOffset);
		
		int count = (int) ((endOffset - offsetArrayStart) / lengthInfo.intSize());
		return new DWARFStringOffsetTableHeader(startOffset, endOffset, offsetArrayStart,
			lengthInfo.intSize(), count);
	}

	private final int count;
	private final int intSize;

	public DWARFStringOffsetTableHeader(long startOffset, long endOffset, long firstElementOffset,
			int intSize, int count) {
		super(startOffset, endOffset, firstElementOffset);
		this.intSize = intSize;
		this.count = count;
	}

	@Override
	public long getOffset(int index, BinaryReader reader) throws IOException {
		if (index < 0 || count <= index) {
			throw new IOException(
				"Invalid indirect string index: %d [0x%x]".formatted(index, index));
		}
		return reader.readUnsignedValue(firstElementOffset + (index * intSize), intSize);
	}
}
