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
import ghidra.app.util.bin.format.dwarf.sectionprovider.DWARFSectionNames;

/**
 * Header found at the start of a set of DWARFRangeList entries, which are stored sequentially
 * in the {@link DWARFSectionNames#DEBUG_RNGLISTS .debug_rnglists} section.
 */
public class DWARFRangeListHeader extends DWARFIndirectTableHeader {

	public static DWARFRangeListHeader read(BinaryReader reader, int defaultIntSize)
			throws IOException {
		// length : dwarf_length
		// version : 2 bytes
		// address_size : 1 byte
		// segment_selector_size : 1 byte
		// offset entry count: 4 bytes
		// offsets : array of elements are are dwarf_format_int sized

		long startOffset = reader.getPointerIndex();
		DWARFLengthValue lengthInfo = DWARFLengthValue.read(reader, defaultIntSize);
		if (lengthInfo == null) {
			return null;
		}

		long endOffset = reader.getPointerIndex() + lengthInfo.length();
		short version = reader.readNextShort();
		if (version != 5) {
			throw new DWARFException("DWARFRangeList (%x): unsupported DWARF version [%d]"
					.formatted(startOffset, version));
		}
		int addressSize = reader.readNextUnsignedByte();
		int segmentSelectorSize = reader.readNextUnsignedByte();
		int offsetEntryCount = reader.readNextUnsignedIntExact();
		long offsetListPosition = reader.getPointerIndex();

		reader.setPointerIndex(endOffset);
		if (segmentSelectorSize != 0) {
			throw new IOException("Unsupported segmentSelectorSize: " + segmentSelectorSize);
		}

		return new DWARFRangeListHeader(startOffset, endOffset, offsetListPosition,
			lengthInfo.intSize(), offsetEntryCount, addressSize, segmentSelectorSize);
	}

	private final int offsetEntryCount;
	private final int offsetIntSize;
	private final int addressSize;
	private final int segmentSelectorSize;

	public DWARFRangeListHeader(long startOffset, long endOffset, long firstElementOffset,
			int offsetIntSize, int offsetEntryCount, int addressSize, int segmentSelectorSize) {
		super(startOffset, endOffset, firstElementOffset);
		this.offsetIntSize = offsetIntSize;
		this.offsetEntryCount = offsetEntryCount;
		this.addressSize = addressSize;
		this.segmentSelectorSize = segmentSelectorSize;
	}

	@Override
	public long getOffset(int index, BinaryReader reader) throws IOException {
		if (index < 0 || offsetEntryCount <= index) {
			throw new IOException("Invalid range list index: " + index);
		}
		return firstElementOffset +
			reader.readUnsignedValue(firstElementOffset + (index * offsetIntSize), offsetIntSize);
	}
}
