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
 * Header at the beginning of a address list table
 */
public class DWARFAddressListHeader extends DWARFIndirectTableHeader {

	/**
	 * Reads a {@link DWARFAddressListHeader} from the stream.
	 * 
	 * @param reader {@link BinaryReader} stream
	 * @param defaultIntSize native int size for the binary
	 * @return {@link DWARFAddressListHeader}, or null if end-of-list marker
	 * @throws IOException if error reading
	 */
	public static DWARFAddressListHeader read(BinaryReader reader, int defaultIntSize)
			throws IOException {
		// length : dwarf_length
		// version : 2 bytes
		// addr_size : 1 byte
		// seg_sel_size : 1 byte

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
		int addressSize = reader.readNextUnsignedByte();
		int segmentSelectorSize = reader.readNextUnsignedByte();
		long firstAddr = reader.getPointerIndex();
		reader.setPointerIndex(endOffset);

		int count = (int) ((endOffset - firstAddr) / (addressSize + segmentSelectorSize));
		return new DWARFAddressListHeader(startOffset, endOffset, firstAddr, addressSize,
			segmentSelectorSize, count);
	}

	private final int addressSize;
	private final int segmentSelectorSize;
	private final int addrCount;

	public DWARFAddressListHeader(long startOffset, long endOffset, long firstElementOffset,
			int addressSize, int segmentSelectorSize, int addrCount) {
		super(startOffset, endOffset, firstElementOffset);

		this.addressSize = addressSize;
		this.segmentSelectorSize = segmentSelectorSize;
		this.addrCount = addrCount;
	}

	@Override
	public long getOffset(int index, BinaryReader reader) throws IOException {
		if (index < 0 || addrCount <= index) {
			throw new IOException("Invalid address index: %d".formatted(index));
		}
		long offset = firstElementOffset + (addressSize + segmentSelectorSize) * index;

		@SuppressWarnings("unused")
		long seg =
			segmentSelectorSize > 0 ? reader.readUnsignedValue(offset, segmentSelectorSize) : 0;

		long addr = reader.readUnsignedValue(offset + segmentSelectorSize, addressSize);
		return addr;
	}

	public int getAddressSize() {
		return addressSize;
	}

	public int getSegmentSelectorSize() {
		return segmentSelectorSize;
	}

}
