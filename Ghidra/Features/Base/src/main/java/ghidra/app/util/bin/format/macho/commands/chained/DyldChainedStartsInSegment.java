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
package ghidra.app.util.bin.format.macho.commands.chained;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a dyld_chained_starts_in_segment structure.
 * 
 * @see <a href="https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h">mach-o/fixup-chains.h</a> 
 */
public class DyldChainedStartsInSegment implements StructConverter {

	private int size;
	private short pageSize;
	private short pointerFormat;
	private long segmentOffset;
	private int maxValidPointer;
	private short pageCount;

	private short[] pageStarts;

	/**
	 * Creates a new {@link DyldChainedStartsInSegment}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public DyldChainedStartsInSegment(BinaryReader reader) throws IOException {
		size = reader.readNextInt();
		pageSize = reader.readNextShort();
		pointerFormat = reader.readNextShort();
		segmentOffset = reader.readNextLong();
		maxValidPointer = reader.readNextInt();
		pageCount = reader.readNextShort();

		pageStarts = reader.readNextShortArray(pageCount);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dyld_chained_starts_in_segment", 0);
		struct.add(DWORD, "size", "size of this (amount kernel needs to copy)");
		struct.add(WORD, "page_size", "0x1000 or 0x4000");
		struct.add(WORD, "pointer_format", "DYLD_CHAINED_PTR_*");
		struct.add(IBO64, "segment_offset", "offset in memory to start of segment");
		struct.add(DWORD, "max_valid_pointer",
			"for 32-bit OS, any value beyond this is not a pointer");
		struct.add(WORD, "page_count", "how many pages are in array");
		struct.add(new ArrayDataType(WORD, pageCount, 1), "page_starts",
			"each entry is offset in each page of first element in chain or DYLD_CHAINED_PTR_START_NONE if no fixups on page");
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	public int getSize() {
		return size;
	}

	public short getPageSize() {
		return pageSize;
	}

	public short getPointerFormat() {
		return pointerFormat;
	}

	public long getSegmentOffset() {
		return segmentOffset;
	}

	public int getMaxValidPointer() {
		return maxValidPointer;
	}

	public short getPageCount() {
		return pageCount;
	}

	public short[] getPageStarts() {
		return pageStarts;
	}
}
