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
package ghidra.app.util.bin.format.macho.commands;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a dyld_chained_starts_in_segment structure.
 * 
 * @see <a href="https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/fixup-chains.h.auto.html">mach-o/fixup-chains.h</a> 
 */
public class DyldChainedStartsInSegment implements StructConverter {

	private int size;               // size of this (amount kernel needs to copy)
	private short page_size;        // 0x1000 or 0x4000
	private short pointer_format;   // DYLD_CHAINED_PTR_*
	private long segment_offset;    // offset in memory to start of segment
	private int max_valid_pointer;  // for 32-bit OS, any value beyond this is not a pointer
	private short page_count;       // how many pages are in array
	private short page_starts[];    // each entry is offset in each page of first element in chain
	private short chain_starts[];   // TODO: used for some 32-bit formats with multiple starts per page 

	DyldChainedStartsInSegment(BinaryReader reader) throws IOException {
		size = reader.readNextInt();
		page_size = reader.readNextShort();
		pointer_format = reader.readNextShort();
		segment_offset = reader.readNextLong();
		max_valid_pointer = reader.readNextInt();
		page_count = reader.readNextShort();

		page_starts = reader.readNextShortArray(page_count);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dyld_chained_starts_in_segment", 0);
		struct.add(DWORD, "size", null);
		struct.add(WORD, "page_size", null);
		struct.add(WORD, "pointer_format", null);
		struct.add(QWORD, "segment_offset", null);
		struct.add(DWORD, "max_valid_pointer", null);
		struct.add(WORD, "page_count", null);
		struct.add(new ArrayDataType(WORD, page_count, 1), "page_starts", "");

		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	public int getSize() {
		return size;
	}

	public short getPageSize() {
		return page_size;
	}

	public short getPointerFormat() {
		return pointer_format;
	}

	public long getSegmentOffset() {
		return segment_offset;
	}

	public int getMaxValidPointer() {
		return max_valid_pointer;
	}

	public short getPageCount() {
		return page_count;
	}

	public short[] getPage_starts() {
		return page_starts;
	}

	public short[] getChain_starts() {
		return chain_starts;
	}
}
