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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a dyld_chained_starts_in_image structure.
 * 
 * @see <a href="https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h">mach-o/fixup-chains.h</a> 
 */
public class DyldChainedStartsInImage implements StructConverter {

	private int segCount;
	private int[] segInfoOffset;

	private List<DyldChainedStartsInSegment> chainedStarts;

	/**
	 * Creates a new {@link DyldChainedStartsInImage}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public DyldChainedStartsInImage(BinaryReader reader) throws IOException {

		long ptrIndex = reader.getPointerIndex();

		segCount = reader.readNextInt();
		segInfoOffset = reader.readNextIntArray(segCount);

		chainedStarts = new ArrayList<>();
		for (int offset : segInfoOffset) {
			if (offset != 0) {
				reader.setPointerIndex(ptrIndex + offset);
				chainedStarts.add(new DyldChainedStartsInSegment(reader));
			}
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dyld_chained_starts_in_image", 0);
		struct.add(DWORD, "seg_count", null);
		struct.add(new ArrayDataType(DWORD, segCount, 1), "seg_info_offset",
			"each entry is offset into this struct for that segment followed by pool of dyld_chain_starts_in_segment data");
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	public int getSegCount() {
		return segCount;
	}

	public int[] getSegInfoOffset() {
		return segInfoOffset;
	}

	public List<DyldChainedStartsInSegment> getChainedStarts() {
		return chainedStarts;
	}
}
