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
import java.util.ArrayList;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a dyld_chained_starts_in_image structure.
 * 
 * @see <a href="https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/fixup-chains.h.auto.html">mach-o/fixup-chains.h</a> 
 */
public class DyldChainedStartsInImage implements StructConverter {

	private int seg_count;         // count of segment chain starts
	private int seg_info_offset[];

	private DyldChainedStartsInSegment chainedStarts[];

	DyldChainedStartsInImage(BinaryReader reader) throws IOException {

		long ptrIndex = reader.getPointerIndex();

		seg_count = reader.readNextInt();
		seg_info_offset = reader.readNextIntArray(seg_count);

		ArrayList<DyldChainedStartsInSegment> starts = new ArrayList<>();
		for (int off : seg_info_offset) {

			// off == 0 means there is no associated starts_in_segment entry
			if (off == 0) {
				continue;
			}

			reader.setPointerIndex(ptrIndex + off);
			starts.add(new DyldChainedStartsInSegment(reader));
		}
		chainedStarts = starts.toArray(DyldChainedStartsInSegment[]::new);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dyld_chained_starts_in_image", 0);

		struct.add(DWORD, "seg_count", null);
		struct.add(new ArrayDataType(DWORD, seg_count, 1), "seg_info_offset", "");

		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

	public int getSeg_count() {
		return seg_count;
	}

	public int[] getSeg_info_offset() {
		return seg_info_offset;
	}

	public DyldChainedStartsInSegment[] getChainedStarts() {
		return chainedStarts;
	}
}
