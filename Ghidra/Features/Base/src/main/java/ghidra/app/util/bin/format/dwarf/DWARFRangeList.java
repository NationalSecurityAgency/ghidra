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

import static ghidra.app.util.bin.format.dwarf.DWARFRangeListEntry.*;
import static ghidra.app.util.bin.format.dwarf.attribs.DWARFForm.*;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.LEB128;
import ghidra.util.NumericUtilities;

/**
 * Represents a list of {@link DWARFRange}s.
 */
public class DWARFRangeList {

	public static final DWARFRangeList EMTPY = new DWARFRangeList(List.of());

	/**
	 * Reads a v4 {@link DWARFRangeList} from the .debug_ranges stream.
	 * 
	 * @param reader stream positioned to the start of a .debug_ranges range list
	 * @param cu the compUnit referring to this range
	 * @return new {@link DWARFRangeList}, never null
	 * @throws IOException if error reading
	 */
	public static DWARFRangeList readV4(BinaryReader reader, DWARFCompilationUnit cu)
			throws IOException {
		byte pointerSize = cu.getPointerSize();
		List<DWARFRange> ranges = new ArrayList<>();

		long baseAddress = cu.getPCRange().getFrom();
		long maxAddrVal = pointerSize == 4 ? NumericUtilities.MAX_UNSIGNED_INT32_AS_LONG : -1;

		while (reader.hasNext()) {
			// Read the beginning and ending addresses
			long beginning = reader.readNextUnsignedValue(pointerSize);
			long ending = reader.readNextUnsignedValue(pointerSize); // dwarf end addrs are exclusive

			// End of the list
			if (beginning == 0 && ending == 0) {
				break;
			}

			// Check to see if this is a base address entry
			if (beginning == maxAddrVal) {
				baseAddress = ending;
				continue;
			}

			// Add the range to the list
			ranges.add(new DWARFRange(baseAddress + beginning, baseAddress + ending));
		}
		return new DWARFRangeList(ranges);
	}

	/**
	 * Reads a v5 {@link DWARFRangeList} from the .debug_rnglists stream.
	 * 
	 * @param reader stream positioned to the start of a .debug_rnglists range list
	 * @param cu the compUnit referring to this range
	 * @return new {@link DWARFRangeList}, never null
	 * @throws IOException if error reading
	 */
	public static DWARFRangeList readV5(BinaryReader reader, DWARFCompilationUnit cu)
			throws IOException {

		List<DWARFRange> list = new ArrayList<>();

		DWARFProgram dprog = cu.getProgram();
		long baseAddr = cu.getPCRange().getFrom();

		while (reader.hasNext()) {
			int rleId = reader.readNextUnsignedByte();
			if (rleId == DW_RLE_end_of_list) {
				break;
			}
			switch (rleId) {
				case DW_RLE_base_addressx: {
					int addrIndex = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
					baseAddr = dprog.getAddress(DW_FORM_addrx, addrIndex, cu);
					break;
				}
				case DW_RLE_startx_endx: {
					int startAddrIndex = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
					int endAddrIndex = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
					long start = dprog.getAddress(DW_FORM_addrx, startAddrIndex, cu);
					long end = dprog.getAddress(DW_FORM_addrx, endAddrIndex, cu);
					list.add(new DWARFRange(start, end));
					break;
				}
				case DW_RLE_startx_length: {
					int startAddrIndex = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
					int len = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
					long start = dprog.getAddress(DW_FORM_addrx, startAddrIndex, cu);
					list.add(new DWARFRange(start, start + len));
					break;
				}
				case DW_RLE_offset_pair: {
					int startOfs = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
					int endOfs = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
					list.add(new DWARFRange(baseAddr+startOfs, baseAddr+endOfs));
					break;
				}
				case DW_RLE_base_address: {
					baseAddr = reader.readNextUnsignedValue(cu.getPointerSize());
					break;
				}
				case DW_RLE_start_end: {
					long startAddr = reader.readNextUnsignedValue(cu.getPointerSize());
					long endAddr = reader.readNextUnsignedValue(cu.getPointerSize());
					list.add(new DWARFRange(startAddr, endAddr));
					break;
				}
				case DW_RLE_start_length: {
					long startAddr = reader.readNextUnsignedValue(cu.getPointerSize());
					int len = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
					list.add(new DWARFRange(startAddr, startAddr + len));
					break;
				}
				default:
					throw new IOException(
						"Unsupported DWARF Range List Entry type: %d".formatted(rleId));
			}
		}
		return new DWARFRangeList(list);
	}

	private List<DWARFRange> ranges;

	public DWARFRangeList(DWARFRange singleRange) {
		ranges = List.of(singleRange);
	}

	public DWARFRangeList(List<DWARFRange> ranges) {
		this.ranges = ranges;
	}

	public boolean isEmpty() {
		return ranges.isEmpty();
	}

	public long getFirstAddress() {
		return getFirst().getFrom();
	}

	public DWARFRange getFirst() {
		return ranges.get(0);
	}

	public DWARFRange get(int index) {
		return ranges.get(index);
	}

	public List<DWARFRange> ranges() {
		return ranges;
	}

	public int getListCount() {
		return ranges.size();
	}

	public DWARFRange getLast() {
		return ranges.get(ranges.size() - 1);
	}

	public DWARFRange getFlattenedRange() {
		if (isEmpty()) {
			return null;
		}
		if (ranges.size() == 1) {
			return getFirst();
		}

		List<DWARFRange> copy = new ArrayList<>(ranges);
		Collections.sort(copy);
		DWARFRange first = copy.get(0);
		DWARFRange last = copy.get(copy.size() - 1);
		return new DWARFRange(first.getFrom(), last.getTo());
	}

	@Override
	public String toString() {
		return "DWARFRangeList: " + ranges;
	}

}
