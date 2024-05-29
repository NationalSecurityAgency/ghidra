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

import static ghidra.app.util.bin.format.dwarf.DWARFLocationListEntry.*;
import static ghidra.app.util.bin.format.dwarf.attribs.DWARFForm.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf.expression.DWARFExpression;
import ghidra.program.model.data.LEB128;
import ghidra.util.NumericUtilities;

/**
 * A collection of {@link DWARFLocation} elements, each which represents a location of an item 
 * that is only valid for a certain range of program-counter locations.
 */
public class DWARFLocationList {
	public static final DWARFLocationList EMPTY = new DWARFLocationList(List.of());

	/**
	 * Creates a simple location list containing a single wildcarded range and the specified
	 * expression bytes.
	 *  
	 * @param expr {@link DWARFExpression} bytes
	 * @return new {@link DWARFLocationList} containing a single wildcarded range
	 */
	public static DWARFLocationList withWildcardRange(byte[] expr) {
		return new DWARFLocationList(List.of(new DWARFLocation(null, expr)));
	}

	/**
	 * Read a v4 {@link DWARFLocationList} from the debug_loc section.
	 * <p>
	 * @param reader stream positioned at the start of a .debug_loc location list 
	 * @param cu the compUnit that refers to the location list
	 * @return list of DWARF locations (address range and location expression)
	 * @throws IOException if an I/O error occurs
	 */
	public static DWARFLocationList readV4(BinaryReader reader, DWARFCompilationUnit cu)
			throws IOException {
		List<DWARFLocation> results = new ArrayList<>();

		byte pointerSize = cu.getPointerSize();
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

			int size = reader.readNextUnsignedShort();
			byte[] expr = reader.readNextByteArray(size);

			if (beginning == ending) {
				// skip adding empty ranges because Ghidra can't use them
				continue;
			}

			DWARFRange range = new DWARFRange(baseAddress + beginning, baseAddress + ending);
			results.add(new DWARFLocation(range, expr));
		}
		return new DWARFLocationList(results);
	}

	/**
	 * Reads a v5 {@link DWARFLocationList} from the debug_loclists stream.
	 * 
	 * @param reader stream positioned at the start of a .debug_loclists location list
	 * @param cu the compUnit that refers to the location list
	 * @return list of DWARF locations (address range and location expression)
	 * @throws IOException if an I/O error occurs
	 */
	public static DWARFLocationList readV5(BinaryReader reader, DWARFCompilationUnit cu)
			throws IOException {
		long baseAddr = cu.getPCRange().getFrom();
		DWARFProgram dprog = cu.getProgram();

		List<DWARFLocation> list = new ArrayList<>();
		while (reader.hasNext()) {
			int lleId = reader.readNextUnsignedByte();
			if (lleId == DW_LLE_end_of_list) {
				break;
			}
			switch (lleId) {
				case DW_LLE_base_addressx: {
					int addrIndex = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
					baseAddr = dprog.getAddress(DW_FORM_addrx, addrIndex, cu);
					break;
				}
				case DW_LLE_startx_endx: {
					int startAddrIndex = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
					int endAddrIndex = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
					byte[] expr = reader.readNext(DWARFLocationList::uleb128SizedByteArray);
					long start = dprog.getAddress(DW_FORM_addrx, startAddrIndex, cu);
					long end = dprog.getAddress(DW_FORM_addrx, endAddrIndex, cu);
					list.add(new DWARFLocation(start, end, expr));
					break;
				}
				case DW_LLE_startx_length: {
					int startAddrIndex = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
					int len = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
					byte[] expr = reader.readNext(DWARFLocationList::uleb128SizedByteArray);
					long start = dprog.getAddress(DW_FORM_addrx, startAddrIndex, cu);
					list.add(new DWARFLocation(start, start + len, expr));
					break;
				}
				case DW_LLE_offset_pair: {
					int startOfs = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
					int endOfs = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
					byte[] expr = reader.readNext(DWARFLocationList::uleb128SizedByteArray);
					list.add(new DWARFLocation(baseAddr + startOfs, baseAddr + endOfs, expr));
					break;
				}
				case DW_LLE_default_location: {
					byte[] expr = reader.readNext(DWARFLocationList::uleb128SizedByteArray);
					list.add(new DWARFLocation(DWARFRange.EMPTY, expr));
					break;
				}
				case DW_LLE_base_address: {
					baseAddr = reader.readNextUnsignedValue(cu.getPointerSize());
					break;
				}
				case DW_LLE_start_end: {
					long startAddr = reader.readNextUnsignedValue(cu.getPointerSize());
					long endAddr = reader.readNextUnsignedValue(cu.getPointerSize());
					byte[] expr = reader.readNext(DWARFLocationList::uleb128SizedByteArray);
					list.add(new DWARFLocation(startAddr, endAddr, expr));
					break;
				}
				case DW_LLE_start_length: {
					long startAddr = reader.readNextUnsignedValue(cu.getPointerSize());
					int len = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
					byte[] expr = reader.readNext(DWARFLocationList::uleb128SizedByteArray);
					list.add(new DWARFLocation(startAddr, startAddr + len, expr));
					break;
				}
				default:
					throw new IOException(
						"Unsupported DWARF Location List Entry type: %d".formatted(lleId));
			}
		}
		return new DWARFLocationList(list);
	}

	private List<DWARFLocation> list;

	public DWARFLocationList(List<DWARFLocation> list) {
		this.list = list;
	}

	public boolean isEmpty() {
		return list.isEmpty();
	}

	/**
	 * Get the location that corresponds to the specified PC location.
	 *
	 * @param pc programcounter address
	 * @return the byte array corresponding to the location expression
	 */
	public DWARFLocation getLocationContaining(long pc) {
		for (DWARFLocation loc : list) {
			if (loc.contains(pc)) {
				return loc;
			}
		}
		return null;
	}

	public DWARFLocation getFirstLocation() {
		return !list.isEmpty() ? list.get(0) : null;
	}

	@Override
	public String toString() {
		return "DWARFLocationList: " + list;
	}

	/**
	 * Reader func that reads a uleb128-length prefixed byte array.
	 * 
	 * @param reader {@link BinaryReader} stream
	 * @return byte array, length specified by the leading leb128 value
	 * @throws IOException if error reading
	 */
	private static byte[] uleb128SizedByteArray(BinaryReader reader) throws IOException {
		int len = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
		if (len > DWARFExpression.MAX_SANE_EXPR) {
			throw new IOException("Invalid DWARF exprloc size: %d".formatted(len));
		}
		return reader.readNextByteArray(len);
	}

}
