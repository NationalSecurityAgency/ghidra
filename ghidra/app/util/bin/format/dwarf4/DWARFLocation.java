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
package ghidra.app.util.bin.format.dwarf4;

public class DWARFLocation {
	private DWARFRange addressRange;
	private byte[] location;

	/**
	 * Create a Location given an address range and location expression.
	 * @param addressRange memory range of this location
	 * @param location byte array holding location expression
	 */
	public DWARFLocation(DWARFRange addressRange, byte[] location) {
		this.addressRange = addressRange;
		this.location = location;
	}

	public DWARFRange getRange() {
		return this.addressRange;
	}

	public byte[] getLocation() {
		return this.location;
	}

	/*
	 * I know we frown on keeping large chunks of code around that have been commented
	 * out, but...
	 * 1) this is how a core DWARF data structure is read from disk, and contains some gotchas
	 * and hard-won knowledge
	 * 2) isn't being used right now due to changes in the analyzer and how it uses addr data.
	 * 3) might be needed in the future if the analyzer changes its ways
	 */
//	/**
//	 * Return a list of DWARF locations read from the debug_loc section.
//	 * @param offset offset into the debug_loc section
//	 * @param die the DIE that pointed to this debug_loc location list
//	 * @return list of DWARF locations (address range and location expression)
//	 * @throws IOException if an I/O error occurs
//	 */
//	public static List<DWARFLocation> parseLocationList(long offset, DebugInfoEntry die)
//			throws IOException {
//		DWARFProgram prog = die.getCompilationUnit().getProgram();
//		BinaryReader debug_loc = prog.getDebugLocation();
//
//		List<DWARFLocation> ranges = new ArrayList<>();
//		if (debug_loc == null) {
//			return ranges;
//		}
//
//		debug_loc.setPointerIndex(offset);
//		byte pointerSize = die.getCompilationUnit().getPointerSize();
//
//		Number baseAddress = die.getCompilationUnit().getCompileUnit().getLowPC();
//		long baseAddressOffset = (baseAddress != null) ? baseAddress.longValue() : 0;
//
//		Number cuLowPC = die.getCompilationUnit().getCompileUnit().getLowPC();
//		long cuBase = (cuLowPC != null) ? cuLowPC.longValue() : Long.MAX_VALUE;
//
//		// Loop through the debug_loc entry
//		while (debug_loc.getPointerIndex() < debug_loc.length()) {
//			Number beginning = DWARFUtil.readAddress(debug_loc, pointerSize);
//			Number ending = DWARFUtil.readAddress(debug_loc, pointerSize);	// dwarf end addrs are exclusive
//
//			// List end
//			if (beginning.longValue() == 0 && ending.longValue() == 0) {
//				break;
//			}
//
//			// Check to see if this is a base address entry
//			if (NumberUtil.equalsMaxUnsignedValue(beginning)) {
//				baseAddressOffset = ending.longValue();
//				continue;
//			}
//
//			// Size is 2 bytes
//			int size = debug_loc.readNextUnsignedShort();
//
//			// Read the location description
//			byte[] location = debug_loc.readNextByteArray(size);
//
//			// Test to see if the 'offset' read from the debug_loc data is already
//			// greater-than the compunit's lowpc.  This indicates the 'offset' isn't
//			// an offset, but already an absolute value.  This occurs in some
//			// gcc dwarf compilation flag combinations.
//			boolean isBadOffset = (beginning.longValue() > cuBase);
//
//			long absStart = beginning.longValue();
//			long absEnd = ending.longValue();
//			if (!isBadOffset) {
//				absStart += baseAddressOffset;
//				absEnd += baseAddressOffset;
//			}
//
//			ranges.add(new DWARFLocation(new DWARFRange(absStart, absEnd), location));
//		}
//		return ranges;
//	}
}
