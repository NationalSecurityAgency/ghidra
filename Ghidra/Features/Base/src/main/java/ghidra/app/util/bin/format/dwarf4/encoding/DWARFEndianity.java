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
package ghidra.app.util.bin.format.dwarf4.encoding;

import ghidra.app.util.bin.format.dwarf4.DWARFUtil;

/**
 * DWARF Endianity consts from www.dwarfstd.org/doc/DWARF4.pdf
 */
public final class DWARFEndianity {
	public static final int DW_END_default = 0x0;
	public static final int DW_END_big = 0x1;
	public static final int DW_END_little = 0x2;
	public static final int DW_END_lo_user = 0x40;
	public static final int DW_END_hi_user = 0xff;

	/**
	 * Get the endianity given a DWARFEndianity value.
	 * @param endian DWARFEndianity value to check
	 * @param defaultisBigEndian true if by default is big endian and false otherwise
	 * @return true if big endian and false if little endian
	 * @throws IllegalArgumentException if an unknown endian value is given
	 */
	public static boolean getEndianity(long endian, boolean defaultisBigEndian) {
		switch ((int) endian) {
			case DW_END_default:
				return defaultisBigEndian;
			case DW_END_big:
				return true;
			case DW_END_little:
				return false;
			default:
				throw new IllegalArgumentException(
					"Unhandled endian type: " + DWARFUtil.toString(DWARFEndianity.class, endian));
		}
	}
}
