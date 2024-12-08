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
package ghidra.app.util.bin.format.dwarf.line;

import ghidra.app.util.bin.format.dwarf.DWARFUtil;

public class DWARFLineNumberExtendedOpcodes {
	public final static int DW_LNE_end_sequence = 1;
	public final static int DW_LNE_set_address = 2;
	public final static int DW_LNE_define_file = 3;	// v2-v4, v5=reserved
	public final static int DW_LNE_set_discriminator = 4;

	public final static int DW_LNE_lo_user = 0x80;
	public final static int DW_LNE_hi_user = 0xff;

	public static String toString(int value) {
		return DWARFUtil.toString(DWARFLineNumberExtendedOpcodes.class, value);
	}

}
