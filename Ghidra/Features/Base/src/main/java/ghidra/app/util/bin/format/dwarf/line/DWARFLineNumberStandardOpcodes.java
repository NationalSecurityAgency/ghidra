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

public class DWARFLineNumberStandardOpcodes {
	public final static int DW_LNS_copy = 1;
	public final static int DW_LNS_advance_pc = 2;
	public final static int DW_LNS_advance_line = 3;
	public final static int DW_LNS_set_file = 4;
	public final static int DW_LNS_set_column = 5;
	public final static int DW_LNS_negate_statement = 6;
	public final static int DW_LNS_set_basic_block = 7;
	public final static int DW_LNS_const_add_pc = 8;
	public final static int DW_LNS_fixed_advanced_pc = 9;
	public final static int DW_LNS_set_prologue_end = 10;
	public final static int DW_LNS_set_epilog_begin = 11;
	public final static int DW_LNS_set_isa = 12;

	public static String toString(int value) {
		return DWARFUtil.toString(DWARFLineNumberStandardOpcodes.class, value);
	}
}
