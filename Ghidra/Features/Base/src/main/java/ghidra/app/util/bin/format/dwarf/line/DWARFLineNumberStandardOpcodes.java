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
		return switch (value) {
			case DW_LNS_copy -> "DW_LNS_copy";
			case DW_LNS_advance_pc -> "DW_LNS_advance_pc";
			case DW_LNS_advance_line -> "DW_LNS_advance_line";
			case DW_LNS_set_file -> "DW_LNS_set_file";
			case DW_LNS_set_column -> "DW_LNS_set_column";
			case DW_LNS_negate_statement -> "DW_LNS_negate_statement";
			case DW_LNS_set_basic_block -> "DW_LNS_set_basic_block";
			case DW_LNS_const_add_pc -> "DW_LNS_const_add_pc";
			case DW_LNS_fixed_advanced_pc -> "DW_LNS_fixed_advanced_pc";
			case DW_LNS_set_prologue_end -> "DW_LNS_set_prologue_end";
			case DW_LNS_set_epilog_begin -> "DW_LNS_set_epilog_begin";
			case DW_LNS_set_isa -> "DW_LNS_set_isa";
			default -> "Unknown DWARF Value: 0x" + Integer.toHexString(value);
		};
	}
}
