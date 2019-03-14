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
 * DWARF attribute encoding consts from www.dwarfstd.org/doc/DWARF4.pdf
 */
public final class DWARFEncoding
{
	public static final int DW_ATE_void = 0x0;
	public static final int DW_ATE_address = 0x1;
	public static final int DW_ATE_boolean = 0x2;
	public static final int DW_ATE_complex_float = 0x3;
	public static final int DW_ATE_float = 0x4;
	public static final int DW_ATE_signed = 0x5;
	public static final int DW_ATE_signed_char = 0x6;
	public static final int DW_ATE_unsigned = 0x7;
	public static final int DW_ATE_unsigned_char = 0x8;
	public static final int DW_ATE_imaginary_float = 0x9;
	public static final int DW_ATE_packed_decimal = 0xa;
	public static final int DW_ATE_numeric_string = 0xb;
	public static final int DW_ATE_edited = 0xc;
	public static final int DW_ATE_signed_fixed = 0xd;
	public static final int DW_ATE_unsigned_fixed = 0xe;
	public static final int DW_ATE_decimal_float = 0xf;
	public static final int DW_ATE_UTF = 0x10;
	public static final int DW_ATE_lo_user = 0x80;
	public static final int DW_ATE_hi_user = 0xff;

	public static String getTypeName(int encoding) {
		String tmp = DWARFUtil.toString(DWARFEncoding.class, encoding);
		return tmp.startsWith("DW_ATE_") ? tmp.substring(7) : "unknown_type_encoding";
	}
}
