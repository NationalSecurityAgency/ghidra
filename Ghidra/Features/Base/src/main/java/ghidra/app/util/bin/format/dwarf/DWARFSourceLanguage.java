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

/**
 * DWARF source lang consts from www.dwarfstd.org/doc/DWARF4.pdf.
 * <p>
 * TODO: The PDF also lists the default lower bound for array dw_tag_subrange_type
 * attributes based on this value.
 */
public final class DWARFSourceLanguage {
	public static final int DW_LANG_C89 = 0x1;
	public static final int DW_LANG_C = 0x2;
	public static final int DW_LANG_Ada83 = 0x3;
	public static final int DW_LANG_C_plus_plus = 0x4;
	public static final int DW_LANG_Cobol74 = 0x5;
	public static final int DW_LANG_Cobol85 = 0x6;
	public static final int DW_LANG_Fortran77 = 0x7;
	public static final int DW_LANG_Fortran90 = 0x8;
	public static final int DW_LANG_Pascal83 = 0x9;
	public static final int DW_LANG_Modula2 = 0xa;
	public static final int DW_LANG_Java = 0xb;
	public static final int DW_LANG_C99 = 0xc;
	public static final int DW_LANG_Ada95 = 0xd;
	public static final int DW_LANG_Fortran95 = 0xe;
	public static final int DW_LANG_PL1 = 0xf;
	public static final int DW_LANG_ObjC = 0x10;
	public static final int DW_LANG_ObjC_plus_plus = 0x11;
	public static final int DW_LANG_UPC = 0x12;
	public static final int DW_LANG_D = 0x13;
	public static final int DW_LANG_Python = 0x14;
	public static final int DW_LANG_OpenCL = 0x15;
	public static final int DW_LANG_Go = 0x16;
	public static final int DW_LANG_Modula3 = 0x17;
	public static final int DW_LANG_Haskell = 0x18;
	public static final int DW_LANG_C_plus_plus_03 = 0x19;
	public static final int DW_LANG_C_plus_plus_11 = 0x1a;
	public static final int DW_LANG_OCaml = 0x1b;
	public static final int DW_LANG_Rust = 0x1c;
	public static final int DW_LANG_C11 = 0x1d;
	public static final int DW_LANG_Swift = 0x1e;
	public static final int DW_LANG_Julia = 0x1f;
	public static final int DW_LANG_Dylan = 0x20;
	public static final int DW_LANG_C_plus_plus_14 = 0x21;
	public static final int DW_LANG_Fortran03 = 0x22;
	public static final int DW_LANG_Fortran08 = 0x23;
	public static final int DW_LANG_RenderScript = 0x24;
	public static final int DW_LANG_BLISS = 0x25;
	
	public static final int DW_LANG_lo_user = 0x8000;
	public static final int DW_LANG_hi_user = 0xffff;

	public static final int DW_LANG_Mips_Assembler = 0x8001;
	public static final int DW_LANG_GOOGLE_RenderScript = 0x8e57;
	public static final int DW_LANG_SUN_Assembler = 0x9001;
	public static final int DW_LANG_ALTIUM_Assembler = 0x9101;
	public static final int DW_LANG_BORLAND_Delphi = 0xb000;
}
