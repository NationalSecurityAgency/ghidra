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

public final class NListConstants {
	/*
	 * The n_type field really contains four fields:
	 *	unsigned char N_STAB:3,
	 *                N_PEXT:1,
	 *                N_TYPE:3,
	 *                N_EXT:1;
	 * which are used via the following masks.
	 */

	/**if any of these bits set, a symbolic debugging entry*/
	public final static int MASK_N_STAB = 0xe0;
	/**private external symbol bit*/
	public final static int MASK_N_PEXT = 0x10;
	/**mask for the type bits*/
	public final static int MASK_N_TYPE = 0x0e;
	/**external symbol bit, set for external symbols*/
	public final static int MASK_N_EXT  = 0x01;

	/*
	 * Values for N_TYPE bits of the n_type field.
	 */

	/**undefined, n_sect == NO_SECT */
	public final static byte TYPE_N_UNDF = 0x0;
	/**absolute, n_sect == NO_SECT */
	public final static byte TYPE_N_ABS  = 0x2;
	/**indirect*/
	public final static byte TYPE_N_INDR = 0xa;
	/**prebound undefined (defined in a dylib)*/
	public final static byte TYPE_N_PBUD = 0xc;
	/**defined in section number n_sect */
	public final static byte TYPE_N_SECT = 0xe;

	/**
	 * Reference type bits of the n_desc field of undefined symbols
	 */
	public final static int REFERENCE_TYPE                            = 0x7;

	public final static int REFERENCE_FLAG_UNDEFINED_NON_LAZY         = 0x0;
	public final static int REFERENCE_FLAG_UNDEFINED_LAZY             = 0x1;
	public final static int REFERENCE_FLAG_DEFINED                    = 0x2;
	public final static int REFERENCE_FLAG_PRIVATE_DEFINED            = 0x3;
	public final static int REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY = 0x4;
	public final static int REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY     = 0x5;

	public final static int REFERENCED_DYNAMICALLY = 0x0010;

	/** symbol is not in any section */
	public final static byte NO_SECT = 0;

	public final static short DESC_N_NO_DEAD_STRIP = 0x0020;/* symbol is not to be dead stripped */
	public final static short DESC_N_DESC_DISCARDED = 0x0020;/* symbol is discarded */
	public final static short DESC_N_WEAK_REF = 0x0040;/* symbol is weak referenced */
	public final static short DESC_N_WEAK_DEF = 0x0080;/* coalesed symbol is a weak definition */
	public final static short DESC_N_REF_TO_WEAK = 0x0080;/* reference to a weak symbol */
	public final static short DESC_N_ARM_THUMB_DEF = 0x0008;

	//
	// Symbolic debugger symbols
	//

	/** global symbol: name,,NO_SECT,type,0 */
	public final static byte DEBUG_N_GSYM    = (byte)0x20;
	/** procedure name (f77 kludge): name,,NO_SECT,0,0 */
	public final static byte DEBUG_N_FNAME   = (byte)0x22;
	/** procedure: name,,n_sect,linenumber,address */
	public final static byte DEBUG_N_FUN     = (byte)0x24;
	/** static symbol: name,,n_sect,type,address */
	public final static byte DEBUG_N_STSYM   = (byte)0x26;
	/** .lcomm symbol: name,,n_sect,type,address */
	public final static byte DEBUG_N_LCSYM   = (byte)0x28;
	/** begin nsect sym: 0,,n_sect,0,address */
	public final static byte DEBUG_N_BNSYM   = (byte)0x2e;
	/** emitted with gcc2_compiled and in gcc source */
	public final static byte DEBUG_N_OPT     = (byte)0x3c;
	/** register sym: name,,NO_SECT,type,register */
	public final static byte DEBUG_N_RSYM    = (byte)0x40;
	/** src line: 0,,n_sect,linenumber,address */
	public final static byte DEBUG_N_SLINE   = (byte)0x44;
	/** end nsect sym: 0,,n_sect,0,address */
	public final static byte DEBUG_N_ENSYM   = (byte)0x4e;
	/** structure elt: name,,NO_SECT,type,struct_offset */
	public final static byte DEBUG_N_SSYM    = (byte)0x60;
	/** source file name: name,,n_sect,0,address */
	public final static byte DEBUG_N_SO      = (byte)0x64;
	/** object file name: name,,0,0,st_mtime */
	public final static byte DEBUG_N_OSO     = (byte)0x66;
	/** local sym: name,,NO_SECT,type,offset */
	public final static byte DEBUG_N_LSYM    = (byte)0x80;
	/** include file beginning: name,,NO_SECT,0,sum */
	public final static byte DEBUG_N_BINCL   = (byte)0x82;
	/** #included file name: name,,n_sect,0,address */
	public final static byte DEBUG_N_SOL     = (byte)0x84;
	/** compiler parameters: name,,NO_SECT,0,0 */
	public final static byte DEBUG_N_PARAMS  = (byte)0x86;
	/** compiler version: name,,NO_SECT,0,0 */
	public final static byte DEBUG_N_VERSION = (byte)0x88;
	/** compiler -O level: name,,NO_SECT,0,0 */
	public final static byte DEBUG_N_OLEVEL  = (byte)0x8A;
	/** parameter: name,,NO_SECT,type,offset */
	public final static byte DEBUG_N_PSYM    = (byte)0xa0;
	/** include file end: name,,NO_SECT,0,0 */
	public final static byte DEBUG_N_EINCL   = (byte)0xa2;
	/** alternate entry: name,,n_sect,linenumber,address */
	public final static byte DEBUG_N_ENTRY   = (byte)0xa4;
	/** left bracket: 0,,NO_SECT,nesting level,address */
	public final static byte DEBUG_N_LBRAC   = (byte)0xc0;
	/** deleted include file: name,,NO_SECT,0,sum */
	public final static byte DEBUG_N_EXCL    = (byte)0xc2;
	/** right bracket: 0,,NO_SECT,nesting level,address */
	public final static byte DEBUG_N_RBRAC   = (byte)0xe0;
	/** begin common: name,,NO_SECT,0,0 */
	public final static byte DEBUG_N_BCOMM   = (byte)0xe2;
	/** end common: name,,n_sect,0,0 */
	public final static byte DEBUG_N_ECOMM   = (byte)0xe4;
	/** end common (local name): 0,,n_sect,0,address */
	public final static byte DEBUG_N_ECOML   = (byte)0xe8;
	/** second stab entry with length information */
	public final static byte DEBUG_N_LENG    = (byte)0xfe;

	public final static byte   SELF_LIBRARY_ORDINAL  =  (byte)0x00;
	public final static byte    MAX_LIBRARY_ORDINAL  =  (byte)0xfd;
	public final static byte DYNAMIC_LOOKUP_ORDINAL  =  (byte)0xfe;
	public final static byte     EXECUTABLE_ORDINAL  =  (byte)0xff;
}
