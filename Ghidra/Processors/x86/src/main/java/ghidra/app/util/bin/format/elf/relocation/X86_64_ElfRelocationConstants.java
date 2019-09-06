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
package ghidra.app.util.bin.format.elf.relocation;

public class X86_64_ElfRelocationConstants {

	public static final int R_X86_64_NONE = 0; /* No reloc */
	/** S + A */
	public static final int R_X86_64_64 = 1; /* Direct 64 bit */
	/** S + A - P */
	public static final int R_X86_64_PC32 = 2; /* PC relative 32 bit signed */
	/** G + P */
	public static final int R_X86_64_GOT32 = 3; /* 32 bit GOT entry */
	/** L + A - P */
	public static final int R_X86_64_PLT32 = 4; /* 32 bit PLT address */
	/** ? */
	public static final int R_X86_64_COPY = 5; /* Copy symbol at runtime */
	/** S */
	public static final int R_X86_64_GLOB_DAT = 6; /* Create GOT entry */
	/** S */
	public static final int R_X86_64_JUMP_SLOT = 7; /* Create PLT entry */
	/** B + A */
	public static final int R_X86_64_RELATIVE = 8; /* Adjust by program base */
	/** G + GOT + A - P */
	public static final int R_X86_64_GOTPCREL = 9; /*
													 * 32 bit signed pc relative
													 * offset to GOT
													 */
	/** S + A */
	public static final int R_X86_64_32 = 10; /* Direct 32 bit zero extended */
	/** S + A */
	public static final int R_X86_64_32S = 11; /* Direct 32 bit sign extended */
	/** S + A */
	public static final int R_X86_64_16 = 12; /* Direct 16 bit zero extended */
	/** S + A - P */
	public static final int R_X86_64_PC16 = 13; /*
												 * 16 bit sign extended pc
												 * relative
												 */
	/** S + A */
	public static final int R_X86_64_8 = 14; /* Direct 8 bit sign extended */
	/** S + A - P */
	public static final int R_X86_64_PC8 = 15; /*
												 * 8 bit sign extended pc
												 * relative
												 */
	/**
	 * Calculates the object identifier of the 
	 * object containing the TLS symbol. 
	 */
	public static final int R_X86_64_DTPMOD64 = 16; // ID of module containing symbol
	/**
	 * Calculates the offset of the variable relative
	 * to the start of the TLS block that contains the 
	 * variable.  The computed value is used as an
	 * immediate value of an addend and is not associated
	 * with a specific register. 
	 * 
	 */
	public static final int R_X86_64_DTPOFF64 = 17; // Offset in module's TLS block 
	public static final int R_X86_64_TPOFF64 = 18; // offset in the initial TLS block
	public static final int R_X86_64_TLSGD = 19; // 32 bit signed PC relative offset to 
													// two GOT entries for GD symbol
	public static final int R_X86_64_TLSLD = 20; // 32 bit signed PC relative offset to 
													// two GOT entries for LD symbol 
	public static final int R_X86_64_DTPOFF32 = 21; // offset in TLS block
	public static final int R_X86_64_GOTTPOFF = 22; // 32 bit signed pc relative offst to
													// GOT entry for IE symbol
	public static final int R_X86_64_TPOFF32 = 23; // offset in initial TLS block

	/** S + A - P */
	public static final int R_X86_64_PC64 = 24; // PC relative 64 bit

	/** S + A - GOT */
	public static final int R_X86_64_GOTOFF64 = 25; // 64 bit offset to GOT
	/** GOT + A + P */
	public static final int R_X86_64_GOTPC32 = 26; // 32 bit signed pc relative offset to GOT
	public static final int R_X86_64_GOT64 = 27; // 64 bit GOT entry offset
	public static final int R_X86_64_GOTPCREL64 = 28; // 64 bit pc relative offset to GOT entry
	public static final int R_X86_64_GOTPC64 = 29; // 64 bit pc relative offset to GOT
	public static final int R_X86_64_GOTPLT64 = 30; // 
	public static final int R_X86_64_PLTOFF64 = 31; // 64 bit GOT relative offset to PLT entry
	/** Z + A */
	public static final int R_X86_64_SIZE32 = 32; // Size of symbol plus 32 bit addend
	/** Z + A */
	public static final int R_X86_64_SIZE64 = 33; // Size of symbol plus 64 bit addend
	public static final int R_X86_64_GOTPC32_TLSDESC = 34; // GOT offset for TLS descriptor
	public static final int R_X86_64_TLSDESC_CALL = 35; // Marker for call through TLS descriptor
	public static final int R_X86_64_TLSDESC = 36; // TLS descriptor; word64  * 2
	public static final int R_X86_64_IRELATIVE = 37; // Adjust indirectly by program base
	public static final int R_X86_64_RELATIVE64 = 38; // 64-bit adjust by program base
	
	public static final int  R_X86_64_PC32_BND  = 39; // deprecated
	public static final int  R_X86_64_PLT32_BND  = 40; // deprecated
	public static final int  R_X86_64_GOTPCRELX  = 41;  // G + GOT + A - P
    public static final int  R_X86_64_REX_GOTPCRELX  = 42; //G + GOT + A - P
	
	public static final int R_X86_64_NUM = 43;
	
	public static final int R_X86_64_GNU_VTINHERIT = 250;
	public static final int R_X86_64_GNU_VTENTRY = 251;

	private X86_64_ElfRelocationConstants() {
		// no construct
	}
}
