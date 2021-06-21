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
package ghidra.app.util.bin.format.elf;

public class ElfSectionHeaderConstants {

	private ElfSectionHeaderConstants() {
	}

	/**RESERVED SECTION NAME*/
	public static final String dot_bss = ".bss";
	/**RESERVED SECTION NAME*/
	public static final String dot_comment = ".comment";
	/**RESERVED SECTION NAME*/
	public static final String dot_data = ".data";
	/**RESERVED SECTION NAME*/
	public static final String dot_data1 = ".data1";
	/**RESERVED SECTION NAME*/
	public static final String dot_debug = ".debug";
	/**RESERVED SECTION NAME*/
	public static final String dot_dynamic = ".dynamic";
	/**RESERVED SECTION NAME*/
	public static final String dot_dynstr = ".dynstr";
	/**RESERVED SECTION NAME*/
	public static final String dot_dynsym = ".dynsym";
	/**RESERVED SECTION NAME*/
	public static final String dot_fini = ".fini";
	/**RESERVED SECTION NAME*/
	public static final String dot_got = ".got";
	/**RESERVED SECTION NAME*/
	public static final String dot_hash = ".hash";
	/**RESERVED SECTION NAME*/
	public static final String dot_init = ".init";
	/**RESERVED SECTION NAME*/
	public static final String dot_interp = ".interp";
	/**RESERVED SECTION NAME*/
	public static final String dot_line = ".line";
	/**RESERVED SECTION NAME*/
	public static final String dot_note = ".note";
	/**RESERVED SECTION NAME*/
	public static final String dot_plt = ".plt";
	/**RESERVED SECTION NAME*/
	public static final String dot_rodata = ".rodata";
	/**RESERVED SECTION NAME*/
	public static final String dot_rodata1 = ".rodata1";
	/**RESERVED SECTION NAME*/
	public static final String dot_shstrtab = ".shstrtab";
	/**RESERVED SECTION NAME*/
	public static final String dot_strtab = ".strtab";
	/**RESERVED SECTION NAME*/
	public static final String dot_symtab = ".symtab";
	/**RESERVED SECTION NAME*/
	public static final String dot_text = ".text";

	/**RESERVED SECTION NAME*/
	public static final String dot_tbss = ".tbss";
	/**RESERVED SECTION NAME*/
	public static final String dot_tdata = ".tdata";
	/**RESERVED SECTION NAME*/
	public static final String dot_tdata1 = ".tdata1";

	// Section Header Types 

	/**Inactive section header*/
	public static final int SHT_NULL = 0;
	/**Program defined*/
	public static final int SHT_PROGBITS = 1;
	/**Symbol table for link editing and dynamic linking*/
	public static final int SHT_SYMTAB = 2;
	/**String table*/
	public static final int SHT_STRTAB = 3;
	/**Relocation entries with explicit addends*/
	public static final int SHT_RELA = 4;
	/**Symbol hash table for dynamic linking*/
	public static final int SHT_HASH = 5;
	/**Dynamic linking information*/
	public static final int SHT_DYNAMIC = 6;
	/**Section holds information that marks the file*/
	public static final int SHT_NOTE = 7;
	/**Section contains no bytes*/
	public static final int SHT_NOBITS = 8;
	/**Relocation entries w/o explicit addends*/
	public static final int SHT_REL = 9;
	/**Undefined*/
	public static final int SHT_SHLIB = 10;
	/**Symbol table for dynamic linking*/
	public static final int SHT_DYNSYM = 11;
	/**Array of constructors*/
	public static final int SHT_INIT_ARRAY = 14;
	/**Array of destructors*/
	public static final int SHT_FINI_ARRAY = 15;
	/**Array of pre-constructors*/
	public static final int SHT_PREINIT_ARRAY = 16;
	/**Section group*/
	public static final int SHT_GROUP = 17;
	/**Extended section indeces*/
	public static final int SHT_SYMTAB_SHNDX = 18;
	/**Experimental support - see proposal at https://groups.google.com/forum/#!topic/generic-abi/bX460iggiKg */
	public static final int SHT_RELR = 19;

	// OS Specific Section Types

	/**Android relocation entries w/o explicit addends*/
	public static final int SHT_ANDROID_REL = 0x60000001;
	/**Android relocation entries with explicit addends*/
	public static final int SHT_ANDROID_RELA = 0x60000002;

	/**Android's experimental support for SHT_RELR sections (see above) */
	public static final int SHT_ANDROID_RELR = 0x6fffff00;

	/**Object attributes */
	public static final int SHT_GNU_ATTRIBUTES = 0x6ffffff5;
	/**GNU-style hash table */
	public static final int SHT_GNU_HASH = 0x6ffffff6;
	/** Prelink library list **/
	public static final int SHT_GNU_LIBLIST = 0x6ffffff7;
	/** Checksum for DSO content. +*/
	public static final int SHT_CHECKSUM = 0x6ffffff8;

	public static final int SHT_SUNW_move = 0x6ffffffa;
	public static final int SHT_SUNW_COMDAT = 0x6ffffffb;
	public static final int SHT_SUNW_syminfo = 0x6ffffffc;
	/**Version definition section.*/
	public static final int SHT_GNU_verdef = 0x6ffffffd;
	/**Version needs section.*/
	public static final int SHT_GNU_verneed = 0x6ffffffe;
	/**Version symbol table.*/
	public static final int SHT_GNU_versym = 0x6fffffff;

	// Section Header Flag Bits

	/**The section contains data that should be writable during process execution.*/
	public static final int SHF_WRITE = (1 << 0);
	/**The section occupies memory during execution*/
	public static final int SHF_ALLOC = (1 << 1);
	/**The section contains executable machine instructions.*/
	public static final int SHF_EXECINSTR = (1 << 2);
	/**The section might be merged*/
	public static final int SHF_MERGE = (1 << 4);
	/**The section contains null-terminated strings*/
	public static final int SHF_STRINGS = (1 << 5);
	/**sh_info contains SHT index*/
	public static final int SHF_INFO_LINK = (1 << 6);
	/**Preserve order after combining*/
	public static final int SHF_LINK_ORDER = (1 << 7);
	/**Non-standard OS specific handling required*/
	public static final int SHF_OS_NONCONFORMING = (1 << 8);
	/**The section  is member of a group.*/
	public static final int SHF_GROUP = (1 << 9);
	/**The section that holds thread-local data.*/
	public static final int SHF_TLS = (1 << 10);
	/**This section is excluded from the final executable or shared library.*/
	public static final int SHF_EXCLUDE = 0x80000000;
	/**The section contains OS-specific data.*/
	public static final int SHF_MASKOS = 0x0ff00000;
	/**Processor-specific*/
	public static final int SHF_MASKPROC = 0xf0000000;

	//  

	/**undefined, missing, irrelevant section*/
	public static final short SHN_UNDEF = (short) 0x0000;
	/**lower bound on range of reserved indexes*/
	public static final short SHN_LORESERVE = (short) 0xff00;
	/**lower bound for processor-specific semantics*/
	public static final short SHN_LOPROC = (short) 0xff00;
	/**upper bound for processor-specific semantics*/
	public static final short SHN_HIPROC = (short) 0xff1f;
	/** Lowest operating system-specific index */
	public static final short SHN_LOOS = (short) 0xff20;
	/** Highest operating system-specific index */
	public static final short SHN_HIOS = (short) 0xff3f;
	/**symbol defined relative to this are absolute, not affected by relocation*/
	public static final short SHN_ABS = (short) 0xfff1;
	/**common symbols, such as Fortran COMMON or unallocated C external vars*/
	public static final short SHN_COMMON = (short) 0xfff2;
	/** Mark that the index is &gt;= SHN_LORESERVE */
	public static final short SHN_XINDEX = (short) 0xffff;
	/**upper bound on range of reserved indexes*/
	public static final short SHN_HIRESERVE = (short) 0xffff;
	
	/**
	 * @param symbolSectionIndex symbol section index (st_shndx)
	 * @return true if specified symbol section index corresponds to a processor
	 * specific value in the range SHN_LOPROC..SHN_HIPROC, else false
	 */
	public static boolean isProcessorSpecificSymbolSectionIndex(short symbolSectionIndex) {
		return symbolSectionIndex >= ElfSectionHeaderConstants.SHN_LOPROC &&
			symbolSectionIndex <= ElfSectionHeaderConstants.SHN_HIPROC;
	}
}
