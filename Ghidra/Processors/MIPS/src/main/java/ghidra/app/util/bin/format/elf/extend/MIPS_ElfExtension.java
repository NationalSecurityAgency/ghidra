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
package ghidra.app.util.bin.format.elf.extend;

import java.math.BigInteger;

import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.bin.format.elf.ElfDynamicType.ElfDynamicValueType;
import ghidra.app.util.bin.format.elf.relocation.MIPS_Elf64Relocation;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class MIPS_ElfExtension extends ElfExtension {
	
	private static final String MIPS_STUBS_SECTION_NAME = ".MIPS.stubs";

	// GP value reflected by symbol address
	public static final String MIPS_GP_DISP_SYMBOL_NAME = "_gp_disp"; // relocation GP marker symbol
	public static final String MIPS_GP_GNU_LOCAL_SYMBOL_NAME = "__gnu_local_gp";
	public static final String MIPS_GP_VALUE_SYMBOL = "_mips_gp_value";
	public static final String MIPS_GP0_VALUE_SYMBOL = "_mips_gp0_value";

	// Elf Program Header Extensions
	public static final ElfProgramHeaderType PT_MIPS_REGINFO = new ElfProgramHeaderType(0x70000000,
		"PT_MIPS_REGINFO", "Register usage information.  Identifies one .reginfo section");
	public static final ElfProgramHeaderType PT_MIPS_RTPROC =
		new ElfProgramHeaderType(0x70000001, "PT_MIPS_RTPROC", "Runtime procedure table");
	public static final ElfProgramHeaderType PT_MIPS_OPTIONS =
		new ElfProgramHeaderType(0x70000002, "PT_MIPS_OPTIONS", ".MIPS.options section");
	public static final ElfProgramHeaderType PT_MIPS_ABIFLAGS =
		new ElfProgramHeaderType(0x70000003, "PT_MIPS_ABIFLAGS", "Records ABI related flags");

	// Elf Section Header Extensions
	public static final ElfSectionHeaderType SHT_MIPS_LIBLIST =
		new ElfSectionHeaderType(0x70000000, "SHT_MIPS_LIBLIST",
			"Section contains the set of dynamic shared objects used when statically linking");
	public static final ElfSectionHeaderType SHT_MIPS_MSYM =
		new ElfSectionHeaderType(0x70000001, "SHT_MIPS_MSYM", "");
	public static final ElfSectionHeaderType SHT_MIPS_CONFLICT = new ElfSectionHeaderType(
		0x70000002, "SHT_MIPS_CONFLICT",
		"Section contains list of symbols whose definitions conflict with symbols defined in shared objects");
	public static final ElfSectionHeaderType SHT_MIPS_GPTAB = new ElfSectionHeaderType(0x70000003,
		"SHT_MIPS_GPTAB", "Section contains the global pointer table");
	public static final ElfSectionHeaderType SHT_MIPS_UCODE = new ElfSectionHeaderType(0x70000004,
		"SHT_MIPS_UCODE", "Section contains microcode information");
	public static final ElfSectionHeaderType SHT_MIPS_DEBUG = new ElfSectionHeaderType(0x70000005,
		"SHT_MIPS_DEBUG", "Section contains some sort of debugging information");
	public static final ElfSectionHeaderType SHT_MIPS_REGINFO = new ElfSectionHeaderType(0x70000006,
		"SHT_MIPS_REGINFO", "Section contains register usage information");
	public static final ElfSectionHeaderType SHT_MIPS_PACKAGE =
		new ElfSectionHeaderType(0x70000007, "SHT_MIPS_PACKAGE", "");
	public static final ElfSectionHeaderType SHT_MIPS_PACKSYM =
		new ElfSectionHeaderType(0x70000008, "SHT_MIPS_PACKSYM", "");
	public static final ElfSectionHeaderType SHT_MIPS_RELD =
		new ElfSectionHeaderType(0x70000009, "SHT_MIPS_RELD", "");

	public static final ElfSectionHeaderType SHT_MIPS_IFACE =
		new ElfSectionHeaderType(0x7000000b, "", "Section contains interface information");
	public static final ElfSectionHeaderType SHT_MIPS_CONTENT = new ElfSectionHeaderType(0x7000000c,
		"SHT_MIPS_CONTENT", "Section contains description of contents of another section");
	public static final ElfSectionHeaderType SHT_MIPS_OPTIONS = new ElfSectionHeaderType(0x7000000d,
		"SHT_MIPS_OPTIONS", "Section contains miscellaneous options");

	public static final ElfSectionHeaderType SHT_MIPS_SHDR =
		new ElfSectionHeaderType(0x70000010, "SHT_MIPS_SHDR", "");
	public static final ElfSectionHeaderType SHT_MIPS_FDESC =
		new ElfSectionHeaderType(0x70000011, "SHT_MIPS_FDESC", "");
	public static final ElfSectionHeaderType SHT_MIPS_EXTSYM =
		new ElfSectionHeaderType(0x70000012, "SHT_MIPS_EXTSYM", "");
	public static final ElfSectionHeaderType SHT_MIPS_DENSE =
		new ElfSectionHeaderType(0x70000013, "SHT_MIPS_DENSE", "");
	public static final ElfSectionHeaderType SHT_MIPS_PDESC =
		new ElfSectionHeaderType(0x70000014, "SHT_MIPS_PDESC", "");
	public static final ElfSectionHeaderType SHT_MIPS_LOCSYM =
		new ElfSectionHeaderType(0x70000015, "SHT_MIPS_LOCSYM", "");
	public static final ElfSectionHeaderType SHT_MIPS_AUXSYM =
		new ElfSectionHeaderType(0x70000016, "SHT_MIPS_AUXSYM", "");
	public static final ElfSectionHeaderType SHT_MIPS_OPTSYM =
		new ElfSectionHeaderType(0x70000017, "SHT_MIPS_OPTSYM", "");
	public static final ElfSectionHeaderType SHT_MIPS_LOCSTR =
		new ElfSectionHeaderType(0x70000018, "SHT_MIPS_LOCSTR", "");
	public static final ElfSectionHeaderType SHT_MIPS_LINE =
		new ElfSectionHeaderType(0x70000019, "SHT_MIPS_LINE", "");
	public static final ElfSectionHeaderType SHT_MIPS_RFDESC =
		new ElfSectionHeaderType(0x7000001a, "SHT_MIPS_RFDESC", "");
	public static final ElfSectionHeaderType SHT_MIPS_DELTASYM =
		new ElfSectionHeaderType(0x7000001b, "SHT_MIPS_DELTASYM", "Delta C++: symbol table");
	public static final ElfSectionHeaderType SHT_MIPS_DELTAINST =
		new ElfSectionHeaderType(0x7000001c, "SHT_MIPS_DELTAINST", "Delta C++: instance table");
	public static final ElfSectionHeaderType SHT_MIPS_DELTACLASS =
		new ElfSectionHeaderType(0x7000001d, "SHT_MIPS_DELTACLASS", "Delta C++: class table");
	public static final ElfSectionHeaderType SHT_MIPS_DWARF =
		new ElfSectionHeaderType(0x7000001e, "SHT_MIPS_DWARF", "DWARF debugging section");
	public static final ElfSectionHeaderType SHT_MIPS_DELTADECL =
		new ElfSectionHeaderType(0x7000001f, "SHT_MIPS_DELTADECL", "Delta C++: declarations");
	public static final ElfSectionHeaderType SHT_MIPS_SYMBOL_LIB =
		new ElfSectionHeaderType(0x70000020, "SHT_MIPS_SYMBOL_LIB",
			"List of libraries the binary depends on.  Includes a time stamp, version number");
	public static final ElfSectionHeaderType SHT_MIPS_EVENTS =
		new ElfSectionHeaderType(0x70000021, "SHT_MIPS_EVENTS", "Events section");
	public static final ElfSectionHeaderType SHT_MIPS_TRANSLATE =
		new ElfSectionHeaderType(0x70000022, "SHT_MIPS_TRANSLATE", "");
	public static final ElfSectionHeaderType SHT_MIPS_PIXIE =
		new ElfSectionHeaderType(0x70000023, "SHT_MIPS_PIXIE", "Special pixie sections");
	public static final ElfSectionHeaderType SHT_MIPS_XLATE = new ElfSectionHeaderType(0x70000024,
		"SHT_MIPS_XLATE", "Address translation table (for debug info)");
	public static final ElfSectionHeaderType SHT_MIPS_XLATE_DEBUG =
		new ElfSectionHeaderType(0x70000025, "SHT_MIPS_XLATE_DEBUG",
			"SGI internal address translation table (for debug info)");
	public static final ElfSectionHeaderType SHT_MIPS_WHIRL =
		new ElfSectionHeaderType(0x70000026, "SHT_MIPS_WHIRL", "Intermediate code");
	public static final ElfSectionHeaderType SHT_MIPS_EH_REGION = new ElfSectionHeaderType(
		0x70000027, "SHT_MIPS_EH_REGION", "C++ exception handling region info");
	public static final ElfSectionHeaderType SHT_MIPS_XLATE_OLD = new ElfSectionHeaderType(
		0x70000028, "SHT_MIPS_XLATE_OLD", "Obsolete address translation table (for debug info)");
	public static final ElfSectionHeaderType SHT_MIPS_PDR_EXCEPTION =
		new ElfSectionHeaderType(0x70000029, "SHT_MIPS_PDR_EXCEPTION",
			"Runtime procedure descriptor table exception information");
	public static final ElfSectionHeaderType SHT_MIPS_ABIFLAGS =
		new ElfSectionHeaderType(0x7000002a, "SHT_MIPS_ABIFLAGS", "ABI related flags section");

	// Elf Dynamic Type Extensions
	public static final ElfDynamicType DT_MIPS_RLD_VERSION =
		new ElfDynamicType(0x70000001, "DT_MIPS_RLD_VERSION",
			"32 bit version number for runtime linker interface", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_MIPS_TIME_STAMP = new ElfDynamicType(0x70000002,
		"DT_MIPS_TIME_STAMP", "Time stamp", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_MIPS_ICHECKSUM =
		new ElfDynamicType(0x70000003, "DT_MIPS_ICHECKSUM",
			"Checksum of external strings and common sizes", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_MIPS_IVERSION = new ElfDynamicType(0x70000004,
		"DT_MIPS_IVERSION", "Index of version string in string table", ElfDynamicValueType.STRING);
	public static final ElfDynamicType DT_MIPS_FLAGS = new ElfDynamicType(0x70000005,
		"DT_MIPS_FLAGS", "32 bits of flags", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_MIPS_BASE_ADDRESS = new ElfDynamicType(0x70000006,
		"DT_MIPS_BASE_ADDRESS", "Base address of the segment", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_MIPS_MSYM =
		new ElfDynamicType(0x70000007, "DT_MIPS_MSYM", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_MIPS_CONFLICT = new ElfDynamicType(0x70000008,
		"DT_MIPS_CONFLICT", "Address of .conflict section", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_MIPS_LIBLIST = new ElfDynamicType(0x70000009,
		"DT_MIPS_LIBLIST", "Address of .liblist section", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_MIPS_LOCAL_GOTNO =
		new ElfDynamicType(0x7000000a, "DT_MIPS_LOCAL_GOTNO",
			"Number of local global offset table entries", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_MIPS_CONFLICTNO =
		new ElfDynamicType(0x7000000b, "DT_MIPS_CONFLICTNO",
			"Number of entries in the .conflict section", ElfDynamicValueType.VALUE);
	// 0x7000000c-0x7000000f
	public static final ElfDynamicType DT_MIPS_LIBLISTNO =
		new ElfDynamicType(0x70000010, "DT_MIPS_LIBLISTNO",
			"Number of entries in the .liblist section", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_MIPS_SYMTABNO = new ElfDynamicType(0x70000011,
		"DT_MIPS_SYMTABNO", "Number of entries in the .dynsym section", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_MIPS_UNREFEXTNO = new ElfDynamicType(0x70000012,
		"DT_MIPS_UNREFEXTNO", "Index of first external dynamic symbol not referenced locally",
		ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_MIPS_GOTSYM =
		new ElfDynamicType(0x70000013, "DT_MIPS_GOTSYM",
			"Index of first dynamic symbol in global offset table", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_MIPS_HIPAGENO =
		new ElfDynamicType(0x70000014, "DT_MIPS_HIPAGENO",
			"Number of page table entries in global offset table", ElfDynamicValueType.VALUE);
	// 0x70000015
	public static final ElfDynamicType DT_MIPS_RLD_MAP =
		new ElfDynamicType(0x70000016, "DT_MIPS_RLD_MAP",
			"Address of run time loader map, used for debugging", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_MIPS_DELTA_CLASS = new ElfDynamicType(0x70000017,
		"DT_MIPS_DELTA_CLASS", "Delta C++ class definition", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_MIPS_DELTA_CLASS_NO =
		new ElfDynamicType(0x70000018, "DT_MIPS_DELTA_CLASS_NO",
			"Number of entries in DT_MIPS_DELTA_CLASS", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_MIPS_DELTA_INSTANCE = new ElfDynamicType(0x70000019,
		"DT_MIPS_DELTA_INSTANCE", "Delta C++ class instances", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_MIPS_DELTA_INSTANCE_NO =
		new ElfDynamicType(0x7000001a, "DT_MIPS_DELTA_INSTANCE_NO",
			"Number of entries in DT_MIPS_DELTA_INSTANCE", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_MIPS_DELTA_RELOC = new ElfDynamicType(0x7000001b,
		"DT_MIPS_DELTA_RELOC", "Delta relocations", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_MIPS_DELTA_RELOC_NO =
		new ElfDynamicType(0x7000001c, "DT_MIPS_DELTA_RELOC_NO",
			"Number of entries in DT_MIPS_DELTA_RELOC", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_MIPS_DELTA_SYM =
		new ElfDynamicType(0x7000001d, "DT_MIPS_DELTA_SYM",
			"Delta symbols that Delta relocations refer to", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_MIPS_DELTA_SYM_NO =
		new ElfDynamicType(0x7000001e, "DT_MIPS_DELTA_SYM_NO",
			"Number of entries in DT_MIPS_DELTA_SYM", ElfDynamicValueType.VALUE);
	// 0x7000001f
	public static final ElfDynamicType DT_MIPS_DELTA_CLASSSYM =
		new ElfDynamicType(0x70000020, "DT_MIPS_DELTA_CLASSSYM",
			"Delta symbols that hold class declarations", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_MIPS_DELTA_CLASSSYM_NO =
		new ElfDynamicType(0x70000021, "DT_MIPS_DELTA_CLASSSYM_NO",
			"Number of entries in DT_MIPS_DELTA_CLASSSYM", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_MIPS_CXX_FLAGS =
		new ElfDynamicType(0x70000022, "DT_MIPS_CXX_FLAGS",
			"Flags indicating information about C++ flavor", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_MIPS_PIXIE_INIT = new ElfDynamicType(0x70000023,
		"DT_MIPS_PIXIE_INIT", "Pixie information", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_MIPS_SYMBOL_LIB = new ElfDynamicType(0x70000024,
		"DT_MIPS_SYMBOL_LIB", "Address of .MIPS.symlib", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_MIPS_LOCALPAGE_GOTIDX =
		new ElfDynamicType(0x70000025, "DT_MIPS_LOCALPAGE_GOTIDX",
			"The GOT index of the first PTE for a segment", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_MIPS_LOCAL_GOTIDX =
		new ElfDynamicType(0x70000026, "DT_MIPS_LOCAL_GOTIDX",
			"GOT index of the first PTE for a local symbol", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_MIPS_HIDDEN_GOTIDX =
		new ElfDynamicType(0x70000027, "DT_MIPS_HIDDEN_GOTIDX",
			"The GOT index of the first PTE for a hidden symbol", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_MIPS_PROTECTED_GOTIDX =
		new ElfDynamicType(0x70000028, "DT_MIPS_PROTECTED_GOTIDX",
			"The GOT index of the first PTE for a protected symbol", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_MIPS_OPTIONS = new ElfDynamicType(0x70000029,
		"DT_MIPS_OPTIONS", "Address of `.MIPS.options'", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_MIPS_INTERFACE = new ElfDynamicType(0x7000002a,
		"DT_MIPS_INTERFACE", "Address of `.interface'", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_MIPS_DYNSTR_ALIGN =
		new ElfDynamicType(0x7000002b, "DT_MIPS_DYNSTR_ALIGN", "", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_MIPS_INTERFACE_SIZE = new ElfDynamicType(0x7000002c,
		"DT_MIPS_INTERFACE_SIZE", "Size of the .interface section", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_MIPS_RLD_TEXT_RESOLVE_ADDR =
		new ElfDynamicType(0x7000002d, "DT_MIPS_RLD_TEXT_RESOLVE_ADDR",
			"Size of rld_text_resolve function stored in the GOT", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_MIPS_PERF_SUFFIX = new ElfDynamicType(0x7000002e,
		"DT_MIPS_PERF_SUFFIX", "Default suffix of DSO to be added by rld on dlopen() calls",
		ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_MIPS_COMPACT_SIZE =
		new ElfDynamicType(0x7000002f, "DT_MIPS_COMPACT_SIZE",
			"Size of compact relocation section (O32)", ElfDynamicValueType.VALUE);
	public static final ElfDynamicType DT_MIPS_GP_VALUE = new ElfDynamicType(0x70000030,
		"DT_MIPS_GP_VALUE", "GP value for auxiliary GOTs", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_MIPS_AUX_DYNAMIC = new ElfDynamicType(0x70000031,
		"DT_MIPS_AUX_DYNAMIC", "Address of auxiliary .dynamic", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_MIPS_PLTGOT = new ElfDynamicType(0x70000032,
		"DT_MIPS_PLTGOT", "Address of the base of the PLTGOT", ElfDynamicValueType.ADDRESS);
	// 0x70000033
	public static final ElfDynamicType DT_MIPS_RWPLT = new ElfDynamicType(0x70000034,
		"DT_MIPS_RWPLT", "Points to the base of a writable PLT", ElfDynamicValueType.ADDRESS);
	public static final ElfDynamicType DT_MIPS_RLD_MAP_REL = new ElfDynamicType(0x70000035,
		"DT_MIPS_RLD_MAP_REL", "Relative offset of run time loader map, used for debugging",
		ElfDynamicValueType.VALUE);

	// MIPS-specific Symbol information
	// Special values for the st_other field in the symbol table entry for MIPS.
	public static final int STO_MIPS_OPTIONAL = 0x04; // Symbol whose definition is optional
	public static final int STO_MIPS_PLT = 0x08; // PLT entry related dynamic table record
	public static final int STO_MIPS_PIC = 0x20; // PIC func in an object mixes PIC/non-PIC
	public static final int STO_MIPS_MICROMIPS = 0x80; // MIPS Specific ISA for MicroMips
	public static final int STO_MIPS_MIPS16 = 0xf0; // MIPS Specific ISA for Mips16

	// MIPS Option Kind
	public static final byte ODK_NULL = 0;
	public static final byte ODK_REGINFO = 1;
	public static final byte ODK_EXCEPTIONS = 2;
	public static final byte ODK_PAD = 3;
	public static final byte ODK_HWPATCH = 4;
	public static final byte ODK_FILL = 5;
	public static final byte ODK_TAGS = 6;
	public static final byte ODK_HWAND = 7;
	public static final byte ODK_HWOR = 8;
	public static final byte ODK_GP_GROUP = 9;
	public static final byte ODK_IDENT = 10;
	public static final byte ODK_PAGESIZE = 11;

	// MIPS-specific SHN values
	public static final short SHN_MIPS_ACOMMON = (short) 0xff00;
	public static final short SHN_MIPS_TEXT = (short) 0xff01;
	public static final short SHN_MIPS_DATA = (short) 0xff02;

	@Override
	public boolean canHandle(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_MIPS;
	}

	@Override
	public boolean canHandle(ElfLoadHelper elfLoadHelper) {
		Language language = elfLoadHelper.getProgram().getLanguage();
		return canHandle(elfLoadHelper.getElfHeader()) &&
			"MIPS".equals(language.getProcessor().toString());
	}

	@Override
	public String getDataTypeSuffix() {
		return "_MIPS";
	}

	@Override
	public Address creatingFunction(ElfLoadHelper elfLoadHelper, Address functionAddress) {

		Program program = elfLoadHelper.getProgram();
		Register isaModeRegister = program.getRegister("ISA_MODE");
		if (isaModeRegister == null) {
			return functionAddress;
		}

		// Detect 16-bit MIPS code when address bit-0 is set
		if ((functionAddress.getOffset() & 1) != 0) {
			functionAddress = functionAddress.previous(); // align address
			try {
				program.getProgramContext().setValue(isaModeRegister, functionAddress,
					functionAddress, BigInteger.ONE);
			}
			catch (ContextChangeException e) {
				// ignore since should not be instructions at time of import
			}
		}
		return functionAddress;
	}

	@Override
	public Address calculateSymbolAddress(ElfLoadHelper elfLoadHelper, ElfSymbol elfSymbol)
			throws NoValueException {

		short sectionIndex = elfSymbol.getSectionHeaderIndex();
		if (!ElfSectionHeaderConstants.isProcessorSpecificSymbolSectionIndex(sectionIndex)) {
			return null;
		}
		
		if (sectionIndex == SHN_MIPS_ACOMMON || sectionIndex == SHN_MIPS_TEXT || sectionIndex == SHN_MIPS_DATA) {
			// NOTE: logic assumes no memory conflict occured during section loading
			AddressSpace defaultSpace = elfLoadHelper.getProgram().getAddressFactory().getDefaultAddressSpace();
			return defaultSpace.getAddress(elfSymbol.getValue() + elfLoadHelper.getImageBaseWordAdjustmentOffset());
		}

		return null;
	}


	@Override
	public Address evaluateElfSymbol(ElfLoadHelper elfLoadHelper, ElfSymbol elfSymbol,
			Address address, boolean isExternal) {

		updateNonRelocatebleGotEntries(elfLoadHelper, elfSymbol, address);

		if (isExternal) {
			return address;
		}

		if (elfSymbol.getType() == ElfSymbol.STT_FUNC) {

			Program program = elfLoadHelper.getProgram();

			Register isaModeRegister = program.getRegister("ISA_MODE");
			if (isaModeRegister != null) {
				address = applyIsaMode(elfSymbol, address, isaModeRegister, program);
			}

			if (!isExternal && (elfSymbol.getOther() & STO_MIPS_PLT) != 0) {
				elfLoadHelper.createExternalFunctionLinkage(elfSymbol.getNameAsString(), address,
					null);
			}
		}
		return address;
	}

	private Address applyIsaMode(ElfSymbol elfSymbol, Address address, Register isaModeRegister,
			Program program) {
		// Detect 16-bit MIPS code symbol
		int mipsMode = elfSymbol.getOther() & 0xf0;
		long symVal = address.getOffset();

		boolean enableISA = false;
		if ((symVal & 1) != 0) {
			// Detect 16-bit MIPS code when symbol value bit-0 is set
			enableISA = true;
			address = address.previous();
		}
		else {
			// Special values for the st_other field in the symbol table entry for MIPS.
			enableISA = (mipsMode == STO_MIPS_MIPS16 || mipsMode == STO_MIPS_MICROMIPS);
		}

		if (enableISA) {
			try {
				program.getProgramContext().setValue(isaModeRegister, address, address,
					BigInteger.ONE);
			}
			catch (ContextChangeException e) {
				// ignore since should not be instructions at time of import
			}
		}
		return address;
	}

	/**
	 * Attempt to update external dynamic .got entries for non-relocatable binaries.
	 * @param elfLoadHelper ELF load helper
	 * @param elfSymbol ELF symbol being processed
	 * @param address dynamic symbol address
	 */
	private void updateNonRelocatebleGotEntries(ElfLoadHelper elfLoadHelper, ElfSymbol elfSymbol,
			Address address) {

		ElfHeader elfHeader = elfLoadHelper.getElfHeader();
		if (elfHeader.isRelocatable() || !elfSymbol.getSymbolTable().isDynamic()) {
			return;
		}

		Long gotBaseOffset = elfLoadHelper.getGOTValue();
		if (gotBaseOffset == null) {
			return;
		}

		ElfDynamicTable dynamicTable = elfHeader.getDynamicTable();
		if (dynamicTable == null || !dynamicTable.containsDynamicValue(DT_MIPS_LOCAL_GOTNO) ||
			!dynamicTable.containsDynamicValue(DT_MIPS_GOTSYM)) {
			return;
		}

		try {
			int gotLocalEntryCount = (int) dynamicTable.getDynamicValue(DT_MIPS_LOCAL_GOTNO);
			int gotSymbolIndex = (int) dynamicTable.getDynamicValue(DT_MIPS_GOTSYM);

			int symbolIndex = elfSymbol.getSymbolTableIndex();
			if (symbolIndex < gotSymbolIndex) {
				return; // assume non-external symbol
			}

			int gotIndex = gotLocalEntryCount + (symbolIndex - gotSymbolIndex);

			Program program = elfLoadHelper.getProgram();

			Address gotBaseAddress =
				program.getAddressFactory().getDefaultAddressSpace().getAddress(gotBaseOffset);

			// Need to apply adjusted address since fixupGot will re-adjust for image base shift
			long imageShift = elfLoadHelper.getImageBaseWordAdjustmentOffset();
			long symbolOffset = address.getOffset() - imageShift;

			setTableEntryIfZero(gotBaseAddress, gotIndex, symbolOffset, elfLoadHelper);
		}
		catch (MemoryAccessException e) {
			Msg.error(this, "Failed to update .got table entry", e);
		}
		catch (NotFoundException e) {
			throw new AssertException("unexpected", e);
		}
	}

	@Override
	public void processElf(ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
			throws CancelledException {

		processMipsHeaders(elfLoadHelper, monitor);

		processMipsDyanmics(elfLoadHelper, monitor);
	}

	private void processMipsDyanmics(ElfLoadHelper elfLoadHelper, TaskMonitor monitor) {

		ElfDynamicTable dynamicTable = elfLoadHelper.getElfHeader().getDynamicTable();
		if (dynamicTable != null && dynamicTable.containsDynamicValue(DT_MIPS_GP_VALUE)) {
			try {
				ElfHeader elf = elfLoadHelper.getElfHeader();
				long gpValue =
					elf.adjustAddressForPrelink(dynamicTable.getDynamicValue(DT_MIPS_GP_VALUE));
				Address gpAddr = elfLoadHelper.getDefaultAddress(gpValue);
				elfLoadHelper.createSymbol(gpAddr, MIPS_GP_VALUE_SYMBOL, false, false, null);
				elfLoadHelper.log(MIPS_GP_VALUE_SYMBOL + "=0x" + Long.toHexString(gpValue));
			}
			catch (NotFoundException | InvalidInputException e) {
				// ignore
			}
		}
	}

	private void processMipsHeaders(ElfLoadHelper elfLoadHelper, TaskMonitor monitor) {
		ElfHeader elf = elfLoadHelper.getElfHeader();

		Address mipsOptionsAddr = null;
		Address regInfoAddr = null;

		for (ElfProgramHeader programHeader : elf.getProgramHeaders()) {
			int headertype = programHeader.getType();
			if (headertype == PT_MIPS_OPTIONS.value) {
				mipsOptionsAddr = elfLoadHelper.findLoadAddress(programHeader, 0);
			}
			else if (headertype == PT_MIPS_REGINFO.value) {
				regInfoAddr = elfLoadHelper.findLoadAddress(programHeader, 0);
			}
		}

		for (ElfSectionHeader sectionHeader : elf.getSections()) {
			int headertype = sectionHeader.getType();
			if (headertype == SHT_MIPS_OPTIONS.value) {
				mipsOptionsAddr = elfLoadHelper.findLoadAddress(sectionHeader, 0);
			}
			else if (headertype == SHT_MIPS_REGINFO.value) {
				regInfoAddr = elfLoadHelper.findLoadAddress(sectionHeader, 0);
			}
		}

		if (mipsOptionsAddr == null) {
			ElfDynamicTable dynamicTable = elf.getDynamicTable();
			if (dynamicTable != null && dynamicTable.containsDynamicValue(DT_MIPS_OPTIONS)) {
				try {
					long optionsOffset =
						elf.adjustAddressForPrelink(dynamicTable.getDynamicValue(DT_MIPS_OPTIONS));
					mipsOptionsAddr = elfLoadHelper.getDefaultAddress(optionsOffset);
				}
				catch (NotFoundException e) {
					throw new AssertException("unexpected", e);
				}
			}
		}

		if (mipsOptionsAddr != null) {
			processMipsOptions(elfLoadHelper, mipsOptionsAddr);
		}
		if (regInfoAddr != null) {
			// TODO: don't do this if mips options present and processed
			processMipsRegInfo(elfLoadHelper, regInfoAddr);
		}
	}

	private void processMipsOptions(ElfLoadHelper elfLoadHelper, Address mipsOptionsAddr) {

		boolean elf64 = elfLoadHelper.getElfHeader().is64Bit();
		String prefix = elf64 ? "Elf64" : "Elf32";

		EnumDataType odkType = new EnumDataType(prefix + "_MipsOptionKind", 1);
		odkType.add("ODK_NULL", ODK_NULL);
		odkType.add("ODK_REGINFO", ODK_REGINFO);
		odkType.add("ODK_EXCEPTIONS", ODK_EXCEPTIONS);
		odkType.add("ODK_PAD", ODK_PAD);
		odkType.add("ODK_HWPATCH", ODK_HWPATCH);
		odkType.add("ODK_FILL", ODK_FILL);
		odkType.add("ODK_TAGS", ODK_TAGS);
		odkType.add("ODK_HWAND", ODK_HWAND);
		odkType.add("ODK_HWOR", ODK_HWOR);
		odkType.add("ODK_GP_GROUP", ODK_GP_GROUP);
		odkType.add("ODK_IDENT", ODK_IDENT);
		odkType.add("ODK_PAGESIZE", ODK_PAGESIZE);

		Structure odkHeader =
			new StructureDataType(new CategoryPath("/ELF"), prefix + "_MipsOptionHeader", 0);
		odkHeader.add(odkType, "kind", null);
		odkHeader.add(ByteDataType.dataType, "size", null);
		odkHeader.add(WordDataType.dataType, "section", null);
		odkHeader.add(DWordDataType.dataType, "info", null);

		Memory memory = elfLoadHelper.getProgram().getMemory();
		long limit = 0;
		MemoryBlock block = memory.getBlock(mipsOptionsAddr);
		if (block != null) {
			limit = block.getEnd().subtract(mipsOptionsAddr) + 1;
		}

		Address nextOptionAddr = mipsOptionsAddr;
		int optionDataSize = 0;
		try {
			while (limit >= odkHeader.getLength()) {

				nextOptionAddr = nextOptionAddr.add(optionDataSize);
				byte kind = memory.getByte(nextOptionAddr);
				if (kind == 0) {
					break;
				}

				Data odkData = elfLoadHelper.createData(nextOptionAddr, odkHeader);
				if (odkData == null) {
					throw new MemoryAccessException();
				}

				int size = (memory.getByte(nextOptionAddr.next()) & 0xff) - odkData.getLength();
				optionDataSize = size + (size % 8);

				if (memory.getByte(nextOptionAddr) == 0) {
					break;
				}

				nextOptionAddr = nextOptionAddr.add(odkData.getLength());

				switch (kind) {

					case ODK_REGINFO:
						processMipsRegInfo(elfLoadHelper, nextOptionAddr);
						break;

					default:
						if (optionDataSize > 0) {
							// consume unprocessed option description bytes
							elfLoadHelper.createData(nextOptionAddr,
								new ArrayDataType(ByteDataType.dataType, optionDataSize, 1));
						}
				}

				limit -= odkHeader.getLength() + optionDataSize;
			}
		}
		catch (AddressOutOfBoundsException | MemoryAccessException e) {
			// ignore
		}
	}

	private Structure buildRegInfoStructure(boolean elf64) {

		String prefix = elf64 ? "Elf64" : "Elf32";

		EnumDataType gprMask = new EnumDataType(prefix + "_GPRMask_MIPS", 4);
		gprMask.add("gpr_zero", 1);
		gprMask.add("gpr_at", 2);
		gprMask.add("gpr_v0", 4);
		gprMask.add("gpr_v1", 8);
		gprMask.add("gpr_a0", 0x10);
		gprMask.add("gpr_a1", 0x20);
		gprMask.add("gpr_a2", 0x40);
		gprMask.add("gpr_a3", 0x80);
		gprMask.add("gpr_t0", 0x100);
		gprMask.add("gpr_t1", 0x200);
		gprMask.add("gpr_t2", 0x400);
		gprMask.add("gpr_t3", 0x800);
		gprMask.add("gpr_t4", 0x1000);
		gprMask.add("gpr_t5", 0x2000);
		gprMask.add("gpr_t6", 0x4000);
		gprMask.add("gpr_t7", 0x8000);
		gprMask.add("gpr_s0", 0x10000);
		gprMask.add("gpr_s1", 0x20000);
		gprMask.add("gpr_s2", 0x40000);
		gprMask.add("gpr_s3", 0x80000);
		gprMask.add("gpr_s4", 0x100000);
		gprMask.add("gpr_s5", 0x200000);
		gprMask.add("gpr_s6", 0x400000);
		gprMask.add("gpr_s7", 0x800000);
		gprMask.add("gpr_t8", 0x1000000);
		gprMask.add("gpr_t9", 0x2000000);
		gprMask.add("gpr_k0", 0x4000000);
		gprMask.add("gpr_k1", 0x8000000);
		gprMask.add("gpr_gp", 0x10000000);
		gprMask.add("gpr_sp", 0x20000000);
		gprMask.add("gpr_fp", 0x40000000);
		gprMask.add("gpr_ra", 0x80000000L);

		Structure regInfoStruct =
			new StructureDataType(new CategoryPath("/ELF"), prefix + "_RegInfo_MIPS", 0);
		regInfoStruct.add(gprMask, "ri_gprmask", null);
		if (elf64) {
			regInfoStruct.add(DWordDataType.dataType, "ri_pad", null);
		}
		regInfoStruct.add(new ArrayDataType(DWordDataType.dataType, 4, 4));
		if (elf64) {
			regInfoStruct.add(QWordDataType.dataType, "ri_gp_value", null);
		}
		else {
			regInfoStruct.add(DWordDataType.dataType, "ri_gp_value", null);
		}
		return regInfoStruct;
	}

	private void processMipsRegInfo(ElfLoadHelper elfLoadHelper, Address regInfoAddr) {

		// NOTES: assumes only one gp0 value

		boolean is64bit = elfLoadHelper.getElfHeader().is64Bit();
		Structure regInfoStruct = buildRegInfoStructure(is64bit);

		Data data = elfLoadHelper.createData(regInfoAddr, regInfoStruct);
		Data gpValueComponent = data.getComponent(is64bit ? 3 : 2); // ri_gp_value value -> gp0
		if (gpValueComponent != null) {
			try {
				// Create gp0 symbol in default space which represents a constant value (pinned)
				Scalar gp0Value = gpValueComponent.getScalar(0);
				long gp0 = gp0Value.getUnsignedValue();
				AddressSpace defaultSpace =
					elfLoadHelper.getProgram().getAddressFactory().getDefaultAddressSpace();
				Address gpAddr = defaultSpace.getAddress(gp0);
				elfLoadHelper.createSymbol(gpAddr, MIPS_GP0_VALUE_SYMBOL, false, false,
					null).setPinned(true);
				elfLoadHelper.log(MIPS_GP0_VALUE_SYMBOL + "=0x" + Long.toHexString(gp0));
			}
			catch (InvalidInputException e) {
				// ignore
			}
		}

	}

	@Override
	public void processGotPlt(ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
			throws CancelledException {

		fixupGot(elfLoadHelper, monitor);

		fixupMipsGot(elfLoadHelper, monitor);

		super.processGotPlt(elfLoadHelper, monitor);

		processMipsStubsSection(elfLoadHelper, monitor);
	}

	private void processMipsStubsSection(ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
			throws CancelledException {

		Memory memory = elfLoadHelper.getProgram().getMemory();
		MemoryBlock stubsBlock = memory.getBlock(MIPS_STUBS_SECTION_NAME);
		if (stubsBlock == null || !stubsBlock.isExecute()) {
			return;
		}

		ElfDefaultGotPltMarkup defaultGotPltMarkup = new ElfDefaultGotPltMarkup(elfLoadHelper);
		defaultGotPltMarkup.processLinkageTable(MIPS_STUBS_SECTION_NAME, stubsBlock.getStart(),
			stubsBlock.getEnd(), monitor);
	}

	private void fixupGot(ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
			throws CancelledException {

		// see Wiki at  https://dmz-portal.mips.com/wiki/MIPS_Multi_GOT
		// see related doc at https://www.cr0.org/paper/mips.elf.external.resolution.txt

		ElfHeader elfHeader = elfLoadHelper.getElfHeader();
		ElfDynamicTable dynamicTable = elfHeader.getDynamicTable();
		ElfSymbolTable dynamicSymbolTable = elfHeader.getDynamicSymbolTable();
		if (dynamicTable == null || dynamicSymbolTable == null) {
			return;
		}

		// Ensure that we can get the required dynamic entries to avoid NotFoundException
		if (!dynamicTable.containsDynamicValue(DT_MIPS_LOCAL_GOTNO) ||
			!dynamicTable.containsDynamicValue(DT_MIPS_GOTSYM)) {
			return;
		}
		Program program = elfLoadHelper.getProgram();
		Long gotBaseOffset = elfLoadHelper.getGOTValue();
		if (gotBaseOffset == null) {
			return;
		}

		Address gotBaseAddress =
			program.getAddressFactory().getDefaultAddressSpace().getAddress(gotBaseOffset);

		try {

			ElfSymbol[] elfSymbols = dynamicSymbolTable.getSymbols();

			int gotLocalEntryCount = (int) dynamicTable.getDynamicValue(DT_MIPS_LOCAL_GOTNO);
			int gotSymbolIndex = (int) dynamicTable.getDynamicValue(DT_MIPS_GOTSYM);

			long imageShift = elfLoadHelper.getImageBaseWordAdjustmentOffset();

			// process local symbol got entries
			for (int i = 0; i < gotLocalEntryCount; i++) {
				monitor.checkCanceled();
				Address gotEntryAddr =
					adjustTableEntryIfNonZero(gotBaseAddress, i, imageShift, elfLoadHelper);
				Data pointerData = elfLoadHelper.createData(gotEntryAddr, PointerDataType.dataType);
				if (ElfDefaultGotPltMarkup.isValidPointer(pointerData)) {
					ElfDefaultGotPltMarkup.setConstant(pointerData);
				}
			}

			// process global/external symbol got entries
			int gotIndex = gotLocalEntryCount;
			for (int i = gotSymbolIndex; i < elfSymbols.length; i++) {
				monitor.checkCanceled();
				Address gotEntryAddr = adjustTableEntryIfNonZero(gotBaseAddress, gotIndex++,
					imageShift, elfLoadHelper);
				Data pointerData = elfLoadHelper.createData(gotEntryAddr, PointerDataType.dataType);
				ElfDefaultGotPltMarkup.setConstant(pointerData);
				if (elfSymbols[i].isFunction() && elfSymbols[i].getSectionHeaderIndex() == 0) {
					// ensure that external function/thunk are created in absence of sections
					Address refAddr = (Address) pointerData.getValue();
					elfLoadHelper.createExternalFunctionLinkage(elfSymbols[i].getNameAsString(),
						refAddr, gotEntryAddr);
				}
			}
		}
		catch (NotFoundException e) {
			throw new AssertException("unexpected", e);
		}
		catch (MemoryAccessException e) {
			elfLoadHelper.log("Failed to adjust GOT: " + e.getMessage());
		}
	}

	private void fixupMipsGot(ElfLoadHelper elfLoadHelper, TaskMonitor monitor) throws CancelledException {

		ElfHeader elfHeader = elfLoadHelper.getElfHeader();
		ElfDynamicTable dynamicTable = elfHeader.getDynamicTable();
		ElfSymbolTable dynamicSymbolTable = elfHeader.getDynamicSymbolTable();
		if (dynamicTable == null || dynamicSymbolTable == null) {
			return;
		}

		ElfSymbol[] elfSymbols = dynamicSymbolTable.getSymbols();

		// Ensure that we can get the required dynamic entries to avoid NotFoundException
		if (!dynamicTable.containsDynamicValue(DT_MIPS_PLTGOT) ||
			!dynamicTable.containsDynamicValue(DT_MIPS_GOTSYM)) {
			return;
		}

		Program program = elfLoadHelper.getProgram();

		Symbol mipsPltgotSym = SymbolUtilities.getLabelOrFunctionSymbol(program, "__DT_MIPS_PLTGOT",
			err -> elfLoadHelper.getLog().appendMsg(err));
		if (mipsPltgotSym == null) {
			return; // unexpected
		}
		Address mipsPltgotBase = mipsPltgotSym.getAddress();

		try {

			int gotSymbolIndex = (int) dynamicTable.getDynamicValue(DT_MIPS_GOTSYM);

			long imageShift = elfLoadHelper.getImageBaseWordAdjustmentOffset();

			// process local symbol got entries
			int gotEntryIndex = 1;
			for (int i = 0; i < gotSymbolIndex; i++) {
				monitor.checkCanceled();
				if (!elfSymbols[i].isFunction() || elfSymbols[i].getSectionHeaderIndex() != 0) {
					continue;
				}
				Address gotEntryAddr = adjustTableEntryIfNonZero(mipsPltgotBase, ++gotEntryIndex,
					imageShift, elfLoadHelper);
				Data pointerData = elfLoadHelper.createData(gotEntryAddr, PointerDataType.dataType);
				ElfDefaultGotPltMarkup.setConstant(pointerData);
			}
		}
		catch (NotFoundException e) {
			throw new AssertException("unexpected", e);
		}
		catch (MemoryAccessException e) {
			elfLoadHelper.log("Failed to adjust MIPS GOT: " + e.getMessage());
		}
	}

	private Address adjustTableEntryIfNonZero(Address tableBaseAddr, int entryIndex,
			long adjustment, ElfLoadHelper elfLoadHelper) throws MemoryAccessException {
		// TODO: record artificial relative relocation for reversion/export concerns
		boolean is64Bit = elfLoadHelper.getElfHeader().is64Bit();
		Memory memory = elfLoadHelper.getProgram().getMemory();
		Address tableEntryAddr;
		if (is64Bit) {
			tableEntryAddr = tableBaseAddr.add(entryIndex * 8);
			long offset = memory.getLong(tableEntryAddr);
			if (offset != 0) {
				memory.setLong(tableEntryAddr, offset + adjustment);
			}
		}
		else {
			tableEntryAddr = tableBaseAddr.add(entryIndex * 4);
			int offset = memory.getInt(tableEntryAddr);
			if (offset != 0) {
				memory.setInt(tableEntryAddr, (int) (offset + adjustment));
			}
		}
		return tableEntryAddr;
	}

	private Address setTableEntryIfZero(Address tableBaseAddr, int entryIndex, long value,
			ElfLoadHelper elfLoadHelper) throws MemoryAccessException {
		// TODO: record artificial relative relocation for reversion/export concerns
		boolean is64Bit = elfLoadHelper.getElfHeader().is64Bit();
		Memory memory = elfLoadHelper.getProgram().getMemory();
		Address tableEntryAddr;
		if (is64Bit) {
			tableEntryAddr = tableBaseAddr.add(entryIndex * 8);
			long offset = memory.getLong(tableEntryAddr);
			if (offset == 0) {
				memory.setLong(tableEntryAddr, value);
			}
		}
		else {
			tableEntryAddr = tableBaseAddr.add(entryIndex * 4);
			int offset = memory.getInt(tableEntryAddr);
			if (offset == 0) {
				memory.setInt(tableEntryAddr, (int) value);
			}
		}
		return tableEntryAddr;
	}

	@Override
	public Class<? extends ElfRelocation> getRelocationClass(ElfHeader elfHeader) {
		if (elfHeader.is64Bit()) {
			return MIPS_Elf64Relocation.class;
		}
		return super.getRelocationClass(elfHeader);
	}

}
