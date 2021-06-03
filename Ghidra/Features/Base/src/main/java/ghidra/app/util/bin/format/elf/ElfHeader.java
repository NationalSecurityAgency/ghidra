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

import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.*;

import generic.continues.GenericFactory;
import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.Writeable;
import ghidra.app.util.bin.format.elf.ElfRelocationTable.TableFormat;
import ghidra.app.util.bin.format.elf.extend.ElfExtensionFactory;
import ghidra.app.util.bin.format.elf.extend.ElfLoadAdapter;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.NotFoundException;

/**
 * A class to represent the Executable and Linking Format (ELF)
 * header and specification.
 */
public class ElfHeader implements StructConverter, Writeable {

	private static final int MAX_HEADERS_TO_CHECK_FOR_IMAGEBASE = 20;

	private static final int PAD_LENGTH = 7;

	private HashMap<Integer, ElfProgramHeaderType> programHeaderTypeMap;
	private HashMap<Integer, ElfSectionHeaderType> sectionHeaderTypeMap;
	private HashMap<Integer, ElfDynamicType> dynamicTypeMap;

	private FactoryBundledWithBinaryReader reader;
	private ElfLoadAdapter elfLoadAdapter = new ElfLoadAdapter();

	private byte e_ident_magic_num; //magic number
	private String e_ident_magic_str; //magic string
	private byte e_ident_class; //file class
	private byte e_ident_data; //data encoding
	private byte e_ident_version; //file version
	private byte e_ident_osabi; //operating system and abi
	private byte e_ident_abiversion; //abi version
	private byte[] e_ident_pad; //padding
	private short e_type; //object file type
	private short e_machine; //target architecture
	private int e_version; //object file version
	private long e_entry; //executable entry point
	private long e_phoff; //program header table offset
	private long e_shoff; //section header table offset
	private int e_flags; //processor-specific flags
	private short e_ehsize; //elf header size
	private short e_phentsize; //size of entries in the program header table
	private short e_phnum; //number of enties in the program header table
	private short e_shentsize; //size of entries in the section header table
	private short e_shnum; //number of enties in the section header table
	private short e_shstrndx; //section index of the section name string table

	private Structure headerStructure;

	private boolean parsed = false;
	private boolean parsedSectionHeaders = false;

	private ElfSectionHeader[] sectionHeaders = new ElfSectionHeader[0];
	private ElfProgramHeader[] programHeaders = new ElfProgramHeader[0];
	private ElfStringTable[] stringTables = new ElfStringTable[0];
	private ElfSymbolTable[] symbolTables = new ElfSymbolTable[0];
	private ElfRelocationTable[] relocationTables = new ElfRelocationTable[0];
	private ElfDynamicTable dynamicTable;

	private ElfStringTable dynamicStringTable;
	private ElfSymbolTable dynamicSymbolTable;

	private String[] dynamicLibraryNames;

	private boolean hasLittleEndianHeaders;

	private static int INITIAL_READ_LEN = ElfConstants.EI_NIDENT + 18;

	/**
	 * Constructs a new ELF header using the specified byte provider.
	 * @param provider the byte provider to supply the bytes
	 * @throws ElfException if the underlying bytes in the byte provider 
	 * do not constitute a valid ELF.
	 */
	public static ElfHeader createElfHeader(GenericFactory factory, ByteProvider provider)
			throws ElfException {
		ElfHeader elfHeader = (ElfHeader) factory.create(ElfHeader.class);
		elfHeader.initElfHeader(factory, provider);
		return elfHeader;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public ElfHeader() {
	}

	/**
	 * Returns the binary reader.
	 * @return the binary reader
	 */
	public BinaryReader getReader() {
		return reader;
	}

	protected void initElfHeader(GenericFactory factory, ByteProvider provider)
			throws ElfException {
		try {

			determineHeaderEndianess(provider);

			reader = new FactoryBundledWithBinaryReader(factory, provider, hasLittleEndianHeaders);

			e_ident_magic_num = reader.readNextByte();
			e_ident_magic_str = reader.readNextAsciiString(ElfConstants.MAGIC_STR_LEN);

			boolean magicMatch = ElfConstants.MAGIC_NUM == e_ident_magic_num &&
				ElfConstants.MAGIC_STR.equalsIgnoreCase(e_ident_magic_str);

			if (!magicMatch) {
				throw new ElfException("Not a valid ELF executable.");
			}

			e_ident_class = reader.readNextByte();
			e_ident_data = reader.readNextByte();
			e_ident_version = reader.readNextByte();
			e_ident_osabi = reader.readNextByte();
			e_ident_abiversion = reader.readNextByte();
			e_ident_pad = reader.readNextByteArray(PAD_LENGTH);
			e_type = reader.readNextShort();
			e_machine = reader.readNextShort();
			e_version = reader.readNextInt();

			if (is32Bit()) {
				e_entry = reader.readNextInt() & 0xffffffffL;
				e_phoff = reader.readNextInt() & 0xffffffffL;
				e_shoff = reader.readNextInt() & 0xffffffffL;
			}
			else if (is64Bit()) {
				e_entry = reader.readNextLong();
				e_phoff = reader.readNextLong();
				e_shoff = reader.readNextLong();
			}
			else {
				throw new ElfException("Only 32-bit and 64-bit ELF headers are supported.");
			}

			e_flags = reader.readNextInt();
			e_ehsize = reader.readNextShort();
			e_phentsize = reader.readNextShort();
			e_phnum = reader.readNextShort();
			if (e_phnum < 0) {
				e_phnum = 0; // protect against stripped program headers
			}
			e_shentsize = reader.readNextShort();
			e_shnum = reader.readNextShort();
			if (e_shnum < 0) {
				e_shnum = 0; // protect against stripped section headers (have seen -1)
			}
			e_shstrndx = reader.readNextShort();
		}
		catch (IOException e) {
			throw new ElfException(e);
		}
	}

	private void initElfLoadAdapter() {

		programHeaderTypeMap = new HashMap<>();
		ElfProgramHeaderType.addDefaultTypes(programHeaderTypeMap);

		sectionHeaderTypeMap = new HashMap<>();
		ElfSectionHeaderType.addDefaultTypes(sectionHeaderTypeMap);

		dynamicTypeMap = new HashMap<>();
		ElfDynamicType.addDefaultTypes(dynamicTypeMap);

		ElfLoadAdapter extensionAdapter = ElfExtensionFactory.getLoadAdapter(this);
		if (extensionAdapter != null) {
			extensionAdapter.addProgramHeaderTypes(programHeaderTypeMap);
			extensionAdapter.addSectionHeaderTypes(sectionHeaderTypeMap);
			extensionAdapter.addDynamicTypes(dynamicTypeMap);
			elfLoadAdapter = extensionAdapter;
		}
	}

	public void parse() throws IOException {

		if (reader == null) {
			throw new IOException("ELF binary reader is null!");
		}
		if (parsed) {
			return;
		}

		initElfLoadAdapter();

		parsed = true;

		parseProgramHeaders();

		parseSectionHeaders();

		parseDynamicTable();

		parseStringTables();
		parseDynamicLibraryNames();
		parseSymbolTables();
		parseRelocationTables();

		parseGNU_d();
		parseGNU_r();
	}

	/**
	 * Get the installed extension provider.  If the parse method has not yet been 
	 * invoked, the default adapter will be returned.
	 * @return ELF load adapter
	 */
	public ElfLoadAdapter getLoadAdapter() {
		return elfLoadAdapter;
	}

	/**
	 * Adjust address offset for certain pre-linked binaries which do not adjust certain
	 * header fields (e.g., dynamic table address entries).  Standard GNU/Linux pre-linked 
	 * shared libraries have adjusted header entries and this method should have no effect. 
	 * @param address
	 * @return address with appropriate pre-link adjustment added
	 */
	public long adjustAddressForPrelink(long address) {

		// TODO: how do we ensure that adjustment is only made to 
		// addresses in the default space?  Should loads into
		// data space have the same adjustment?

		long base = getPreLinkImageBase();
		if (base == -1) {
			base = 0;
		}

		return base + address;
	}

	/**
	 * Unadjust address offset for certain pre-linked binaries which do not adjust certain
	 * header fields (e.g., dynamic table address entries).  This may be needed when updating
	 * a header address field which requires pre-link adjustment.
	 * @param address
	 * @return address with appropriate pre-link adjustment subtracted
	 */
	public long unadjustAddressForPrelink(long address) {

		// TODO: how do we ensure that adjustment is only made to 
		// addresses in the default space?  Should loads into
		// data space have the same adjustment?

		long base = getPreLinkImageBase();
		if (base == -1) {
			base = 0;
		}

		return address - base;
	}

	protected HashMap<Integer, ElfProgramHeaderType> getProgramHeaderTypeMap() {
		return programHeaderTypeMap;
	}

	protected HashMap<Integer, ElfSectionHeaderType> getSectionHeaderTypeMap() {
		return sectionHeaderTypeMap;
	}

	public ElfProgramHeaderType getProgramHeaderType(int type) {
		if (programHeaderTypeMap != null) {
			return programHeaderTypeMap.get(type);
		}
		return null; // not found
	}

	public ElfSectionHeaderType getSectionHeaderType(int type) {
		if (sectionHeaderTypeMap != null) {
			return sectionHeaderTypeMap.get(type);
		}
		return null; // not found
	}

	protected HashMap<Integer, ElfDynamicType> getDynamicTypeMap() {
		return dynamicTypeMap;
	}

	public ElfDynamicType getDynamicType(int type) {
		if (dynamicTypeMap != null) {
			return dynamicTypeMap.get(type);
		}
		return null; // not found
	}

	String getTypeSuffix() {
		if (elfLoadAdapter == null) {
			return null;
		}
		String typeSuffix = elfLoadAdapter.getDataTypeSuffix();
		if (typeSuffix != null && typeSuffix.length() == 0) {
			typeSuffix = null;
		}
		return typeSuffix;
	}

	private void parseGNU_d() {
		ElfSectionHeader[] sections = getSections(ElfSectionHeaderConstants.SHT_GNU_verdef);
		if (sections.length == 0) {
			return;
		}
		//TODO: ElfSectionHeader gnuVersionD = sections[0];
	}

	private void parseGNU_r() {
		ElfSectionHeader[] sections = getSections(ElfSectionHeaderConstants.SHT_GNU_verneed);
		if (sections.length == 0) {
			return;
		}
		//TODO ElfSectionHeader gnuVersionR = sections[0];
	}

	private void parseRelocationTables() throws IOException {

		ArrayList<ElfRelocationTable> relocationTableList = new ArrayList<>();

		// Order of parsing and processing dynamic relocation tables can be important to ensure that
		// GOT/PLT relocations are applied late.

		parseDynamicRelocTable(relocationTableList, ElfDynamicType.DT_REL, ElfDynamicType.DT_RELENT,
			ElfDynamicType.DT_RELSZ, false);

		parseDynamicRelocTable(relocationTableList, ElfDynamicType.DT_RELA,
			ElfDynamicType.DT_RELAENT, ElfDynamicType.DT_RELASZ, true);

		if (dynamicTable != null && dynamicTable.containsDynamicValue(ElfDynamicType.DT_PLTREL)) {
			try {
				boolean isRela = (dynamicTable
						.getDynamicValue(ElfDynamicType.DT_PLTREL) == ElfDynamicType.DT_RELA.value);
				parseDynamicRelocTable(relocationTableList, ElfDynamicType.DT_JMPREL, null,
					ElfDynamicType.DT_PLTRELSZ, isRela);
			}
			catch (NotFoundException e) {
				// ignore - skip (required dynamic table value is missing)
			}
		}

		// Android versions
		parseDynamicRelocTable(relocationTableList, ElfDynamicType.DT_ANDROID_REL, null,
			ElfDynamicType.DT_ANDROID_RELSZ, false);

		parseDynamicRelocTable(relocationTableList, ElfDynamicType.DT_ANDROID_RELA, null,
			ElfDynamicType.DT_ANDROID_RELASZ, true);

		parseDynamicRelocTable(relocationTableList, ElfDynamicType.DT_RELR,
			ElfDynamicType.DT_RELRENT, ElfDynamicType.DT_RELRSZ, false);

		parseDynamicRelocTable(relocationTableList, ElfDynamicType.DT_ANDROID_RELR,
			ElfDynamicType.DT_ANDROID_RELRENT, ElfDynamicType.DT_ANDROID_RELRSZ, false);

		parseJMPRelocTable(relocationTableList);

		// In general the above dynamic relocation tables should cover most cases, we will
		// check section headers for possible custom relocation tables
		for (ElfSectionHeader section : sectionHeaders) {
			parseSectionBasedRelocationTable(section, relocationTableList);
		}

		relocationTables = new ElfRelocationTable[relocationTableList.size()];
		relocationTableList.toArray(relocationTables);
	}

	private void parseSectionBasedRelocationTable(ElfSectionHeader section,
			ArrayList<ElfRelocationTable> relocationTableList) throws IOException {
		try {
			int sectionHeaderType = section.getType();
			if (sectionHeaderType == ElfSectionHeaderConstants.SHT_REL ||
				sectionHeaderType == ElfSectionHeaderConstants.SHT_RELA ||
				sectionHeaderType == ElfSectionHeaderConstants.SHT_RELR ||
				sectionHeaderType == ElfSectionHeaderConstants.SHT_ANDROID_REL ||
				sectionHeaderType == ElfSectionHeaderConstants.SHT_ANDROID_RELA ||
				sectionHeaderType == ElfSectionHeaderConstants.SHT_ANDROID_RELR) {

				for (ElfRelocationTable relocTable : relocationTableList) {
					if (relocTable.getFileOffset() == section.getOffset()) {
						return; // skip reloc table previously parsed as dynamic entry
					}
				}

				int link = section.getLink(); // section index of associated symbol table
				int info = section.getInfo(); // section index of section to which relocations apply (relocation offset base)

				ElfSectionHeader sectionToBeRelocated = info != 0 ? getLinkedSection(info) : null;
				String relocaBaseName =
					sectionToBeRelocated != null ? sectionToBeRelocated.getNameAsString()
							: "PT_LOAD";

				ElfSectionHeader symbolTableSection;
				if (link == 0) {
					// dynamic symbol table assumed when link section value is 0
					symbolTableSection = getSection(ElfSectionHeaderConstants.dot_dynsym);
				}
				else {
					symbolTableSection = getLinkedSection(link,
						ElfSectionHeaderConstants.SHT_DYNSYM, ElfSectionHeaderConstants.SHT_SYMTAB);
				}

				ElfSymbolTable symbolTable = getSymbolTable(symbolTableSection);
				if (symbolTable == null) {
					throw new NotFoundException("Referenced relocation symbol section not found.");
				}

				boolean addendTypeReloc =
					(sectionHeaderType == ElfSectionHeaderConstants.SHT_RELA ||
						sectionHeaderType == ElfSectionHeaderConstants.SHT_ANDROID_RELA);

				Msg.debug(this,
					"Elf relocation table section " + section.getNameAsString() +
						" linked to symbol table section " + symbolTableSection.getNameAsString() +
						" affecting " + relocaBaseName);

				if (section.getOffset() < 0) {
					return;
				}

				ElfRelocationTable.TableFormat format = TableFormat.DEFAULT;
				if (sectionHeaderType == ElfSectionHeaderConstants.SHT_ANDROID_REL ||
					sectionHeaderType == ElfSectionHeaderConstants.SHT_ANDROID_RELA) {
					format = TableFormat.ANDROID;
				}
				else if (sectionHeaderType == ElfSectionHeaderConstants.SHT_RELR ||
					sectionHeaderType == ElfSectionHeaderConstants.SHT_ANDROID_RELR) {
					format = TableFormat.RELR;
				}

				ElfRelocationTable relocTable = ElfRelocationTable.createElfRelocationTable(reader,
					this, section, section.getOffset(), section.getAddress(), section.getSize(),
					section.getEntrySize(), addendTypeReloc, symbolTable, sectionToBeRelocated,
					format);

				relocationTableList.add(relocTable);
			}
		}
		catch (NotFoundException e) {
			Msg.error(this, "Failed to process relocation section " + section.getNameAsString() +
				": " + e.getMessage());
		}
	}

	private void parseJMPRelocTable(ArrayList<ElfRelocationTable> relocationTableList)
			throws IOException {

		if (dynamicTable == null) {
			return;
		}

		boolean addendTypeReloc;
		try {
			long tableType = dynamicTable.getDynamicValue(ElfDynamicType.DT_PLTREL);
			addendTypeReloc = (tableType == ElfDynamicType.DT_RELA.value);
		}
		catch (NotFoundException e) {
			return; // ignore - skip
		}

		parseDynamicRelocTable(relocationTableList, ElfDynamicType.DT_JMPREL,
			addendTypeReloc ? ElfDynamicType.DT_RELAENT : ElfDynamicType.DT_RELENT,
			ElfDynamicType.DT_PLTRELSZ, addendTypeReloc);

	}

	private void parseDynamicRelocTable(ArrayList<ElfRelocationTable> relocationTableList,
			ElfDynamicType relocTableAddrType, ElfDynamicType relocEntrySizeType,
			ElfDynamicType relocTableSizeType, boolean addendTypeReloc) throws IOException {

		if (dynamicTable == null) {
			return;
		}

		try {

			// NOTE: Dynamic and Relocation tables are loaded into memory, however,
			// we construct them without loading so we must map memory addresses 
			// back to file offsets.

			long relocTableAddr =
				adjustAddressForPrelink(dynamicTable.getDynamicValue(relocTableAddrType));

			ElfSectionHeader relocTableSectionHeader =
				getSectionLoadHeaderContaining(relocTableAddr);
			if (relocTableSectionHeader != null) {
				parseSectionBasedRelocationTable(relocTableSectionHeader, relocationTableList);
				return;
			}

			ElfProgramHeader relocTableLoadHeader = getProgramLoadHeaderContaining(relocTableAddr);
			if (relocTableLoadHeader == null) {
				Msg.warn(this, "Failed to locate " + relocTableAddrType.name + " in memory at 0x" +
					Long.toHexString(relocTableAddr));
				return;
			}
			if (relocTableLoadHeader.getOffset() < 0) {
				return;
			}

			if (dynamicSymbolTable == null) {
				Msg.warn(this, "Failed to process " + relocTableAddrType.name +
					", missing dynamic symbol table");
				return;
			}

			long relocTableOffset = relocTableLoadHeader.getOffset(relocTableAddr);
			long tableEntrySize =
				relocEntrySizeType != null ? dynamicTable.getDynamicValue(relocEntrySizeType) : -1;
			long tableSize = dynamicTable.getDynamicValue(relocTableSizeType);

			ElfRelocationTable.TableFormat format = TableFormat.DEFAULT;
			if (relocTableAddrType == ElfDynamicType.DT_ANDROID_REL ||
				relocTableAddrType == ElfDynamicType.DT_ANDROID_RELA) {
				format = TableFormat.ANDROID;
			}
			else if (relocTableAddrType == ElfDynamicType.DT_RELR ||
				relocTableAddrType == ElfDynamicType.DT_ANDROID_RELR) {
				format = TableFormat.RELR;
			}

			ElfRelocationTable relocTable = ElfRelocationTable.createElfRelocationTable(reader,
				this, null, relocTableOffset, relocTableAddr, tableSize, tableEntrySize,
				addendTypeReloc, dynamicSymbolTable, null, format);
			relocationTableList.add(relocTable);
		}
		catch (NotFoundException e) {
			// ignore - skip (required dynamic table value is missing)
		}
	}

	/**
	 * Get linked section
	 * @param sectionIndex
	 * @param expectedTypes list of expectedTypes (may be omitted to accept any type)
	 * @return section or null if not found
	 */
	private ElfSectionHeader getLinkedSection(int sectionIndex, int... expectedTypes)
			throws NotFoundException {
		if (sectionIndex < 0 || sectionIndex >= sectionHeaders.length) {
			throw new NotFoundException("invalid linked section index " + sectionIndex);
		}
		ElfSectionHeader section = sectionHeaders[sectionIndex];
		if (expectedTypes.length == 0) {
			return section;
		}
		for (int type : expectedTypes) {
			if (type == section.getType()) {
				return section;
			}
		}
		throw new NotFoundException("unexpected section type for section index " + sectionIndex);
	}

	private void parseDynamicLibraryNames() {

		if (dynamicTable == null) {
			dynamicLibraryNames = new String[0];
			return;
		}

		ElfDynamic[] needed = dynamicTable.getDynamics(ElfDynamicType.DT_NEEDED);
		dynamicLibraryNames = new String[needed.length];
		for (int i = 0; i < needed.length; i++) {
			if (dynamicStringTable != null) {
				try {
					dynamicLibraryNames[i] =
						dynamicStringTable.readString(reader, needed[i].getValue());
				}
				catch (Exception e) {
					// ignore
				}
			}
			if (dynamicLibraryNames[i] == null) {
				dynamicLibraryNames[i] = "UNK_LIB_NAME_" + i;
			}
		}
	}

	private void parseDynamicTable() throws IOException {
		ElfProgramHeader[] dynamicHeaders = getProgramHeaders(ElfProgramHeaderConstants.PT_DYNAMIC);
		if (dynamicHeaders.length == 1) { // no more than one expected

			// The p_offset may not refer to the start of the DYNAMIC table so we must use
			// p_vaddr to find it relative to a PT_LOAD segment
			long vaddr = dynamicHeaders[0].getVirtualAddress();
			if (vaddr == 0) {
				Msg.warn(this, "ELF Dynamic table appears to have been stripped from binary");
				return;
			}

			ElfProgramHeader loadHeader = getProgramLoadHeaderContaining(vaddr);
			if (loadHeader != null) {
				long dynamicTableOffset = loadHeader.getOffset() +
					(dynamicHeaders[0].getVirtualAddress() - loadHeader.getVirtualAddress());
				dynamicTable = ElfDynamicTable.createDynamicTable(reader, this, dynamicTableOffset,
					dynamicHeaders[0].getVirtualAddress());
				return;
			}
		}
		else if (dynamicHeaders.length > 1) {
			Msg.error(this, "Multiple ELF Dynamic table program headers found");
		}

		ElfSectionHeader[] dynamicSections = getSections(ElfSectionHeaderConstants.SHT_DYNAMIC);
		if (dynamicSections.length == 1) {

			ElfProgramHeader loadHeader =
				getProgramLoadHeaderContaining(dynamicSections[0].getAddress());
			if (loadHeader != null) {
				long dynamicTableOffset = loadHeader.getOffset() +
					(dynamicSections[0].getAddress() - loadHeader.getVirtualAddress());
				dynamicTable = ElfDynamicTable.createDynamicTable(reader, this, dynamicTableOffset,
					dynamicSections[0].getAddress());
				return;
			}
		}

	}

	private void parseStringTables() throws IOException {

		// identify dynamic symbol table address
		long dynamicStringTableAddr = -1;
		if (dynamicTable != null) {
			try {
				dynamicStringTableAddr =
					adjustAddressForPrelink(dynamicTable.getDynamicValue(ElfDynamicType.DT_STRTAB));
			}
			catch (NotFoundException e) {
				Msg.warn(this, "ELF does not contain a dynamic string table (DT_STRTAB)");
			}
		}

		ArrayList<ElfStringTable> stringTableList = new ArrayList<>();
		for (ElfSectionHeader stringTableSectionHeader : sectionHeaders) {
			if (stringTableSectionHeader.getType() == ElfSectionHeaderConstants.SHT_STRTAB) {
				ElfStringTable stringTable = ElfStringTable.createElfStringTable(reader, this,
					stringTableSectionHeader, stringTableSectionHeader.getOffset(),
					stringTableSectionHeader.getAddress(), stringTableSectionHeader.getSize());
				stringTableList.add(stringTable);
				if (stringTable.getAddressOffset() == dynamicStringTableAddr) {
					dynamicStringTable = stringTable;
				}
			}
		}

		if (dynamicStringTable == null && dynamicStringTableAddr != -1) {
			dynamicStringTable = parseDynamicStringTable(dynamicStringTableAddr);
			if (dynamicStringTable != null) {
				stringTableList.add(dynamicStringTable);
			}
		}

		stringTables = new ElfStringTable[stringTableList.size()];
		stringTableList.toArray(stringTables);
	}

	private ElfStringTable parseDynamicStringTable(long dynamicStringTableAddr) throws IOException {

		if (!dynamicTable.containsDynamicValue(ElfDynamicType.DT_STRSZ)) {
			Msg.warn(this, "Failed to parse DT_STRTAB, missing dynamic dependency");
			return null;
		}

		try {
			long stringTableSize = dynamicTable.getDynamicValue(ElfDynamicType.DT_STRSZ);

			if (dynamicStringTableAddr == 0) {
				Msg.warn(this, "ELF Dynamic String Table of size " + stringTableSize +
					" appears to have been stripped from binary");
				return null;
			}

			ElfProgramHeader stringTableLoadHeader =
				getProgramLoadHeaderContaining(dynamicStringTableAddr);
			if (stringTableLoadHeader == null) {
				Msg.warn(this, "Failed to locate DT_STRTAB in memory at 0x" +
					Long.toHexString(dynamicStringTableAddr));
				return null;
			}

			return ElfStringTable.createElfStringTable(reader, this, null,
				stringTableLoadHeader.getOffset(dynamicStringTableAddr), dynamicStringTableAddr,
				stringTableSize);
		}
		catch (NotFoundException e) {
			throw new AssertException(e);
		}
	}

	private void parseSymbolTables() throws IOException {

		// identify dynamic symbol table address
		long dynamicSymbolTableAddr = -1;
		if (dynamicTable != null) {
			try {
				dynamicSymbolTableAddr =
					adjustAddressForPrelink(dynamicTable.getDynamicValue(ElfDynamicType.DT_SYMTAB));
			}
			catch (NotFoundException e) {
				Msg.warn(this, "ELF does not contain a dynamic symbol table (DT_SYMTAB)");
			}
		}

		// Add section based symbol tables
		ArrayList<ElfSymbolTable> symbolTableList = new ArrayList<>();
		for (ElfSectionHeader symbolTableSectionHeader : sectionHeaders) {
			if (symbolTableSectionHeader.getType() == ElfSectionHeaderConstants.SHT_SYMTAB ||
				symbolTableSectionHeader.getType() == ElfSectionHeaderConstants.SHT_DYNSYM) {
				if (symbolTableSectionHeader.getOffset() < 0) {
					continue;
				}

				ElfSectionHeader stringTableSectionHeader =
					sectionHeaders[symbolTableSectionHeader.getLink()];
				ElfStringTable stringTable = getStringTable(stringTableSectionHeader);

				Msg.debug(this,
					"Elf symbol table section " + symbolTableSectionHeader.getNameAsString() +
						" linked to string table section " +
						stringTableSectionHeader.getNameAsString());

				boolean isDyanmic = ElfSectionHeaderConstants.dot_dynsym
						.equals(symbolTableSectionHeader.getNameAsString());

				ElfSymbolTable symbolTable = ElfSymbolTable.createElfSymbolTable(reader, this,
					symbolTableSectionHeader, symbolTableSectionHeader.getOffset(),
					symbolTableSectionHeader.getAddress(), symbolTableSectionHeader.getSize(),
					symbolTableSectionHeader.getEntrySize(), stringTable, isDyanmic);
				symbolTableList.add(symbolTable);
				if (symbolTable.getAddressOffset() == dynamicSymbolTableAddr) {
					dynamicSymbolTable = symbolTable; // remember dynamic symbol table
				}
			}
		}

		if (dynamicSymbolTable == null && dynamicSymbolTableAddr != -1) {
			dynamicSymbolTable = parseDynamicSymbolTable();
			if (dynamicSymbolTable != null) {
				symbolTableList.add(dynamicSymbolTable);
			}
		}

		symbolTables = new ElfSymbolTable[symbolTableList.size()];
		symbolTableList.toArray(symbolTables);
	}

	private ElfSymbolTable parseDynamicSymbolTable() throws IOException {

		if (!dynamicTable.containsDynamicValue(ElfDynamicType.DT_SYMTAB) ||
			!dynamicTable.containsDynamicValue(ElfDynamicType.DT_SYMENT) ||
			!(dynamicTable.containsDynamicValue(ElfDynamicType.DT_HASH) ||
				dynamicTable.containsDynamicValue(ElfDynamicType.DT_GNU_HASH))) {
			if (dynamicStringTable != null) {
				Msg.warn(this, "Failed to parse DT_SYMTAB, missing dynamic dependency");
			}
			return null;
		}

		try {

			long tableAddr = dynamicTable.getDynamicValue(ElfDynamicType.DT_SYMTAB);
			if (tableAddr == 0) {
				Msg.warn(this,
					"ELF Dynamic String Table of size appears to have been stripped from binary");
			}

			if (dynamicStringTable == null) {
				Msg.warn(this, "Failed to process DT_SYMTAB, missing dynamic string table");
				return null;
			}

			if (tableAddr == 0) {
				return null;
			}

			tableAddr = adjustAddressForPrelink(tableAddr);
			long tableEntrySize = dynamicTable.getDynamicValue(ElfDynamicType.DT_SYMENT);

			// Use dynamic symbol hash table DT_HASH or DT_GNU_HASH to determine symbol table count/length
			boolean useGnuHash = dynamicTable.containsDynamicValue(ElfDynamicType.DT_GNU_HASH);
			long hashTableAddr =
				useGnuHash ? dynamicTable.getDynamicValue(ElfDynamicType.DT_GNU_HASH)
						: dynamicTable.getDynamicValue(ElfDynamicType.DT_HASH);
			hashTableAddr = adjustAddressForPrelink(hashTableAddr);

			ElfProgramHeader symbolTableLoadHeader = getProgramLoadHeaderContaining(tableAddr);
			if (symbolTableLoadHeader == null) {
				Msg.warn(this,
					"Failed to locate DT_SYMTAB in memory at 0x" + Long.toHexString(tableAddr));
				return null;
			}
			ElfProgramHeader hashTableLoadHeader = getProgramLoadHeaderContaining(hashTableAddr);
			if (hashTableLoadHeader == null) {
				Msg.warn(this, "Failed to locate DT_HASH or DT_GNU_HASH in memory at 0x" +
					Long.toHexString(hashTableAddr));
				return null;
			}

			// Create dynamic symbol table if not defined as a section
			long symbolTableOffset = symbolTableLoadHeader.getOffset(tableAddr);

			// determine symbol count from dynamic symbol hash table
			int symCount;
			long symbolHashTableOffset = hashTableLoadHeader.getOffset(hashTableAddr);
			if (useGnuHash) {
				symCount = deriveGnuHashDynamicSymbolCount(symbolHashTableOffset);
			}
			else {
				// DT_HASH table, nchain corresponds is same as symbol count
				symCount = reader.readInt(symbolHashTableOffset + 4); // nchain from DT_HASH
			}

			return ElfSymbolTable.createElfSymbolTable(reader, this, null, symbolTableOffset,
				tableAddr, tableEntrySize * symCount, tableEntrySize, dynamicStringTable, true);
		}
		catch (NotFoundException e) {
			throw new AssertException(e);
		}
	}

	/**
	 * Walk DT_GNU_HASH table to determine dynamic symbol count
	 * @param DT_GNU_HASH table file offset
	 * @return dynamic symbol count
	 * @throws IOException file read error
	 */
	private int deriveGnuHashDynamicSymbolCount(long gnuHashTableOffset) throws IOException {
		int numBuckets = reader.readInt(gnuHashTableOffset);
		int symbolBase = reader.readInt(gnuHashTableOffset + 4);
		int bloomSize = reader.readInt(gnuHashTableOffset + 8);
		// int bloomShift = reader.readInt(gnuHashTableOffset + 12);
		int bloomWordSize = is64Bit() ? 8 : 4;
		long bucketsOffset = gnuHashTableOffset + 16 + (bloomWordSize * bloomSize);

		long bucketOffset = bucketsOffset;
		int maxSymbolIndex = 0;
		for (int i = 0; i < numBuckets; i++) {
			int symbolIndex = reader.readInt(bucketOffset);
			if (symbolIndex > maxSymbolIndex) {
				maxSymbolIndex = symbolIndex;
			}
			bucketOffset += 4;
		}

		int chainIndex = maxSymbolIndex - symbolBase;

		++maxSymbolIndex;
		long chainOffset = bucketOffset + (4 * chainIndex); // chains immediately follow buckets
		while (true) {
			int chainValue = reader.readInt(chainOffset);
			if ((chainValue & 1) != 0) {
				break;
			}
			++maxSymbolIndex;
			chainOffset += 4;
		}
		return maxSymbolIndex;
	}

	protected void parseSectionHeaders() throws IOException {
		if (reader == null) {
			throw new IOException("ELF binary reader is null!");
		}
		if (parsedSectionHeaders) {
			return;
		}

		parsedSectionHeaders = true;
		sectionHeaders = new ElfSectionHeader[e_shnum];
		for (int i = 0; i < e_shnum; ++i) {
			long index = e_shoff + (i * e_shentsize);
			reader.setPointerIndex(index);
			sectionHeaders[i] = ElfSectionHeader.createElfSectionHeader(reader, this);
		}

		//note: we cannot retrieve all the names
		//until after we have read all the section headers.
		//this is because one of the section headers 
		//is a string table that contains the names of the sections.
		for (int i = 0; i < e_shnum; ++i) {
			sectionHeaders[i].updateName();
		}
	}

	private void parseProgramHeaders() throws IOException {
		long fileLength = reader.length();
		programHeaders = new ElfProgramHeader[e_phnum];
		for (int i = 0; i < e_phnum; ++i) {
			long index = e_phoff + (i * e_phentsize);
			reader.setPointerIndex(index);
			programHeaders[i] = ElfProgramHeader.createElfProgramHeader(reader, this);
		}

		// TODO: Find sample file which requires this hack to verify its necessity
		// HACK: 07/01/2013 - Added hack for malformed ELF file with only program header sections
		ElfProgramHeader[] pheaders = getProgramHeaders();
		long size = 0;
		for (ElfProgramHeader pheader : pheaders) {
			size += pheader.getFileSize();
		}
		if (size == fileLength) {
			// adjust program section file offset to be based on relative read offset
			long relOffset = 0;
			for (ElfProgramHeader pheader : pheaders) {
				pheader.setOffset(relOffset);
				relOffset += pheader.getFileSize();
			}
		}
	}

	/**
	 * Returns true if this ELF was created for a big endian processor.
	 * @return true if this ELF was created for a big endian processor
	 */
	public boolean isBigEndian() {
		return e_ident_data == ElfConstants.ELF_DATA_BE;
	}

	/**
	 * Returns true if this ELF was created for a little endian processor.
	 * @return true if this ELF was created for a little endian processor
	 */
	public boolean isLittleEndian() {
		return e_ident_data == ElfConstants.ELF_DATA_LE;
	}

	/**
	 * Returns true if this ELF was created for a 32-bit processor.
	 * @return true if this ELF was created for a 32-bit processor
	 */
	public boolean is32Bit() {
		return e_ident_class == ElfConstants.ELF_CLASS_32;
	}

	/**
	 * Returns true if this ELF was created for a 64-bit processor.
	 * @return true if this ELF was created for a 64-bit processor
	 */
	public boolean is64Bit() {
		return e_ident_class == ElfConstants.ELF_CLASS_64;
	}

	private long getMinBase(long addr, long minBase) {
		if (is32Bit()) {
			addr &= Conv.INT_MASK;
		}
		if (Long.compareUnsigned(addr, minBase) < 0) {
			minBase = addr;
		}
		return minBase;
	}

	/**
	 * Inspect the Elf image and determine the default image base prior 
	 * to the {@link #parse()} method being invoked (i.e., only the main Elf
	 * header structure has been parsed).
	 * The image base is the virtual address of the PT_LOAD program header
	 * with the smallest address or 0 if no program headers exist.  By default,
	 * the image base address should be treated as a addressable unit offset.
	 * @return preferred image base 
	 */
	public long findImageBase() {

		// FIXME! This needs to be consistent with the getImageBase() method
		// which currently considers prelink. 

		long minBase = -1;

		int n = Math.min(e_phnum, MAX_HEADERS_TO_CHECK_FOR_IMAGEBASE);
		for (int i = 0; i < n; ++i) {
			long index = e_phoff + (i * e_phentsize);
			reader.setPointerIndex(index);
			try {
				int headerType = reader.peekNextInt();
				if (headerType == ElfProgramHeaderConstants.PT_LOAD) {
					ElfProgramHeader header = ElfProgramHeader.createElfProgramHeader(reader, this);
					minBase = getMinBase(header.getVirtualAddress(), minBase);
				}
			}
			catch (IOException e) {
				// skip
			}
		}
		return minBase == -1 ? 0 : minBase;
	}

	private Long elfImageBase;

	/**
	 * Returns the image base of this ELF. 
	 * The image base is the virtual address of the first PT_LOAD
	 * program header or 0 if no program headers. By default,
	 * the image base address should be treated as a addressable unit offset.s
	 * @return the image base of this ELF
	 */
	public long getImageBase() {
		if (elfImageBase != null) {
			return elfImageBase;
		}

		elfImageBase = 0L;

		long base = getPreLinkImageBase();
		if (base != -1) {
			elfImageBase = base;
		}
		else {
			int n = Math.min(programHeaders.length, MAX_HEADERS_TO_CHECK_FOR_IMAGEBASE);
			long minBase = -1;
			for (int i = 0; i < n; i++) {
				ElfProgramHeader header = programHeaders[i];
				if (programHeaders[i].getType() == ElfProgramHeaderConstants.PT_LOAD) {
					minBase = getMinBase(header.getVirtualAddress(), minBase);
				}
			}
			elfImageBase = (minBase == -1 ? 0 : minBase);
		}
		return elfImageBase;
	}

	/**
	 * Determine if the image has been pre-linked.
	 * NOTE: Currently has very limited support.  Certain pre-link
	 * cases can not be detected until after a full parse has been 
	 * performed.
	 * @return true if image has been pre-linked
	 */
	public boolean isPreLinked() {
		if (getPreLinkImageBase() != -1L) {
			return true;
		}
		if (dynamicTable != null) {
			if (dynamicTable.containsDynamicValue(ElfDynamicType.DT_GNU_PRELINKED)) {
				return true;
			}
		}
		return false;
	}

	private Long preLinkImageBase = null;

	/**
	 *  Some elfs can get pre-linked to an OS.
	 *     At the very end a "PRE " string is appended with the image base load address
	 *     set.  Try there if none of the images told us where to load.
	 * @return -1 - if the imagebase is not a pre-link image base.
	 */
	private long getPreLinkImageBase() {
		if (preLinkImageBase != null) {
			return preLinkImageBase;
		}
		preLinkImageBase = -1L;
		try {
			long ptr = reader.getPointerIndex();

			long fileLength = reader.getByteProvider().length();

			// not enough bytes
			if (fileLength < 8) {
				return -1;
			}
			//reader.setPointerIndex(fileLength - 8);
			int readInt = reader.readInt(fileLength - 8);
			String readAsciiString = reader.readAsciiString(fileLength - 4, 4);

			if (reader.getPointerIndex() != ptr) {
				reader.setPointerIndex(ptr);
			}

			if (readAsciiString.equals("PRE")) {
				preLinkImageBase = (readInt) & 0xffffffffL;
			}
		}
		catch (IOException e) {
			Msg.error(this, "Elf prelink read failure", e);
		}
		return preLinkImageBase;
	}

	public boolean isSectionLoaded(ElfSectionHeader section) {
		if (section.getType() == ElfSectionHeaderConstants.SHT_NULL) {
			return false;
		}
		long sectionStart = section.getAddress();
		if (sectionStart == 0) {
			return false;
		}
		long sectionEnd = section.getSize() - 1 + sectionStart;
		for (ElfProgramHeader segment : programHeaders) {
			if (segment.getType() != ElfProgramHeaderConstants.PT_LOAD) {
				continue;
			}
			long segmentStart = segment.getVirtualAddress();
			long segmentEnd = segment.getMemorySize() - 1 + segmentStart;
			if (segmentStart <= sectionStart && segmentEnd >= sectionEnd) {
				return true;
			}
		}
		return false;
	}

	private void determineHeaderEndianess(ByteProvider provider) throws ElfException, IOException {

		if (provider.length() < INITIAL_READ_LEN) {
			throw new ElfException("Not enough bytes to be a valid ELF executable.");
		}

		hasLittleEndianHeaders = true;
		byte[] bytes = provider.readBytes(0, INITIAL_READ_LEN);
		if (bytes[ElfConstants.EI_DATA] == ElfConstants.ELF_DATA_BE) {
			hasLittleEndianHeaders = false;
		}
		else if (bytes[ElfConstants.EI_DATA] != ElfConstants.ELF_DATA_LE) {
			throw new ElfException("Unsupported Elf Header");
		}
		if (!hasLittleEndianHeaders && bytes[ElfConstants.EI_NIDENT] != 0) {
			// Header endianess sanity check
			// Some toolchains always use little endian Elf Headers

			// TODO: unsure if forced endianess applies to relocation data

			// Check first byte of version (allow switch if equal 1)
			if (bytes[ElfConstants.EI_NIDENT + 4] == 1) {
				hasLittleEndianHeaders = true;
			}
		}
	}

	/**
	 * This member holds the ELF header's size in bytes.
	 * @return the ELF header's size in bytes
	 */
	public short e_ehsize() {
		return e_ehsize;
	}

	/**
	 * This member gives the virtual address to which the system first transfers control, thus
	 * starting the process. If the file has no associated entry point, this member holds zero.
	 * @return the virtual address to which the system first transfers control
	 */
	public long e_entry() {
		// guard against adjustment of 0
		// TODO: this might need to be re-thought.  
		if (e_entry == 0) {
			return 0;
		}
		return adjustAddressForPrelink(e_entry);
	}

	/**
	 * This member holds processor-specific flags associated with the file. Flag names take
	 * the form EF_machine_flag.
	 * @return the processor-specific flags associated with the file
	 * @see ElfConstants for flag definitions
	 */
	public int e_flags() {
		return e_flags;
	}

	/**
	 * This member's value specifies the required architecture for an individual file.
	 * @return the required architecture for an individual file
	 * @see ElfConstants for machine definitions
	 */
	public short e_machine() {
		return e_machine;
	}

	/**
	 * This member identifies the target operating system and ABI.
	 * @return the target operating system and ABI
	 */
	public byte e_ident_osabi() {
		return e_ident_osabi;
	}

	/**
	 * This member identifies the target ABI version.
	 * @return the target ABI version
	 */
	public byte e_ident_abiversion() {
		return e_ident_abiversion;
	}

	/**
	 * This member holds the size in bytes of one entry in the file's program header table;
	 * all entries are the same size.
	 * @return the size in bytes of one program header table entry 
	 */
	public short e_phentsize() {
		return e_phentsize;
	}

	/**
	 * This member holds the number of entries in the program header table. Thus the product
	 * of e_phentsize and e_phnum gives the table's size in bytes. If a file has no program
	 * header table, e_phnum holds the value zero.
	 * @return the number of entries in the program header table
	 */
	public short e_phnum() {
		return e_phnum;
	}

	/**
	 * This member holds the program header table's file offset in bytes. If the file has no
	 * program header table, this member holds zero.
	 * @return the program header table's file offset in bytes
	 */
	public long e_phoff() {
		return e_phoff;
	}

	/**
	 * This member holds the section header's size in bytes. A section header is one entry in
	 * the section header table; all entries are the same size.
	 * @return the section header's size in bytes
	 */
	public short e_shentsize() {
		return e_shentsize;
	}

	/**
	 * This member holds the number of entries in the section header table. Thus the product
	 * of e_shentsize and e_shnum gives the section header table's size in bytes. If a file
	 * has no section header table, e_shnum holds the value zero.
	 * @return the number of entries in the section header table
	 */
	public short e_shnum() {
		return e_shnum;
	}

	/**
	 * This member holds the section header table's file offset in bytes. If the file has no section
	 * header table, this member holds zero.
	 * @return the section header table's file offset in bytes
	 */
	public long e_shoff() {
		return e_shoff;
	}

	/**
	 * This member holds the section header table index of the entry associated with the section
	 * name string table. If the file has no section name string table, this member holds
	 * the value SHN_UNDEF.
	 * @return the section header table index of the entry associated with the section name string table
	 */
	public short e_shstrndx() {
		return e_shstrndx;
	}

	/**
	 * This member identifies the object file type; executable, shared object, etc.
	 * @return the object file type
	 */
	public short e_type() {
		return e_type;
	}

	/**
	 * Returns true if this is a relocatable file.
	 * <br>
	 * e_type == NewElfHeaderConstants.ET_REL
	 * @return true if this is a relocatable file
	 */
	public boolean isRelocatable() {
		return e_type == ElfConstants.ET_REL;
	}

	/**
	 * Returns true if this is a shared object file.
	 * <br>
	 * e_type == NewElfHeaderConstants.ET_DYN
	 * @return true if this is a shared object file
	 */
	public boolean isSharedObject() {
		return e_type == ElfConstants.ET_DYN;
	}

	/**
	 * Returns true if this is an executable file.
	 * <br>
	 * e_type == NewElfHeaderConstants.ET_EXEC
	 * @return true if this is a executable file
	 */
	public boolean isExecutable() {
		return e_type == ElfConstants.ET_EXEC;
	}

	/**
	 * This member identifies the object file version,
	 * where "EV_NONE == Invalid Version" and "EV_CURRENT == Current Version"
	 * The value 1 signifies the original file format; extensions will 
	 * create new versions with higher numbers. 
	 * The value of EV_CURRENT, though given as 1 above, will change as
	 * necessary to reflect the current version number.
	 * @return the object file version
	 */
	public int e_version() {
		return e_version;
	}

	/**
	 * Returns the section headers as defined in this ELF file.
	 * @return the section headers as defined in this ELF file
	 */
	public ElfSectionHeader[] getSections() {
		return sectionHeaders;
	}

	/**
	 * Returns the section headers with the specified type.
	 * The array could be zero-length, but will not be null.
	 * @param type
	 * @return the section headers with the specified type
	 * @see ElfSectionHeader
	 */
	public ElfSectionHeader[] getSections(int type) {
		ArrayList<ElfSectionHeader> list = new ArrayList<>();
		for (ElfSectionHeader sectionHeader : sectionHeaders) {
			if (sectionHeader.getType() == type) {
				list.add(sectionHeader);
			}
		}
		ElfSectionHeader[] sections = new ElfSectionHeader[list.size()];
		list.toArray(sections);
		return sections;
	}

	/**
	 * Returns the section header with the specified name, or null
	 * if no section exists with that name.
	 * @param name the name of the requested section
	 * @return the section header with the specified name
	 */
	public ElfSectionHeader getSection(String name) {
		List<ElfSectionHeader> list = new ArrayList<>();
		for (ElfSectionHeader sectionHeader : sectionHeaders) {
			if (name != null && name.equals(sectionHeader.getNameAsString())) {
				list.add(sectionHeader);
			}
		}
		if (list.size() == 0) {
			return null;
		}
		if (list.size() > 1) {
			throw new RuntimeException(">1 section with name of " + name);
		}
		return list.get(0);
	}

	/**
	 * Returns the section header at the specified address,
	 * or null if no section exists at that address.
	 * @param address the address of the requested section
	 * @return the section header with the specified address
	 */
	public ElfSectionHeader getSectionAt(long address) {
		for (ElfSectionHeader sectionHeader : sectionHeaders) {
			if (sectionHeader.getAddress() == address) {
				return sectionHeader;
			}
		}
		return null;
	}

	/**
	 * Returns the section header that loads/contains the specified address,
	 * or null if no section contains the address.
	 * @param address the address of the requested section
	 * @return the section header that contains the address
	 */
	public ElfSectionHeader getSectionLoadHeaderContaining(long address) {
// FIXME: verify 
		for (ElfSectionHeader sectionHeader : sectionHeaders) {
			if (!sectionHeader.isAlloc()) {
				continue;
			}
			long start = sectionHeader.getAddress();
			long end = start + sectionHeader.getSize();
			if (start <= address && address <= end) {
				return sectionHeader;
			}
		}
		return null;
	}

	/**
	 * Returns the section header which fully contains the specified file offset range.
	 * @param fileOffset file offset
	 * @param fileRangeLength length of file range in bytes
	 * @return section or null if not found
	 */
	public ElfSectionHeader getSectionHeaderContainingFileRange(long fileOffset,
			long fileRangeLength) {
		long maxOffset = fileOffset + fileRangeLength - 1;
		for (ElfSectionHeader section : sectionHeaders) {
			if (section.getType() == ElfSectionHeaderConstants.SHN_UNDEF) {
				continue;
			}
			long size = section.getSize();
			if (size == 0) {
				continue;
			}
			long start = section.getOffset();
			long end = start + size - 1;
			if (fileOffset >= start && maxOffset <= end) {
				return section;
			}
		}
		return null;
	}

	/**
	 * Returns the index of the specified section.
	 * The index is the order in which the section was
	 * defined in the section header table.
	 * @param section the section header
	 * @return the index of the specified section header
	 */
	public int getSectionIndex(ElfSectionHeader section) {
		for (int i = 0; i < sectionHeaders.length; i++) {
			if (sectionHeaders[i] == section) {
				return i;
			}
		}
		throw new RuntimeException("Section not located.");
	}

	/**
	 * Returns the program headers as defined in this ELF file.
	 * @return the program headers as defined in this ELF file
	 */
	public ElfProgramHeader[] getProgramHeaders() {
		return programHeaders;
	}

	/**
	 * Returns the program headers with the specified type.
	 * The array could be zero-length, but will not be null.
	 * @param type
	 * @return the program headers with the specified type
	 * @see ElfProgramHeader
	 */
	public ElfProgramHeader[] getProgramHeaders(int type) {
		ArrayList<ElfProgramHeader> list = new ArrayList<>();
		for (ElfProgramHeader programHeader : programHeaders) {
			if (programHeader.getType() == type) {
				list.add(programHeader);
			}
		}
		ElfProgramHeader[] arr = new ElfProgramHeader[list.size()];
		list.toArray(arr);
		return arr;
	}

	/**
	 * Returns the dynamic table defined by program header of type PT_DYNAMIC or the .dynamic program section.
	 * Or, null if one does not exist.
	 * @return the dynamic table
	 */
	public ElfDynamicTable getDynamicTable() {
		return dynamicTable;
	}

	/**
	 * Returns the program header with type of PT_PHDR.
	 * Or, null if one does not exist.
	 * @return the program header with type of PT_PHDR
	 */
	public ElfProgramHeader getProgramHeaderProgramHeader() {
		ElfProgramHeader[] pharr = getProgramHeaders(ElfProgramHeaderConstants.PT_PHDR);
		if (pharr.length == 0 || pharr.length > 1) {
			return null;
			//throw new RuntimeException("Unable to locate PT_PHDR program header");
		}
		return pharr[0];
	}

	/**
	 * Returns the program header at the specified address,
	 * or null if no program header exists at that address.
	 * @param virtualAddr the address of the requested program header
	 * @return the program header with the specified address
	 */
	public ElfProgramHeader getProgramHeaderAt(long virtualAddr) {
		for (ElfProgramHeader programHeader : programHeaders) {
			if (programHeader.getVirtualAddress() == virtualAddr) {
				return programHeader;
			}
		}
		return null;
	}

	/**
	 * Returns the PT_LOAD program header which loads a range containing 
	 * the specified address, or null if not found.
	 * @param virtualAddr the address of the requested program header
	 * @return the program header with the specified address
	 */
	public ElfProgramHeader getProgramLoadHeaderContaining(long virtualAddr) {
		for (ElfProgramHeader programHeader : programHeaders) {
			if (programHeader == null ||
				programHeader.getType() != ElfProgramHeaderConstants.PT_LOAD) {
				continue;
			}
			long start = programHeader.getVirtualAddress();
			long end = programHeader.getAdjustedMemorySize() - 1 + start;
			if (virtualAddr >= start && virtualAddr <= end) {
				return programHeader;
			}
		}
		return null;
	}

	/**
	 * Returns the PT_LOAD program header which loads a range containing 
	 * the specified file offset, or null if not found.
	 * @param offset the file offset to be loaded
	 * @return the program header with the specified file offset
	 */
	public ElfProgramHeader getProgramLoadHeaderContainingFileOffset(long offset) {
		for (ElfProgramHeader programHeader : programHeaders) {
			if (programHeader == null ||
				programHeader.getType() != ElfProgramHeaderConstants.PT_LOAD) {
				continue;
			}
			long start = programHeader.getOffset();
			long end = start + (programHeader.getFileSize() - 1);
			if (offset >= start && offset <= end) {
				return programHeader;
			}
		}
		return null;
	}

	/**
	 * Returns array of dynamic library names defined by DT_NEEDED
	 * @return array of dynamic library names
	 */
	public String[] getDynamicLibraryNames() {
		return dynamicLibraryNames;
	}

	/**
	 * Returns the dynamic string table as defined in this ELF file.
	 * @return the dynamic string table as defined in this ELF file
	 */
	public ElfStringTable getDynamicStringTable() {
		return dynamicStringTable;
	}

	/**
	 * Returns the string tables as defined in this ELF file.
	 * @return the string tables as defined in this ELF file
	 */
	public ElfStringTable[] getStringTables() {
		return stringTables;
	}

	/**
	 * Returns the string table associated to the specified section header.
	 * Or, null if one does not exist.
	 * @return the string table associated to the specified section header
	 */
	public ElfStringTable getStringTable(ElfSectionHeader section) {
		for (ElfStringTable stringTable : stringTables) {
			if (stringTable.getFileOffset() == section.getOffset()) {
				return stringTable;
			}
		}
		return null;
	}

	/**
	 * Returns the dynamic symbol table as defined in this ELF file.
	 * @return the dynamic symbol table as defined in this ELF file
	 */
	public ElfSymbolTable getDynamicSymbolTable() {
		return dynamicSymbolTable;
	}

	/**
	 * Returns the symbol tables as defined in this ELF file.
	 * @return the symbol tables as defined in this ELF file
	 */
	public ElfSymbolTable[] getSymbolTables() {
		return symbolTables;
	}

	/**
	 * Returns the symbol table associated to the specified section header.
	 * Or, null if one does not exist.
	 * @return the symbol table associated to the specified section header
	 */
	public ElfSymbolTable getSymbolTable(ElfSectionHeader symbolTableSection) {
		if (symbolTableSection == null) {
			return null;
		}
		for (ElfSymbolTable symbolTable : symbolTables) {
			if (symbolTable.getFileOffset() == symbolTableSection.getOffset()) {
				return symbolTable;
			}
		}
		return null;
	}

	/**
	 * Returns the relocation tables as defined in this ELF file.
	 * @return the relocation tables as defined in this ELF file
	 */
	public ElfRelocationTable[] getRelocationTables() {
		return relocationTables;
	}

	/**
	 * Returns the relocation table associated to the specified section header,
	 * or null if one does not exist.
	 * @param relocSection section header corresponding to relocation table
	 * @return the relocation table associated to the specified section header
	 */
	public ElfRelocationTable getRelocationTable(ElfSectionHeader relocSection) {
		return getRelocationTableAtOffset(relocSection.getOffset());
	}

	/**
	 * Returns the relocation table located at the specified fileOffset,
	 * or null if one does not exist.
	 * @param fileOffset file offset corresponding to start of relocation table
	 * @return the relocation table located at the specified fileOffset or null
	 */
	public ElfRelocationTable getRelocationTableAtOffset(long fileOffset) {
		for (ElfRelocationTable relocationTable : relocationTables) {
			if (relocationTable.getFileOffset() == fileOffset) {
				return relocationTable;
			}
		}
		return null;
	}

	/**
	 * Returns a string name of the processor specified in this ELF header.
	 * For example, if "e_machine==EM_386", then it returns "80386".
	 * @return a string name of the processor specified in this ELF header
	 */
	public String getMachineName() {
		return Short.toString(e_machine);
	}

	/**
	 * Returns a string representation of the numeric flags field.
	 * @return elf flags field value
	 */
	public String getFlags() {
		return Integer.toString(e_flags);
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	@Override
	public DataType toDataType() {
		if (headerStructure != null) {
			return headerStructure;
		}
		String name = is32Bit() ? "Elf32_Ehdr" : "Elf64_Ehdr";
		headerStructure = new StructureDataType(new CategoryPath("/ELF"), name, 0);
		headerStructure.add(BYTE, "e_ident_magic_num", null);
		headerStructure.add(STRING, e_ident_magic_str.length(), "e_ident_magic_str", null);
		headerStructure.add(BYTE, "e_ident_class", null);
		headerStructure.add(BYTE, "e_ident_data", null);
		headerStructure.add(BYTE, "e_ident_version", null);
		headerStructure.add(BYTE, "e_ident_osabi", null);
		headerStructure.add(BYTE, "e_ident_abiversion", null);
		headerStructure.add(new ArrayDataType(BYTE, PAD_LENGTH, 1), "e_ident_pad", null);
		headerStructure.add(WORD, "e_type", null);
		headerStructure.add(WORD, "e_machine", null);
		headerStructure.add(DWORD, "e_version", null);

		if (is32Bit()) {
			headerStructure.add(DWORD, "e_entry", null);
			headerStructure.add(DWORD, "e_phoff", null);
			headerStructure.add(DWORD, "e_shoff", null);
		}
		else {
			headerStructure.add(QWORD, "e_entry", null);
			headerStructure.add(QWORD, "e_phoff", null);
			headerStructure.add(QWORD, "e_shoff", null);
		}

		headerStructure.add(DWORD, "e_flags", null);
		headerStructure.add(WORD, "e_ehsize", null);
		headerStructure.add(WORD, "e_phentsize", null);
		headerStructure.add(WORD, "e_phnum", null);
		headerStructure.add(WORD, "e_shentsize", null);
		headerStructure.add(WORD, "e_shnum", null);
		headerStructure.add(WORD, "e_shstrndx", null);
		return headerStructure;
	}

	/**
	 * Get the Elf header structure component ordinal 
	 * corresponding to the e_entry element
	 * @return e_entry component ordinal 
	 */
	public int getEntryComponentOrdinal() {
		return 11;
	}

	/**
	 * Get the Elf header structure component ordinal 
	 * corresponding to the e_phoff element
	 * @return e_phoff component ordinal 
	 */
	public int getPhoffComponentOrdinal() {
		return 12;
	}

	/**
	 * Get the Elf header structure component ordinal 
	 * corresponding to the e_shoff element
	 * @return e_shoff component ordinal 
	 */
	public int getShoffComponentOrdinal() {
		return 13;
	}

	private void addSection(ElfSectionHeader newSection) {
		++e_shnum;

		ElfSectionHeader[] tmp = new ElfSectionHeader[e_shnum];
		System.arraycopy(sectionHeaders, 0, tmp, 0, sectionHeaders.length);
		sectionHeaders = tmp;

		sectionHeaders[e_shnum - 1] = newSection;

		if (e_shnum != sectionHeaders.length) {
			throw new IllegalStateException();
		}
	}

	/**
	 * Adds a new section using the specified memory block.
	 * The memory block is used to setting the address and size.
	 * As well as, setting the data.
	 * @param block the memory block
	 * @param sh_name the byte index into the string table where the name begins
	 * @return the newly created section
	 * @throws MemoryAccessException if any of the requested memory block bytes are uninitialized.
	 */
	public ElfSectionHeader addSection(MemoryBlock block, int sh_name)
			throws MemoryAccessException {
		ElfSectionHeader newSection = new ElfSectionHeader(this, block, sh_name, getImageBase());
		addSection(newSection);
		return newSection;
	}

	/**
	 * Adds a new section the specifed name and name index.
	 * The type of the section will be SHT_PROGBITS.
	 * @param name the actual name of the new section
	 * @param sh_name the byte index into the string table where the name begins
	 * @return the newly created section
	 */
	public ElfSectionHeader addSection(String name, int sh_name) {
		return addSection(name, sh_name, ElfSectionHeaderConstants.SHT_PROGBITS);
	}

	/**
	 * Adds a new section the specifed name and name index.
	 * The type of the section will be SHT_PROGBITS.
	 * @param name the actual name of the new section
	 * @param sh_name the byte index into the string table where the name begins
	 * @param type the type of the new section
	 * @return the newly created section
	 */
	public ElfSectionHeader addSection(String name, int sh_name, int type) {
		ElfSectionHeader newSection = new ElfSectionHeader(this, name, sh_name, type);
		addSection(newSection);
		return newSection;
	}

	/**
	 * Appends the new program header to the end of the existing
	 * program header table.
	 * @param ph the new program header
	 */
	public void addProgramHeader(ElfProgramHeader ph) {
		ElfProgramHeader[] tmp = new ElfProgramHeader[e_phnum + 1];

		int pos = tmp.length - 1;

		boolean firstLoad = true;
		int firstLoadPos = -1;

		/*PT_LOAD segments must be inserted in sorted order*/
		if (ph.getType() == ElfProgramHeaderConstants.PT_LOAD) {
			for (int i = 0; i < programHeaders.length - 1; ++i) {
				if (programHeaders[i].getType() == ElfProgramHeaderConstants.PT_LOAD) {
					if (firstLoad) {
						firstLoad = false;
						firstLoadPos = i;
					}
					pos = i;
				}
			}
			++pos;
		}

		System.arraycopy(programHeaders, 0, tmp, 0, pos);
		tmp[pos] = ph;
		System.arraycopy(programHeaders, pos, tmp, pos + 1, programHeaders.length - pos);

		if (ph.getType() == ElfProgramHeaderConstants.PT_LOAD) {
			Arrays.sort(tmp, firstLoadPos, pos + 1);
		}

		programHeaders = tmp;

		++e_phnum;

		if (e_phnum != programHeaders.length) {
			throw new IllegalStateException();
		}
	}

	/**
	 * @see ghidra.app.util.bin.format.Writeable#write(java.io.RandomAccessFile, ghidra.util.DataConverter)
	 */
	@Override
	public void write(RandomAccessFile raf, DataConverter dc) throws IOException {
		raf.seek(0);
		raf.writeByte(e_ident_magic_num);
		raf.write(e_ident_magic_str.getBytes());
		raf.writeByte(e_ident_class);
		raf.writeByte(e_ident_data);
		raf.writeByte(e_ident_version);
		raf.writeByte(e_ident_osabi);
		raf.writeByte(e_ident_abiversion);
		raf.write(e_ident_pad);
		raf.write(dc.getBytes(e_type));
		raf.write(dc.getBytes(e_machine));
		raf.write(dc.getBytes(e_version));

		if (is32Bit()) {
			raf.write(dc.getBytes((int) e_entry));
			raf.write(dc.getBytes((int) e_phoff));
			raf.write(dc.getBytes((int) e_shoff));
		}
		else if (is64Bit()) {
			raf.write(dc.getBytes(e_entry));
			raf.write(dc.getBytes(e_phoff));
			raf.write(dc.getBytes(e_shoff));
		}

		raf.write(dc.getBytes(e_flags));
		raf.write(dc.getBytes(e_ehsize));
		raf.write(dc.getBytes(e_phentsize));
		raf.write(dc.getBytes(e_phnum));
		raf.write(dc.getBytes(e_shentsize));
		raf.write(dc.getBytes(e_shnum));
		raf.write(dc.getBytes(e_shstrndx));
	}

	/**
	 * Sets the section header offset.
	 * @param offset the new section header offset
	 */
	public void setSectionHeaderOffset(long offset) {
		this.e_shoff = offset;
	}

	/**
	 * Sets the program header offset.
	 * @param offset the new program header offset
	 */
	public void setProgramHeaderOffset(long offset) {
		this.e_phoff = offset;
	}

}
