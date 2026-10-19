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
import java.util.*;
import java.util.function.Consumer;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.elf.ElfRelocationTable.TableFormat;
import ghidra.app.util.bin.format.elf.extend.ElfExtensionFactory;
import ghidra.app.util.bin.format.elf.extend.ElfLoadAdapter;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.NotFoundException;

/**
 * A class to represent the Executable and Linking Format (ELF)
 * header and specification.
 */
public class ElfHeader implements StructConverter {

	private static final int MAX_HEADERS_TO_CHECK_FOR_IMAGEBASE = 20;

	private static final int PAD_LENGTH = 7;
	
	static final long FILE_OFFSET_HARD_LIMIT = 0x00007FFFFFFFFFFFL;

	private HashMap<Integer, ElfProgramHeaderType> programHeaderTypeMap;
	private HashMap<Integer, ElfSectionHeaderType> sectionHeaderTypeMap;
	private HashMap<Integer, ElfDynamicType> dynamicTypeMap;

	private final ByteProvider provider; // original byte provider
	private final BinaryReader reader; // unlimited reader

	@SuppressWarnings("unused")
	private final byte e_ident_magic_num; //magic number
	private final String e_ident_magic_str; //magic string
	private final byte e_ident_class; //file class
	private final byte e_ident_data; //data encoding
	@SuppressWarnings("unused")
	private final byte e_ident_version; //file version
	private final byte e_ident_osabi; //operating system and abi
	private final byte e_ident_abiversion; //abi version
	@SuppressWarnings("unused")
	private final byte[] e_ident_pad; //padding
	private final short e_type; //object file type
	private final short e_machine; //target architecture
	private final int e_version; //object file version
	private final long e_entry; //executable entry point
	private final long e_phoff; //program header table offset
	private final long e_shoff; //section header table offset
	private final int e_flags; //processor-specific flags
	private final short e_ehsize; //elf header size
	private final short e_phentsize; //size of entries in the program header table
	private final int e_phnum; //number of entries in the program header table (may be extended and may not be preserved)
	private final short e_shentsize; //size of entries in the section header table
	private final int e_shnum; //number of entries in the section header table (may be extended and may not be preserved)
	private final int e_shstrndx; //section index of the section name string table (may be extended and may not be preserved)

	private boolean phnumTruncated = false;
	private boolean shnumTruncated = false;

	private Structure headerStructure;

	private boolean parsed = false;
	private boolean parsedSectionHeaders = false;

	private ElfLoadAdapter elfLoadAdapter = new ElfLoadAdapter();

	private ElfSectionHeader section0 = null;
	private ElfSectionHeader[] sectionHeaders = new ElfSectionHeader[0];
	private ElfProgramHeader[] programHeaders = new ElfProgramHeader[0];
	private ElfStringTable[] stringTables = new ElfStringTable[0];
	private ElfSymbolTable[] symbolTables = new ElfSymbolTable[0];
	private ElfRelocationTable[] relocationTables = new ElfRelocationTable[0];
	private ElfDynamicTable dynamicTable;

	private ElfStringTable dynamicStringTable;
	private ElfSymbolTable dynamicSymbolTable;
	private boolean hasExtendedSymbolSectionIndexTable; // if SHT_SYMTAB_SHNDX sections exist

	private String[] dynamicLibraryNames;

	private boolean hasLittleEndianHeaders;

	private Consumer<String> errorConsumer;

	private static int INITIAL_READ_LEN = ElfConstants.EI_NIDENT + 18;

	/**
	 * Construct <code>ElfHeader</code> from byte provider
	 * @param provider byte provider
	 * @param errorConsumer error consumer
	 * @throws ElfException if header parse failed
	 */
	public ElfHeader(ByteProvider provider, Consumer<String> errorConsumer) throws ElfException {
		if (provider.length() < 0) {
			throw new IllegalArgumentException(
				"Unsupport byte provider length: 0x" + Long.toHexString(provider.length()));
		}
		this.provider = provider;
		this.errorConsumer = errorConsumer != null ? errorConsumer : _ -> {
			/* no logging if errorConsumer was null */
		};
		try {

			if (!Arrays.equals(ElfConstants.MAGIC_BYTES,
				provider.readBytes(0, ElfConstants.MAGIC_BYTES.length))) {
				throw new ElfException("Not a valid ELF executable.");
			}
			e_ident_magic_num = ElfConstants.MAGIC_NUM;
			e_ident_magic_str = ElfConstants.MAGIC_STR;

			determineHeaderEndianness();

			// reader uses unbounded provider wrapper to allow handling of missing/truncated headers
			reader = new BinaryReader(new UnlimitedByteProviderWrapper(provider),
				hasLittleEndianHeaders);
			reader.setPointerIndex(ElfConstants.MAGIC_BYTES.length);

			e_ident_class = reader.readNextByte();
			e_ident_data = reader.readNextByte();
			e_ident_version = reader.readNextByte();
			e_ident_osabi = reader.readNextByte();
			e_ident_abiversion = reader.readNextByte();
			e_ident_pad = reader.readNextByteArray(PAD_LENGTH);
			e_type = reader.readNextShort();
			e_machine = reader.readNextShort();
			e_version = reader.readNextInt();

			long phoff;
			long shoff;
			if (is32Bit()) {
				e_entry = reader.readNextUnsignedInt();
				phoff = reader.readNextUnsignedInt();
				shoff = reader.readNextUnsignedInt();
			}
			else if (is64Bit()) {
				e_entry = reader.readNextLong();
				phoff = reader.readNextLong();
				shoff = reader.readNextLong();
			}
			else {
				throw new ElfException(
					"Only 32-bit and 64-bit ELF headers are supported (EI_CLASS=0x" +
						Integer.toHexString(e_ident_class) + ")");
			}

			if (phoff < 0 || phoff > FILE_OFFSET_HARD_LIMIT || phoff >= provider.length()) {
				logError("Invalid ELF e_phoff value (program header table offset): 0x" +
					Long.toHexString(phoff));
				phoff = 0;
			}
			if (shoff < 0 || shoff > FILE_OFFSET_HARD_LIMIT || shoff >= provider.length()) {
				logError("Invalid ELF e_shoff value (section header table offset): 0x" +
					Long.toHexString(shoff));
				shoff = 0;
			}
			e_phoff = phoff;
			e_shoff = shoff;

			e_flags = reader.readNextInt();
			e_ehsize = reader.readNextShort();

			e_phentsize = reader.readNextShort();
			long u_phentsize = Short.toUnsignedLong(e_phentsize);

			int phnum = reader.readNextUnsignedShort();
			if (e_phoff == 0) {
				phnum = 0; // disable program header use
			}
			else if (phnum == Short.toUnsignedInt(ElfConstants.PN_XNUM)) {
				phnum = readExtendedProgramHeaderCount(); // use extended stored program header count (uses e_shoff)
			}
			long u_phnum = Integer.toUnsignedLong(phnum);

			e_shentsize = reader.readNextShort();
			long u_shentsize = Short.toUnsignedLong(e_shentsize);

			int shnum = reader.readNextUnsignedShort();
			if (shnum >= Short.toUnsignedInt(ElfSectionHeaderConstants.SHN_LORESERVE)) {
				logError("Invalid ELF e_shnum value (section header count): 0x" +
					Long.toHexString(shnum));
				shnum = 0;
			}
			if (e_shoff == 0) {
				shnum = 0; // disable section header use
			}
			else if (shnum == 0) {
				// NOTE: Only e_shnum==0 is a valid trigger for extended value but we will check regardless when bad value is read
				shnum = readExtendedSectionHeaderCount(); // use extended stored section header count (uses e_shoff)
			}
			long u_shnum = Integer.toUnsignedLong(shnum);

			if (phnum > 0) {
				// validate e_phentsize value
				long supportedPHSize =
					is64Bit() ? ElfProgramHeader.ELF64_PHDR_SIZE : ElfProgramHeader.ELF32_PHDR_SIZE;
				if (u_phentsize != supportedPHSize) {
					if (shnum != 0) {
						logError(
							"Unsupported e_phentsize value (program header size): " + u_phentsize +
								" (expected " + supportedPHSize + "), using section headers only");
						phnum = 0; // disable parse of program headers
					}
					else {
						throw new ElfException(
							"Unsupported e_phentsize value (program header size): " + u_phentsize +
								" (expected " + supportedPHSize + ")");
					}
				}
				else {
					long hardLimit = Integer.toUnsignedLong(Integer.MAX_VALUE) / u_phentsize;
					int count = (int) constrainHeaderCount(u_phnum, e_phoff, u_phentsize, hardLimit,
						"Program Header");
					// flag as truncated if only a partial header set can be read or marked-up 
					phnumTruncated = hasHeaderFragment(u_phnum, e_phoff, u_phentsize, hardLimit,
						"Program Header") ||
						(count != phnum);
					phnum = count;
				}
			}

			if (shnum > 0) {
				// validate e_shentsize value
				long supportedSHSize =
					is64Bit() ? ElfSectionHeader.ELF64_SHDR_SIZE : ElfSectionHeader.ELF32_SHDR_SIZE;
				if (u_shentsize != supportedSHSize) {
					if (phnum != 0) {
						logError(
							"Unsupported e_shentsize value (section header size): " + u_shentsize +
								" (expected " + supportedSHSize + "), using program headers only");
						shnum = 0; // disable parse of section headers
					}
					// TODO: add ability to handle short headers with limited markup
					else {
						throw new ElfException(
							"Unsupported e_shentsize value (section header size): " + u_shentsize +
								" (expected " + supportedSHSize + ")");
					}
				}
				else {
					long hardLimit = Integer.toUnsignedLong(Integer.MAX_VALUE) / u_shentsize;
					int count = (int) constrainHeaderCount(u_shnum, e_shoff, u_shentsize, hardLimit,
						"Section Header");
					shnumTruncated = hasHeaderFragment(u_shnum, e_shoff, u_shentsize, hardLimit,
						"Section Header") ||
						(count != shnum);
					shnum = count;
				}
			}

			// commit final program and section header counts
			e_phnum = phnum;
			e_shnum = shnum;

			int shstrndx = reader.readNextUnsignedShort();
			if (e_shnum == 0) {
				shstrndx = 0;
			}
			else if (shstrndx == Short.toUnsignedInt(ElfSectionHeaderConstants.SHN_XINDEX)) {
				shstrndx = readExtendedSectionHeaderStringTableIndex();
			}
			e_shstrndx = shstrndx;
		}
		catch (IOException e) {
			throw new ElfException(e);
		}
	}

	/**
	 * Constrain number of header elements based upon file bounds and hard limits.
	 *
	 * @param headerCount header count as specified by another header field (unsigned)
	 * @param headerTableOffset starting offset of header table 
	 * @param headerSize size of each header element
	 * @param hardLimit hard limit for maximum number of headers in table (-1 no limit imposed)
	 * @param headerType type of header (used for logging)
	 * @return allowed header count
	 */
	long constrainHeaderCount(long headerCount, long headerTableOffset, long headerSize,
			long hardLimit, String headerType) {
		// maxPossible allows one extra which may be truncated
		long availableSpace = provider.length() - headerTableOffset;
		long maxPossible = availableSpace / headerSize;
		String limitType = "file capacity";
		if (hardLimit >= 0 && maxPossible >= hardLimit) {
			maxPossible = hardLimit;
			limitType = "hard limit";
		}
		else if ((availableSpace % headerSize) != 0) {
			// NOTE: If using an array for markup last partial element must be omitted
			// (see hasHeaderFragment)
			++maxPossible; // allow for last header to be truncated
		}
		if (headerCount > maxPossible) {
			logError(headerType + " count " + headerCount +
				" exceeds " + limitType + " " + maxPossible + "; truncating");
			return maxPossible;
		}
		return headerCount;
	}

	/**
	 * Used in conjunction with {@link #constrainHeaderCount(long, long, long, long, String)} to
	 * determine if the last table entry to be loaded is a partial-entry.
	 * <p>
	 * NOTE: If a markup array datatype is applied to memory it may not fit in the memory 
	 * block and may need to be reduced by one element.
	 * 
	 * @param headerCount header count as specified by another header field (unsigned)
	 * @param headerTableOffset starting offset of header table 
	 * @param headerSize size of each header element
	 * @param hardLimit hard limit for maximum number of headers in table (-1 no limit imposed)
	 * @param headerType type of header (used for logging)
	 * @return allowed header count
	 */
	boolean hasHeaderFragment(long headerCount, long headerTableOffset, long headerSize,
			long hardLimit, String headerType) {

		long availableSpace = provider.length() - headerTableOffset;
		long completeEntryCount = availableSpace / headerSize;
		long permittedCount = headerCount;
		if (hardLimit >= 0) {
			permittedCount = Math.min(headerCount, hardLimit);
		}

		if (permittedCount > completeEntryCount && (availableSpace % headerSize) != 0) {
			logError(headerType + " has partial entry");
			return true;
		}
		return false;
	}

	/**
	 * Returns the unconstrained binary reader (i.e., reads beyond EOF
	 * will return 0-bytes).
	 * @return the binary reader
	 */
	public BinaryReader getReader() {
		return reader;
	}

	/**
	 * Returns the byte provider
	 * @return the byte provider
	 */
	public ByteProvider getByteProvider() {
		return provider;
	}

	void logError(String msg) {
		errorConsumer.accept(msg);
	}

	private ElfSectionHeader getSection0() throws IOException {
		if (section0 == null && e_shoff != 0) {
			if (!providerContainsRegion(e_shoff,
				is64Bit() ? ElfSectionHeader.ELF64_SHDR_SIZE : ElfSectionHeader.ELF32_SHDR_SIZE)) {
				return null;
			}
			section0 = new ElfSectionHeader(reader.clone(e_shoff), this);
		}
		return section0;
	}

	/**
	 * Read extended program header count (e_phnum) stored in first section header (ST_NULL) 
	 * sh_info field value. This is done to overcome the short value limitation of the
	 * e_phnum header field.
	 * @return extended program header count or 0 if not found or invalid
	 * @throws IOException if file IO error occurs
	 */
	private int readExtendedProgramHeaderCount() throws IOException {
		ElfSectionHeader s = getSection0();
		if (s == null || s.getType() != ElfSectionHeaderConstants.SHT_NULL) {
			logError("Failed to load Section-0 required for extended program header count");
			return 0;
		}
		int val = s.getInfo();
		if (val < 0) {
			logError("Invalid extended program header count: " + val);
			return 0;
		}
		return val;
	}

	/**
	 * Read extended section header count (e_shnum) stored in first section header (ST_NULL) 
	 * sh_size field value.  This is done to overcome the short value limitation of the
	 * e_shnum header field.
	 * @return extended section header count or 0 if not found or invalid
	 * @throws IOException if file IO error occurs
	 */
	private int readExtendedSectionHeaderCount() throws IOException {
		ElfSectionHeader s = getSection0();
		if (s == null || s.getType() != ElfSectionHeaderConstants.SHT_NULL) {
			logError("Failed to load Section-0 required for extended section header count");
			return 0;
		}
		long val = s.getSize();
		if (val < 0 || val > Integer.MAX_VALUE) {
			logError("Invalid extended section header count: " + val);
			return 0;
		}
		return (int) val;
	}

	/**
	 * Read extended section header string table index (e_shstrndx) stored in first section header 
	 * (ST_NULL) sh_size field value.  This is done to overcome the short value limitation of the
	 * e_shstrndx header field.  Returned value is restricted to the range 0..0x7fffffff.
	 * @return extended section header count or 0 if not found or out of range
	 * @throws IOException if file IO error occurs
	 */
	private int readExtendedSectionHeaderStringTableIndex() throws IOException {
		ElfSectionHeader s = getSection0();
		if (s != null && s.getType() == ElfSectionHeaderConstants.SHT_NULL) {
			int val = s.getLink();
			return val < 0 ? 0 : val;
		}
		return 0;
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

	/**
	 * Perform parse of all supported headers.
	 * @throws IOException if file IO error occurs
	 */
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
	 * @param address unadjusted address offset
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
	 * @param address prelink-adjusted address offset
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

				if (section.isInvalidOffset()) {
					Msg.debug(this, "Skipping Elf relocation table section with invalid offset " +
						section.getNameAsString());
					return;
				}

				long tableSize = section.getSize();
				if (tableSize <= 0) {
					logError("Relocation table section header '" +
						section.getNameAsString() +
						"' has invalid sh_size value (table size): 0x" +
						Long.toHexString(tableSize));
					return;
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

				boolean addendTypeReloc =
					(sectionHeaderType == ElfSectionHeaderConstants.SHT_RELA ||
						sectionHeaderType == ElfSectionHeaderConstants.SHT_ANDROID_RELA);

				String details = "Elf relocation table section " + section.getNameAsString();
				if (symbolTableSection != null) {
					details +=
						" linked to symbol table section " + symbolTableSection.getNameAsString();
				}
				details += " affecting " + relocaBaseName;
				Msg.debug(this, details);

				ElfRelocationTable.TableFormat format = TableFormat.DEFAULT;
				if (sectionHeaderType == ElfSectionHeaderConstants.SHT_ANDROID_REL ||
					sectionHeaderType == ElfSectionHeaderConstants.SHT_ANDROID_RELA) {
					format = TableFormat.ANDROID;
				}
				else if (sectionHeaderType == ElfSectionHeaderConstants.SHT_RELR ||
					sectionHeaderType == ElfSectionHeaderConstants.SHT_ANDROID_RELR) {
					format = TableFormat.RELR;
				}

				// Avoid use of unlimited reader for relocation tables to enforce EOF
				ElfRelocationTable relocTable =
					new ElfRelocationTable(new BinaryReader(provider, hasLittleEndianHeaders), this,
						section, section.getOffset(), section.getAddress(), tableSize,
						section.getEntrySize(), addendTypeReloc, symbolTable, sectionToBeRelocated,
						format);

				relocationTableList.add(relocTable);
			}
		}
		catch (NotFoundException | ElfException e) {
			logError("Failed to process relocation table " +
				section.getNameAsString() + ": " + e.getMessage());
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
				logError("Failed to locate " + relocTableAddrType.name +
					" in memory at 0x" + Long.toHexString(relocTableAddr));
				return;
			}
			if (relocTableLoadHeader.isInvalidOffset()) {
				return;
			}

			long relocTableOffset = relocTableLoadHeader.getOffset(relocTableAddr);
			for (ElfRelocationTable relocTable : relocationTableList) {
				if (relocTable.getFileOffset() == relocTableOffset) {
					return; // skip reloc table previously parsed
				}
			}

			if (relocTableOffset < 0 || relocTableOffset > FILE_OFFSET_HARD_LIMIT ||
				relocTableOffset >= provider.length()) {
				logError("Invalid derived dynamic relocation table file offset: 0x" +
					Long.toHexString(relocTableOffset) + "; " + relocTableAddrType + ": 0x" +
					Long.toHexString(relocTableAddr));
				return;
			}

			long tableEntrySize =
				relocEntrySizeType != null ? dynamicTable.getDynamicValue(relocEntrySizeType) : -1;
			long tableSize = dynamicTable.getDynamicValue(relocTableSizeType);

			if (tableSize <= 0) {
				logError("Dynamic relocation table has invalid " + relocTableSizeType +
					" (table size): 0x" +
					Long.toHexString(tableSize));
				return;
			}

			ElfRelocationTable.TableFormat format = TableFormat.DEFAULT;
			if (relocTableAddrType == ElfDynamicType.DT_ANDROID_REL ||
				relocTableAddrType == ElfDynamicType.DT_ANDROID_RELA) {
				format = TableFormat.ANDROID;
			}
			else if (relocTableAddrType == ElfDynamicType.DT_RELR ||
				relocTableAddrType == ElfDynamicType.DT_ANDROID_RELR) {
				format = TableFormat.RELR;
			}

			// Avoid use of unlimited reader for relocation tables to enforce EOF
			ElfRelocationTable relocTable =
				new ElfRelocationTable(new BinaryReader(provider, hasLittleEndianHeaders), this,
					null, relocTableOffset, relocTableAddr, tableSize, tableEntrySize,
					addendTypeReloc, dynamicSymbolTable, null, format);
			relocationTableList.add(relocTable);
		}
		catch (ElfException e) {
			logError("Failed to process relocation table: " + e.getMessage());
		}
		catch (NotFoundException e) {
			// ignore - skip (required dynamic table value is missing)
		}
	}

	/**
	 * Get linked section
	 * @param sectionIndex section index
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
			if (vaddr == 0 || dynamicHeaders[0].getFileSize() == 0) {
				logError("ELF Dynamic table appears to have been stripped from binary");
				return;
			}

			ElfProgramHeader loadHeader = getProgramLoadHeaderContaining(vaddr);
			if (loadHeader == null) {
				// Assume p_offset can be used reliably if no corresponding PT_LOAD
				loadHeader = dynamicHeaders[0];
			}
			long dynamicTableOffset = loadHeader.getOffset() +
				(dynamicHeaders[0].getVirtualAddress() - loadHeader.getVirtualAddress());
			dynamicTable = new ElfDynamicTable(reader, this, dynamicTableOffset,
				dynamicHeaders[0].getVirtualAddress());
			return;
		}
		if (dynamicHeaders.length > 1) {
			logError("Multiple ELF Dynamic table program headers found");
		}

		ElfSectionHeader[] dynamicSections = getSections(ElfSectionHeaderConstants.SHT_DYNAMIC);
		if (dynamicSections.length == 1) {

			ElfProgramHeader loadHeader =
				getProgramLoadHeaderContaining(dynamicSections[0].getAddress());
			if (loadHeader != null) {
				long dynamicTableOffset = loadHeader.getOffset() +
					(dynamicSections[0].getAddress() - loadHeader.getVirtualAddress());
				dynamicTable = new ElfDynamicTable(reader, this, dynamicTableOffset,
					dynamicSections[0].getAddress());
				return;
			}
		}

	}

	private void parseStringTables() {

		// identify dynamic symbol table address
		long dynamicStringTableAddr = -1;
		if (dynamicTable != null) {
			try {
				dynamicStringTableAddr =
					adjustAddressForPrelink(dynamicTable.getDynamicValue(ElfDynamicType.DT_STRTAB));
			}
			catch (NotFoundException e) {
				logError("ELF does not contain a dynamic string table (DT_STRTAB)");
			}
		}

		ArrayList<ElfStringTable> stringTableList = new ArrayList<>();
		for (ElfSectionHeader stringTableSectionHeader : sectionHeaders) {
			if (stringTableSectionHeader.getType() == ElfSectionHeaderConstants.SHT_STRTAB) {
				ElfStringTable stringTable = new ElfStringTable(this, stringTableSectionHeader,
					stringTableSectionHeader.getOffset(), stringTableSectionHeader.getAddress(),
					stringTableSectionHeader.getSize());
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

	private ElfStringTable parseDynamicStringTable(long dynamicStringTableAddr) {

		if (!dynamicTable.containsDynamicValue(ElfDynamicType.DT_STRSZ)) {
			logError("Failed to parse DT_STRTAB, missing dynamic dependency");
			return null;
		}

		try {
			long stringTableSize = dynamicTable.getDynamicValue(ElfDynamicType.DT_STRSZ);

			if (dynamicStringTableAddr == 0) {
				logError("ELF Dynamic String Table of size " + stringTableSize +
					" appears to have been stripped from binary");
				return null;
			}

			ElfProgramHeader stringTableLoadHeader =
				getProgramLoadHeaderContaining(dynamicStringTableAddr);
			if (stringTableLoadHeader == null) {
				logError("Failed to locate DT_STRTAB in memory at 0x" +
					Long.toHexString(dynamicStringTableAddr));
				return null;
			}

			return new ElfStringTable(this, null,
				stringTableLoadHeader.getOffset(dynamicStringTableAddr), dynamicStringTableAddr,
				stringTableSize);
		}
		catch (NotFoundException e) {
			throw new AssertException(e);
		}
	}

	private int[] getExtendedSymbolSectionIndexTable(ElfSectionHeader symbolTableSectionHeader,
			int symbolCount) {

		if (!hasExtendedSymbolSectionIndexTable) {
			return null;
		}

		// Find SHT_SYMTAB_SHNDX section linked to specified symbol table section
		ElfSectionHeader symbolSectionIndexHeader = null;
		for (ElfSectionHeader section : sectionHeaders) {
			if (section.getType() != ElfSectionHeaderConstants.SHT_SYMTAB_SHNDX) {
				continue;
			}
			int linkIndex = section.getLink();
			if (linkIndex <= 0 || linkIndex >= sectionHeaders.length) {
				continue;
			}
			if (sectionHeaders[linkIndex] == symbolTableSectionHeader) {
				symbolSectionIndexHeader = section;
				break;
			}
		}
		if (symbolSectionIndexHeader == null) {
			return null;
		}

		// determine number of 32-bit index elements for int[]
		long size = symbolSectionIndexHeader.getSize();
		if (size <= 0 || size > Integer.MAX_VALUE) {
			logError(
				"Symbol table section index header '" + symbolSectionIndexHeader.getNameAsString() +
					"' has invalid size: 0x" + Long.toHexString(size));
			return null;
		}

		long indexTableOffset = symbolSectionIndexHeader.getOffset();
		if (symbolSectionIndexHeader.isInvalidOffset()) {
			logError(
				"Symbol table section index header '" + symbolSectionIndexHeader.getNameAsString() +
					"' has invalid offset value: 0x" +
					Long.toHexString(indexTableOffset));
			return null;
		}

		// Get constrained index entry count - limited by the number of symbol entries
		int count = (int) constrainHeaderCount(size / 4, indexTableOffset, 4, symbolCount,
			"Symbol section index");
		hasHeaderFragment(size / 4, indexTableOffset, 4, symbolCount, "Symbol section index"); // performs logging only

		int[] indexTable = new int[count];

		try {
			BinaryReader r = reader.clone(symbolSectionIndexHeader.getOffset());
			for (int i = 0; i < count; i++) {
				indexTable[i] = r.readNextInt();
			}
		}
		catch (IOException e) {
			logError("Failed to read symbol section index table at 0x" +
				Long.toHexString(symbolSectionIndexHeader.getOffset()) + ": " +
				symbolSectionIndexHeader.getNameAsString());
		}

		return indexTable;
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
				logError("ELF does not contain a dynamic symbol table (DT_SYMTAB)");
			}
		}

		// Add section based symbol tables
		ArrayList<ElfSymbolTable> symbolTableList = new ArrayList<>();
		for (ElfSectionHeader symbolTableSectionHeader : sectionHeaders) {
			if (symbolTableSectionHeader.getType() == ElfSectionHeaderConstants.SHT_SYMTAB ||
				symbolTableSectionHeader.getType() == ElfSectionHeaderConstants.SHT_DYNSYM) {
				// || symbolTableSectionHeader.getType() == ElfSectionHeaderConstants.SHT_SUNW_LDYNSYM) {

				long tableOffset = symbolTableSectionHeader.getOffset();
				if (symbolTableSectionHeader.isInvalidOffset()) {
					logError(
						"Symbol table section header '" +
							symbolTableSectionHeader.getNameAsString() +
							"' has invalid offset value: 0x" +
							Long.toHexString(tableOffset));
					continue;
				}

				long tableSize = symbolTableSectionHeader.getSize();
				if (tableSize <= 0) {
					logError("Symbol table section header '" +
						symbolTableSectionHeader.getNameAsString() +
						"' has invalid sh_size value (table size): 0x" +
						Long.toHexString(tableSize));
					continue;
				}

				long entrySize = symbolTableSectionHeader.getEntrySize();
				if (!ElfSymbolTable.isValidEntrySize(is32Bit(), entrySize)) {
					logError("Symbol table section header '" +
						symbolTableSectionHeader.getNameAsString() +
						"' has unsupported sh_entsize value (table entry size): 0x" +
						Long.toHexString(entrySize));
					continue;
				}
				if ((tableSize % entrySize) != 0) {
					logError("Symbol table section header '" +
						symbolTableSectionHeader.getNameAsString() +
						"' has sh_size which is not a multiple of sh_entsize value");
				}

				// Get constrained symbol count for table
				long expectedSymbolCount = tableSize / entrySize;
				long hardLimit = Integer.toUnsignedLong(Integer.MAX_VALUE) / entrySize;
				int symbolCount =
					(int) constrainHeaderCount(expectedSymbolCount, tableOffset, entrySize,
						hardLimit, "Symbol");
				boolean hasTruncatedSymbolTable =
					hasHeaderFragment(expectedSymbolCount, tableOffset, entrySize,
						hardLimit, "Symbol") || (symbolCount != expectedSymbolCount);

				ElfStringTable stringTable = null;
				int stringSectionIndex = symbolTableSectionHeader.getLink();
				if (stringSectionIndex >= 0 && stringSectionIndex < sectionHeaders.length) {
					ElfSectionHeader stringTableSectionHeader = sectionHeaders[stringSectionIndex];
					stringTable = getStringTable(stringTableSectionHeader);
					if (stringTable != null) {
						Msg.debug(this,
							"Elf symbol table section " +
								symbolTableSectionHeader.getNameAsString() +
								" linked to string table section " +
								stringTableSectionHeader.getNameAsString());
					}
				}
				if (stringTable == null) {
					logError("String table not found for symbol table: " +
						symbolTableSectionHeader.getNameAsString());
				}

				boolean isDyanmic = ElfSectionHeaderConstants.dot_dynsym
						.equals(symbolTableSectionHeader.getNameAsString());

				// get extended symbol section index table if present
				int[] symbolSectionIndexTable =
					getExtendedSymbolSectionIndexTable(symbolTableSectionHeader, symbolCount);

				ElfSymbolTable symbolTable =
					new ElfSymbolTable(reader, this, symbolTableSectionHeader,
						tableOffset, symbolTableSectionHeader.getAddress(),
						(int) entrySize, symbolCount, hasTruncatedSymbolTable,
						stringTable, symbolSectionIndexTable, isDyanmic);
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

	private ElfDynamicType getDynamicHashTableType() {
		if (dynamicTable.containsDynamicValue(ElfDynamicType.DT_HASH)) {
			return ElfDynamicType.DT_HASH;
		}
		if (dynamicTable.containsDynamicValue(ElfDynamicType.DT_GNU_HASH)) {
			return ElfDynamicType.DT_GNU_HASH;
		}
		if (dynamicTable.containsDynamicValue(ElfDynamicType.DT_GNU_XHASH)) {
			return ElfDynamicType.DT_GNU_XHASH;
		}
		return null;
	}

	private ElfSymbolTable parseDynamicSymbolTable() throws IOException {

		ElfDynamicType dynamicHashType = getDynamicHashTableType();

		if (!dynamicTable.containsDynamicValue(ElfDynamicType.DT_SYMTAB) ||
			!dynamicTable.containsDynamicValue(ElfDynamicType.DT_SYMENT) ||
			dynamicHashType == null) {
			if (dynamicStringTable != null) {
				logError("Failed to parse DT_SYMTAB, missing dynamic dependency");
			}
			return null;
		}

		try {

			long tableAddr = dynamicTable.getDynamicValue(ElfDynamicType.DT_SYMTAB);
			if (tableAddr == 0) {
				logError("Failed to process DT_SYMTAB with 0 value");
				return null;
			}

			tableAddr = adjustAddressForPrelink(tableAddr);
			long tableEntrySize = dynamicTable.getDynamicValue(ElfDynamicType.DT_SYMENT);

			ElfProgramHeader symbolTableLoadHeader = getProgramLoadHeaderContaining(tableAddr);
			if (symbolTableLoadHeader == null) {
				logError(
					"Failed to locate DT_SYMTAB in memory at 0x" + Long.toHexString(tableAddr));
				return null;
			}

			// Create dynamic symbol table if not defined as a section
			long symbolTableOffset = symbolTableLoadHeader.getOffset(tableAddr);
			if (symbolTableOffset <= 0 || symbolTableOffset > FILE_OFFSET_HARD_LIMIT ||
				symbolTableOffset >= provider.length()) {
				logError("Dynamic symbol table has invalid DT_SYMTAB value (table offset): 0x" +
					Long.toHexString(symbolTableOffset));
				return null;
			}

			// Use dynamic symbol hash table DT_HASH, DT_GNU_HASH, or DT_GNU_XHASH to 
			// determine symbol table count/length
			long hashTableAddr = dynamicTable.getDynamicValue(dynamicHashType);
			hashTableAddr = adjustAddressForPrelink(hashTableAddr);

			ElfProgramHeader hashTableLoadHeader = getProgramLoadHeaderContaining(hashTableAddr);
			if (hashTableLoadHeader == null) {
				logError(
					"Failed to locate DT_HASH, DT_GNU_HASH, or DT_GNU_XHASH in memory at 0x" +
						Long.toHexString(hashTableAddr));
				return null;
			}

			if (!ElfSymbolTable.isValidEntrySize(is32Bit(), tableEntrySize)) {
				logError(
					"Dynamic symbol table has unsupported DT_SYMENT value (table entry size): 0x" +
					Long.toHexString(tableEntrySize));
				return null;
			}

			// determine symbol count from dynamic symbol hash table
			long expectedSymbolCount;
			long symbolHashTableOffset = hashTableLoadHeader.getOffset(hashTableAddr);
			if (dynamicHashType == ElfDynamicType.DT_GNU_HASH) {
				expectedSymbolCount = deriveGnuHashDynamicSymbolCount(symbolHashTableOffset);
			}
			else if (dynamicHashType == ElfDynamicType.DT_GNU_XHASH) {
				expectedSymbolCount = deriveGnuXHashDynamicSymbolCount(symbolHashTableOffset);
			}
			else {
				// DT_HASH table, nchain corresponds is same as symbol count
				expectedSymbolCount = reader.readUnsignedInt(symbolHashTableOffset + 4); // nchain from DT_HASH
			}

			if (expectedSymbolCount <= 0) {
				logError("Unable to determine symbol count for dynamic symbol table at address 0x" +
					Long.toHexString(tableAddr));
				return null;
			}

			// Get constrained symbol count for table
			long hardLimit = Integer.toUnsignedLong(Integer.MAX_VALUE) / tableEntrySize;
			int symbolCount =
				(int) constrainHeaderCount(expectedSymbolCount, symbolTableOffset, tableEntrySize,
					hardLimit, "Symbol");
			boolean hasTruncatedSymbolTable =
				hasHeaderFragment(expectedSymbolCount, symbolTableOffset, tableEntrySize,
					hardLimit, "Symbol") || (symbolCount != expectedSymbolCount);

			if (dynamicStringTable == null) {
				logError("String table not found for dynamic symbol table at address 0x" +
					Long.toHexString(tableAddr));
			}

			// NOTE: When parsed from dynamic table and not found via section header parse
			// it is assumed that the extended symbol section table is not used.

			return new ElfSymbolTable(reader, this, null, symbolTableOffset, tableAddr,
				(int) tableEntrySize, symbolCount, hasTruncatedSymbolTable, dynamicStringTable,
				null, true);
		}
		catch (NotFoundException e) {
			throw new AssertException(e);
		}
	}

	/**
	 * Walk DT_GNU_HASH table to determine dynamic symbol count
	 * @param gnuHashTableOffset DT_GNU_HASH table file offset
	 * @return dynamic symbol count (0 may be returned when processing error occurs)
	 * @throws IOException file read error
	 */
	private long deriveGnuHashDynamicSymbolCount(long gnuHashTableOffset) throws IOException {
		
		long numBuckets = reader.readUnsignedInt(gnuHashTableOffset);
		long symbolBase = reader.readUnsignedInt(gnuHashTableOffset + 4);
		long bloomSize = reader.readUnsignedInt(gnuHashTableOffset + 8);
		// int bloomShift = reader.readInt(gnuHashTableOffset + 12);
		long bloomWordSize = is64Bit() ? 8 : 4;
		long bucketsOffset = gnuHashTableOffset + 16 + (bloomWordSize * bloomSize);

		// Identify restricted region which contains GNU hash table (arbitrary min-length)
		long maxOffset = getMaxOffsetForLoadedRegionContaining(gnuHashTableOffset, 12);
		if (maxOffset <= 0) {
			logError("Failed to idenitify loaded GNU Hash table");
			return 0;
		}

		long bucketOffset = bucketsOffset;
		long maxSymbolIndex = 0;
		for (long i = 0; i < numBuckets; i++) {
			if (bucketOffset < gnuHashTableOffset || bucketOffset > maxOffset) {
				logError("Error occured while inspecting GNU Hash table");
				return 0;
			}
			int symbolIndex = reader.readInt(bucketOffset);
			if (symbolIndex > maxSymbolIndex) {
				maxSymbolIndex = symbolIndex;
			}
			bucketOffset += 4;
		}

		long chainIndex = maxSymbolIndex - symbolBase;

		++maxSymbolIndex;
		long chainOffset = bucketOffset + (4 * chainIndex); // chains immediately follow buckets
		while (true) {
			if (chainOffset < gnuHashTableOffset || chainOffset > maxOffset) {
				logError("Error occured while inspecting GNU Hash table");
				return 0;
			}
			int chainValue = reader.readInt(chainOffset);
			if ((chainValue & 1) != 0) {
				break;
			}
			++maxSymbolIndex;
			chainOffset += 4;
		}
		return maxSymbolIndex;
	}

	private long getMaxOffsetForLoadedRegionContaining(long offset, long minSize) {
		if (e_shnum != 0) {
			ElfSectionHeader sectionContaining =
				getSectionHeaderContainingFileRange(offset, minSize);
			if (sectionContaining != null) {
				return sectionContaining.getOffset() + sectionContaining.getSize() - 1;
			}
		}
		if (e_phnum != 0) {
			ElfProgramHeader containingSegment =
				getProgramLoadHeaderContainingFileOffset(offset);
			if (containingSegment != null) {
				return containingSegment.getOffset() + containingSegment.getFileSize() - 1;
			}
		}
		return -1;
	}

	/**
	 * Walk DT_GNU_XHASH table to determine dynamic symbol count
	 * @param gnuHashTableOffset DT_GNU_XHASH table file offset
	 * @return dynamic symbol count
	 * @throws IOException file read error
	 */
	private long deriveGnuXHashDynamicSymbolCount(long gnuHashTableOffset) throws IOException {
		// Elf32_Word  ngnusyms;  // number of entries in chains (and xlat); dynsymcount=symndx+ngnusyms
		// Elf32_Word  nbuckets;  // number of hash table buckets
		// Elf32_Word  symndx;  // number of initial .dynsym entires skipped in chains[] (and xlat[])
		long ngnusyms = reader.readUnsignedInt(gnuHashTableOffset);
		long symndx = reader.readUnsignedInt(gnuHashTableOffset + 8);

		return symndx + ngnusyms;
	}

	/**
	 * Perform offset region check against byte provider.
	 * This is done against the byte provider since the
	 * reader is unbounded.
	 * @param offset starting offset
	 * @param length length of range
	 * @return true if provider contains specified byte offset range
	 */
	private boolean providerContainsRegion(long offset, int length) {
		return offset >= 0 && (offset + length) <= provider.length();
	}

	public void parseSectionHeaders() throws IOException {
		if (reader == null) {
			throw new IOException("ELF binary reader is null!");
		}
		if (parsedSectionHeaders) {
			return;
		}

		parsedSectionHeaders = true;
		sectionHeaders = new ElfSectionHeader[e_shnum];
		for (int i = 0; i < e_shnum; ++i) {
			long index = e_shoff + (i * (long) e_shentsize);
			sectionHeaders[i] = new ElfSectionHeader(reader.clone(index), this);
			if (sectionHeaders[i].getType() == ElfSectionHeaderConstants.SHT_SYMTAB_SHNDX) {
				hasExtendedSymbolSectionIndexTable = true;
			}
		}

		if (sectionHeaders.length != 0) {
			section0 = sectionHeaders[0];
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
		programHeaders = new ElfProgramHeader[e_phnum];
		for (int i = 0; i < e_phnum; ++i) {
			long index = e_phoff + (i * (long) e_phentsize);
			programHeaders[i] = new ElfProgramHeader(reader.clone(index), this);
		}

		// TODO: Find sample file which requires this hack to verify its necessity
		// HACK: 07/01/2013 - Added hack for malformed ELF file with only program header sections
		long size = 0;
		for (ElfProgramHeader pheader : programHeaders) {
			size += pheader.getFileSize();
		}
		if (size == reader.length()) {
			// adjust program section file offset to be based on relative read offset
			long relOffset = 0;
			for (ElfProgramHeader pheader : programHeaders) {
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
			addr = Integer.toUnsignedLong((int) addr);
		}
		if (Long.compareUnsigned(addr, minBase) < 0) {
			minBase = addr;
		}
		return minBase;
	}

	/**
	 * Inspect the Elf image and determine the default image base prior 
	 * to any parse method being invoked (i.e., only the main Elf
	 * header structure has been parsed during initialization.
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
			if (!providerContainsRegion(index, e_phentsize)) {
				break;
			}
			try {
				int headerType = reader.readInt(index);
				if (headerType == ElfProgramHeaderConstants.PT_LOAD) {
					ElfProgramHeader header = new ElfProgramHeader(reader.clone(index), this);
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
			long fileLength = reader.getByteProvider().length();

			// not enough bytes
			if (fileLength < 8) {
				return -1;
			}
			int preLinkImageBaseInt = reader.readInt(fileLength - 8);
			String preLinkMagicString = reader.readAsciiString(fileLength - 4, 4).trim();

			if (preLinkMagicString.equals("PRE")) {
				preLinkImageBase = Integer.toUnsignedLong(preLinkImageBaseInt);
			}
		}
		catch (IOException e) {
			logError("Elf prelink read failure (see log)");
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

	private void determineHeaderEndianness() throws ElfException, IOException {

		if (provider.length() < INITIAL_READ_LEN) {
			throw new ElfException("Not enough bytes to be a valid ELF executable.");
		}

		hasLittleEndianHeaders = true;
		byte[] bytes = provider.readBytes(0, INITIAL_READ_LEN);
		if (bytes[ElfConstants.EI_DATA] == ElfConstants.ELF_DATA_BE) {
			hasLittleEndianHeaders = false;
		}
		else if (bytes[ElfConstants.EI_DATA] != ElfConstants.ELF_DATA_LE) {
			logError("Invalid EI_DATA, assuming little-endian headers (EI_DATA=0x" +
				Integer.toHexString(bytes[ElfConstants.EI_DATA]) + ")");
		}
		if (!hasLittleEndianHeaders && bytes[ElfConstants.EI_NIDENT] != 0) {
			// Header endianness sanity check
			// Some toolchains always use little endian Elf Headers

			// TODO: unsure if forced endianness applies to relocation data

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
	 * of e_phentsize and unsigned e_phnum gives the table's size in bytes. If original 
	 * e_phnum equals PNXNUM (0xffff) an attempt will be made to obtained the extended size
	 * from section[0].sh_info field.  If a file has no program header table, e_phnum holds 
	 * the value zero.
	 * @return the number of entries in the program header table
	 */
	public int getProgramHeaderCount() {
		return e_phnum;
	}

	/**
	 * {@return true if {@link #getProgramHeaderCount()} was reduced or table entries were 
	 * truncated during parse due to constraints}
	 */
	public boolean hasTruncatedProgramHeaders() {
		return phnumTruncated;
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
	 * of e_shentsize and unsigned e_shnum gives the section header table's size in bytes. If a file
	 * has no section header table, e_shnum holds the value zero.
	 * @return the number of entries in the section header table
	 */
	public int getSectionHeaderCount() {
		return e_shnum;
	}

	/**
	 * {@return true if {@link #getSectionHeaderCount()} was reduced or table entries were truncated 
	 * during parse due to constraints}
	 */
	public boolean hasTruncatedSectionHeaders() {
		return shnumTruncated;
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
	public int e_shstrndx() {
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
	 * @param type section type
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
			if (!sectionHeader.isAlloc()) {
				continue;
			}
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
		for (ElfSectionHeader sectionHeader : sectionHeaders) {
			if (!sectionHeader.isAlloc()) {
				continue;
			}
			long start = sectionHeader.getAddress();
			long end = start + sectionHeader.getSize();
			if (start <= address && address < end) {
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
			if (section.getType() == ElfSectionHeaderConstants.SHT_NULL ||
				section.isInvalidOffset()) {
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
	 * @param type program header type
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
			if (programHeader.getType() == ElfProgramHeaderConstants.PT_LOAD &&
				programHeader.getVirtualAddress() == virtualAddr) {
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
			if (programHeader.getType() != ElfProgramHeaderConstants.PT_LOAD) {
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
				programHeader.getType() != ElfProgramHeaderConstants.PT_LOAD ||
				programHeader.isInvalidOffset()) {
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
	 * @param section section whose associated string table is requested
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
	 * @param symbolTableSection symbol table section header
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

}
