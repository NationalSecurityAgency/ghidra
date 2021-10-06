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
package ghidra.app.util.opinion;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.text.NumberFormat;
import java.util.*;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.cmd.label.SetLabelPrimaryCmd;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.MemoryLoadable;
import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.bin.format.elf.ElfDynamicType.ElfDynamicValueType;
import ghidra.app.util.bin.format.elf.extend.ElfLoadAdapter;
import ghidra.app.util.bin.format.elf.relocation.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.database.register.AddressRangeObjectMap;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.*;
import ghidra.util.datastruct.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

class ElfProgramBuilder extends MemorySectionResolver implements ElfLoadHelper {

	public static final String BLOCK_SOURCE_NAME = "Elf Loader";

	private static final String SEGMENT_NAME_PREFIX = "segment_";
	private static final String UNALLOCATED_NAME_PREFIX = "unallocated_";

	private static final String ELF_HEADER_BLOCK_NAME = "_elfHeader";
	private static final String ELF_PROGRAM_HEADERS_BLOCK_NAME = "_elfProgramHeaders";
	private static final String ELF_SECTION_HEADERS_BLOCK_NAME = "_elfSectionHeaders";

	// Maximum length of discardable segment
	// If program contains section headers, any zeroed segment smaller than this size
	// will be eligible for removal.
	private static final int DISCARDABLE_SEGMENT_SIZE = 0xff;

	private List<Option> options;
	private Long dataImageBase; // cached data image base option or null if not applicable
	private MessageLog log;

	private ElfHeader elf;
	private FileBytes fileBytes;

	private Listing listing;
	private Memory memory;

	private HashMap<ElfSymbol, Address> symbolMap = new HashMap<>();

	protected ElfProgramBuilder(ElfHeader elf, Program program, List<Option> options,
			MessageLog log) {
		super(program);
		this.elf = elf;
		this.options = options;
		this.log = log;
		memory = program.getMemory();
		listing = program.getListing();
	}

	@Override
	public ElfHeader getElfHeader() {
		return elf;
	}

	static void loadElf(ElfHeader elf, Program program, List<Option> options, MessageLog log,
			TaskMonitor monitor) throws IOException, CancelledException {
		ElfProgramBuilder elfProgramBuilder = new ElfProgramBuilder(elf, program, options, log);
		elfProgramBuilder.load(monitor);
	}

	protected void load(TaskMonitor monitor) throws IOException, CancelledException {

		monitor.setMessage("Completing ELF header parsing...");
		monitor.setCancelEnabled(false);
		elf.parse();
		monitor.setCancelEnabled(true);

		int id = program.startTransaction("Load ELF program");
		boolean success = false;
		try {

			addProgramProperties(monitor);

			setImageBase();
			program.setExecutableFormat(ElfLoader.ELF_NAME);

			// resolve segment/sections and create program memory blocks
			ByteProvider byteProvider = elf.getReader().getByteProvider();
			try (InputStream fileIn = byteProvider.getInputStream(0)) {
				fileBytes = program.getMemory()
						.createFileBytes(byteProvider.getName(), 0, byteProvider.length(), fileIn,
							monitor);
			}

			adjustSegmentAndSectionFileAllocations(byteProvider);

			// process headers and define "section" within memory elfProgramBuilder
			processProgramHeaders(monitor);
			processSectionHeaders(monitor);

			resolve(monitor);

			if (elf.e_shnum() == 0) {
				// create/expand segments to their fullsize if no sections are defined
				expandProgramHeaderBlocks(monitor);
			}

			if (memory.isEmpty()) {
				// TODO: Does this really happen?
				success = true;
				return;
			}

			markupElfHeader(monitor);
			markupProgramHeaders(monitor);
			markupSectionHeaders(monitor);
			markupDynamicTable(monitor);
			markupInterpreter(monitor);

			processStringTables(monitor);

			processSymbolTables(monitor);

			elf.getLoadAdapter().processElf(this, monitor);

			processEntryPoints(monitor);

			processRelocations(monitor);
			processImports(monitor);

			monitor.setMessage("Processing PLT/GOT ...");
			elf.getLoadAdapter().processGotPlt(this, monitor);

			markupHashTable(monitor);
			markupGnuHashTable(monitor);
			markupGnuBuildId(monitor);
			markupGnuDebugLink(monitor);

			processGNU(monitor);
			processGNU_readOnly(monitor);

			success = true;
		}
		finally {
			program.endTransaction(id, success);
		}
	}

	private void adjustSegmentAndSectionFileAllocations(
			ByteProvider byteProvider)
			throws IOException {

		// Identify file ranges not allocated to segments or sections
		RangeMap fileMap = new RangeMap();
		fileMap.paintRange(0, byteProvider.length() - 1, -1); // -1: unallocated

		ElfProgramHeader[] segments = elf.getProgramHeaders();
		ElfSectionHeader[] sections = elf.getSections();

		for (ElfProgramHeader segment : segments) {
			if (segment.getType() == ElfProgramHeaderConstants.PT_NULL) {
				continue;
			}
			long size = segment.getFileSize();
			long offset = segment.getOffset();
			if (size > 0) {
				fileMap.paintRange(offset, offset + size - 1, -2); // -2: used by segment
			}
		}

		for (ElfSectionHeader section : sections) {
			if (section.getType() == ElfSectionHeaderConstants.SHT_NULL ||
				section.getType() == ElfSectionHeaderConstants.SHT_NOBITS) {
				continue;
			}
			section.getSize();
			section.getOffset();
			long size = section.getSize();
			long offset = section.getOffset();
			if (size > 0) {
				fileMap.paintRange(offset, offset + size - 1, -3); // -3: used by section 
			}
		}

		// Ignore header regions which will always be allocated to blocks
		int elfHeaderSize = elf.toDataType().getLength();
		fileMap.paintRange(0, elfHeaderSize - 1, -4); // -4: header block
		int programHeaderSize = elf.e_phentsize() * elf.e_phnum();
		if (programHeaderSize != 0) {
			fileMap.paintRange(elf.e_phoff(), elf.e_phoff() + programHeaderSize - 1, -4); // -4: header block
		}
		int sectionHeaderSize = elf.e_shentsize() * elf.e_shnum();
		if (sectionHeaderSize != 0) {
			fileMap.paintRange(elf.e_shoff(), elf.e_shoff() + sectionHeaderSize - 1, -4); // -4: header block
		}

		// Add unallocated non-zero file regions as OTHER blocks
		IndexRangeIterator rangeIterator = fileMap.getIndexRangeIterator(0);
		int unallocatedIndex = 0;
		while (rangeIterator.hasNext()) {
			IndexRange range = rangeIterator.next();
			int value = fileMap.getValue(range.getStart());
			if (value != -1) {
				continue;
			}

			long start = range.getStart();
			long length = range.getEnd() - start + 1;

			if (isZeroFilledFileRegion(byteProvider, start, length)) {
				continue;
			}

			String name = UNALLOCATED_NAME_PREFIX + unallocatedIndex++;
			try {
				addInitializedMemorySection(null, start, length,
					AddressSpace.OTHER_SPACE.getMinAddress(),
					name, false, false, false, null, false, false);
			}
			catch (AddressOverflowException e) {
				// ignore
			}
		}
	}

	private boolean isZeroFilledFileRegion(ByteProvider byteProvider, long start, long length)
			throws IOException {
		int bufSize = 16 * 1024;
		if (length < bufSize) {
			bufSize = (int) length;
		}
		long remaining = length;
		while (remaining > 0) {
			byte[] bytes = byteProvider.readBytes(start, Math.min(remaining, bufSize));
			if (!isZeroedArray(bytes, bytes.length)) {
				return false;
			}
			remaining -= bytes.length;
		}
		return true;
	}

	private boolean isZeroedArray(byte[] bytes, int len) {
		for (int i = 0; i < len; i++) {
			if (bytes[i] != 0) {
				return false;
			}
		}
		return true;
	}

	private boolean isDiscardableFillerSegment(MemoryLoadable loadable, String blockName,
			Address start, long fileOffset, long length) throws IOException {
		if (elf.e_shnum() == 0 || elf.e_phnum() == 0) {
			return false; // only prune if both sections and program headers are present
		}
		if (length > DISCARDABLE_SEGMENT_SIZE || !blockName.startsWith(SEGMENT_NAME_PREFIX)) {
			return false;
		}

		if (elf.getLoadAdapter().hasFilteredLoadInputStream(this, loadable, start)) {
			// block is unable to map directly to file bytes - read from filtered input stream
			try (InputStream dataInput =
				getInitializedBlockInputStream(loadable, start, fileOffset, length)) {
				byte[] bytes = new byte[(int) length];
				return dataInput.read(bytes) == bytes.length && isZeroedArray(bytes, bytes.length);
			}
		}

		byte[] bytes = new byte[(int) length];
		return fileBytes.getModifiedBytes(fileOffset, bytes) == bytes.length &&
			isZeroedArray(bytes, bytes.length);
	}

	@Override
	public MessageLog getLog() {
		return log;
	}

	@Override
	public void log(String msg) {
		log.appendMsg(msg);
	}

	@Override
	public void log(Throwable t) {
		log.appendException(t);
	}

	private void setImageBase() {
		if (!ElfLoaderOptionsFactory.hasImageBaseOption(options)) {
			log("Using existing program image base of " + program.getImageBase());
			return;
		}
		try {
			AddressSpace defaultSpace = getDefaultAddressSpace();
			Address imageBase = null;

			String imageBaseStr = ElfLoaderOptionsFactory.getImageBaseOption(options);
			if (imageBaseStr == null) {
				imageBase = defaultSpace.getAddress(elf.getImageBase(), true);
			}
			else {
				long imageBaseOffset = NumericUtilities.parseHexLong(imageBaseStr);
				imageBase = defaultSpace.getAddress(imageBaseOffset, true);
			}

			program.setImageBase(imageBase, true);
		}
		catch (Exception e) {
			// this shouldn't happen
			Msg.error(this, "Can't set image base.", e);
		}
	}

	private long getImageDataBase() {
		if (dataImageBase == null) {
			dataImageBase = 0L;
			String imageBaseStr = ElfLoaderOptionsFactory.getDataImageBaseOption(options);
			if (imageBaseStr != null) {
				dataImageBase = NumericUtilities.parseHexLong(imageBaseStr);
			}
		}
		return dataImageBase;
	}

	private void addProgramProperties(TaskMonitor monitor) throws CancelledException {

		monitor.checkCanceled();
		monitor.setMessage("Adding program properties...");

		Options props = program.getOptions(Program.PROGRAM_INFO);

		// Preserve original image base which may be required for DWARF address fixup.
		// String is used to avoid decimal rendering of long values in display.
		props.setString(ElfLoader.ELF_ORIGINAL_IMAGE_BASE_PROPERTY,
			"0x" + Long.toHexString(elf.getImageBase()));
		props.setBoolean(ElfLoader.ELF_PRELINKED_PROPERTY, elf.isPreLinked());

		String elfFileType;
		boolean isRelocatable = false;
		switch (elf.e_type()) {
			case ElfConstants.ET_NONE:
				elfFileType = "unspecified";
				break;
			case ElfConstants.ET_REL:
				elfFileType = "relocatable";
				isRelocatable = true;
				break;
			case ElfConstants.ET_EXEC:
				elfFileType = "executable";
				break;
			case ElfConstants.ET_DYN:
				elfFileType = "shared object";
				isRelocatable = true;
				break;
			case ElfConstants.ET_CORE:
				elfFileType = "core";
				isRelocatable = true;
				break;
			default:
				elfFileType = "unknown";
				break;
		}
		props.setString(ElfLoader.ELF_FILE_TYPE_PROPERTY, elfFileType);
		props.setBoolean(RelocationTable.RELOCATABLE_PROP_NAME, isRelocatable);

		int fileIndex = 0;
		ElfSymbolTable[] symbolTables = elf.getSymbolTables();
		for (ElfSymbolTable symbolTable : symbolTables) {
			monitor.checkCanceled();
			String[] files = symbolTable.getSourceFiles();
			for (String file : files) {
				monitor.checkCanceled();
				props.setString(ElfLoader.ELF_SOURCE_FILE_PROPERTY_PREFIX + pad(fileIndex++) + "]",
					file);
			}
		}

		int libraryIndex = 0;
		ElfDynamicTable dynamicTable = elf.getDynamicTable();
		if (dynamicTable != null) {
			String[] neededLibs = elf.getDynamicLibraryNames();
			for (String neededLib : neededLibs) {
				monitor.checkCanceled();
				props.setString(
					ElfLoader.ELF_REQUIRED_LIBRARY_PROPERTY_PREFIX + pad(libraryIndex++) + "]",
					neededLib);
			}
		}

	}

	private AddressRange getMarkupMemoryRangeConstraint(Address addr) {
		MemoryBlock block = memory.getBlock(addr);
		if (block == null) {
			return null;
		}
		return new AddressRangeImpl(addr, block.getEnd());
	}

	/**
	 * Processes the GNU version section.
	 * @throws CancelledException 
	 */
	private void processGNU(TaskMonitor monitor) throws CancelledException {
		monitor.checkCanceled();

		Address versionTableAddr = null;

		ElfDynamicTable dynamicTable = elf.getDynamicTable();
		if (dynamicTable != null) {
			try {
				long versionTableAddrOffset =
					dynamicTable.getDynamicValue(ElfDynamicType.DT_VERSYM);
				versionTableAddr = getDefaultAddress(versionTableAddrOffset);
			}
			catch (NotFoundException e) {
				// ignore
			}
		}

		// TODO: Handle multiple version tables

		if (versionTableAddr == null) {
			ElfSectionHeader[] sections = elf.getSections(ElfSectionHeaderConstants.SHT_GNU_versym);
			if (sections.length == 0) {
				return;
			}
			versionTableAddr = findLoadAddress(sections[0], 0);
		}

		if (versionTableAddr == null) {
			return;
		}

		AddressRange markupRange = getMarkupMemoryRangeConstraint(versionTableAddr);
		if (markupRange == null) {
			return;
		}

		WordDataType WORD = new WordDataType();

		ElfSymbolTable symtab = elf.getDynamicSymbolTable();
		if (symtab == null) {
			return;
		}

		ElfSymbol[] symbols = symtab.getSymbols();
		int maxCnt = Math.min((int) (markupRange.getLength() / 2), symbols.length);

		Address nextAddr = versionTableAddr;
		for (int index = 0; index < maxCnt; index++) {
			CodeUnit cu = null;
			try {
				cu = listing.createData(nextAddr, WORD);
			}
			catch (CodeUnitInsertionException e) {
				// ignore
			}
			catch (DataTypeConflictException e) {
				// ignore
			}

			if (cu == null) {
				cu = listing.getCodeUnitAt(nextAddr);
			}
			if (cu != null) {

				String comment = null;

				comment = symbols[index].getNameAsString();
				if (comment == null) {
					comment = Long.toHexString(symbols[index].getValue());
				}

				cu.setComment(CodeUnit.EOL_COMMENT, comment);

//            Scalar scalar = (Scalar)data.getValue();
//            switch ((int)scalar.getValue()) {
//                case GNU_Constants.VER_NDX_LOCAL:
//                    data.setComment(Data.EOL_COMMENT, symbols[index].getNameAsString()+ " - local version");
//                    break;
//                case GNU_Constants.VER_NDX_GLOBAL:
//                    data.setComment(Data.EOL_COMMENT, symbols[index].getNameAsString()+ " - global version");
//                    break;
//                default:
//                    data.setComment(Data.EOL_COMMENT, symbols[index].getNameAsString()+ " - ??");
//                  break;
//            }
			}
			try {
				nextAddr = nextAddr.add(2);
			}
			catch (AddressOutOfBoundsException e) {
				break; // no more room
			}
		}
	}

	/**
	 * Adjust GNU read-only segments following relocations (PT_GNU_RELRO).
	 */
	private void processGNU_readOnly(TaskMonitor monitor) {

		// Set read-only segments
		if (elf.e_shentsize() != 0) {
			return;
		}

		monitor.setMessage("Processing GNU Definitions");
		for (ElfProgramHeader roSegment : elf
				.getProgramHeaders(ElfProgramHeaderConstants.PT_GNU_RELRO)) {
			ElfProgramHeader loadedSegment =
				elf.getProgramLoadHeaderContaining(roSegment.getVirtualAddress());
			if (loadedSegment != null) {
				for (AddressRange blockRange : getResolvedLoadAddresses(loadedSegment)) {
					MemoryBlock block = memory.getBlock(blockRange.getMinAddress());
					if (block != null) {
						log("Setting block " + block.getName() +
							" to read-only based upon PT_GNU_RELRO data");
						block.setWrite(false);
					}
				}
			}
		}
	}

	private void processEntryPoints(TaskMonitor monitor) throws CancelledException {
		monitor.checkCanceled();
		monitor.setMessage("Creating entry points...");

		long entry = elf.e_entry(); // already adjusted for pre-link
		if (entry != 0) {
			Address entryAddr =
				createEntryFunction(ElfLoader.ELF_ENTRY_FUNCTION_NAME, entry, monitor);
			if (entryAddr != null) {
				addElfHeaderReferenceMarkup(elf.getEntryComponentOrdinal(), entryAddr);
			}
		}

		// process dynamic entry points
		createDynamicEntryPoints(ElfDynamicType.DT_INIT, null, "_INIT_", monitor);
		createDynamicEntryPoints(ElfDynamicType.DT_INIT_ARRAY, ElfDynamicType.DT_INIT_ARRAYSZ,
			"_INIT_", monitor);
		createDynamicEntryPoints(ElfDynamicType.DT_PREINIT_ARRAY, ElfDynamicType.DT_PREINIT_ARRAYSZ,
			"_PREINIT_", monitor);
		createDynamicEntryPoints(ElfDynamicType.DT_FINI, null, "_FINI_", monitor);
		createDynamicEntryPoints(ElfDynamicType.DT_FINI_ARRAY, ElfDynamicType.DT_FINI_ARRAYSZ,
			"_FINI_", monitor);

	}

	private void createDynamicEntryPoints(ElfDynamicType dynamicEntryType,
			ElfDynamicType entryArraySizeType, String baseName, TaskMonitor monitor) {

		ElfDynamicTable dynamicTable = elf.getDynamicTable();
		if (dynamicTable == null) {
			return;
		}

		try {
			long entryAddrOffset =
				elf.adjustAddressForPrelink(dynamicTable.getDynamicValue(dynamicEntryType));

			if (entryArraySizeType == null) {
				// single entry addr case
				createEntryFunction("_" + dynamicEntryType.name, entryAddrOffset, monitor);
				return;
			}

			// entryAddrOffset points to array of entry addresses
			DataType dt = elf.is32Bit() ? DWordDataType.dataType : QWordDataType.dataType;
			Address entryArrayAddr = getDefaultAddress(entryAddrOffset);
			long arraySize = dynamicTable.getDynamicValue(entryArraySizeType);
			long elementCount = arraySize / dt.getLength();

			for (int i = 0; i < elementCount; i++) {
				Address addr = entryArrayAddr.add(i * dt.getLength());
				Data data = createData(addr, dt);
				if (data == null) {
					break;
				}
				Scalar value = (Scalar) data.getValue();
				if (value != null) {
					if (i != 0 && value.getValue() == 0) {
						continue;
					}
					long funcAddrOffset = elf.adjustAddressForPrelink(value.getValue());
					Address funcAddr = createEntryFunction(baseName + i, funcAddrOffset, monitor);
					if (funcAddr != null) {
						data.addOperandReference(0, funcAddr, RefType.DATA, SourceType.ANALYSIS);
					}
				}
			}

		}
		catch (NotFoundException e) {
			// ignore
		}

	}

	/**
	 * Create an entry point function.
	 * Note: entries in the dynamic table appear to have any pre-link adjustment already applied.
	 * @param name
	 * @param entryAddr function address (adjusted for pre-linking).
	 * @param monitor
	 * @return function address
	 */
	private Address createEntryFunction(String name, long entryAddr, TaskMonitor monitor) {

		entryAddr += getImageBaseWordAdjustmentOffset(); // word offset

		Address entryAddress = getDefaultAddressSpace().getTruncatedAddress(entryAddr, true);

		// TODO: Entry may refer to a pointer - make sure we have execute permission
		MemoryBlock block = memory.getBlock(entryAddress);
		if (block == null || !block.isExecute()) {
			return entryAddress;
		}

		entryAddress = elf.getLoadAdapter().creatingFunction(this, entryAddress);

		Function function = program.getFunctionManager().getFunctionAt(entryAddress);
		if (function != null) {
			program.getSymbolTable().addExternalEntryPoint(entryAddress);
			return entryAddress; // symbol-based function already created
		}

		try {
			createOneByteFunction(name, entryAddress, true);
		}
		catch (Exception e) {
			log("Could not create symbol at entry point: " + getMessage(e));
		}

		return entryAddress;
	}

	private String getMessage(Exception e) {
		String msg = e.getMessage();
		if (msg == null) {
			msg = e.toString();
		}
		return msg;
	}

	private void markupInterpreter(TaskMonitor monitor) throws CancelledException {
		monitor.checkCanceled();
		monitor.setMessage("Processing interpreter...");
		Address interpStrAddr = null;

		ElfProgramHeader[] interpProgramHeaders =
			elf.getProgramHeaders(ElfProgramHeaderConstants.PT_INTERP);
		if (interpProgramHeaders.length != 0) {
			long offset = interpProgramHeaders[0].getOffset();
			if (offset == 0) {
				Msg.warn(this, "ELF PT_INTERP appears to have been stripped from binary");
				return;
			}
			interpStrAddr = findLoadAddress(interpProgramHeaders[0].getOffset(), 1);
		}

		if (interpStrAddr == null) {
			ElfSectionHeader interpSection = elf.getSection(ElfSectionHeaderConstants.dot_interp);
			if (interpSection != null) {
				interpStrAddr = findLoadAddress(interpSection, 0);
			}
		}

		if (interpStrAddr == null) {
			return;
		}

		createData(interpStrAddr, TerminatedStringDataType.dataType);
		listing.setComment(interpStrAddr, CodeUnit.EOL_COMMENT, "Initial Elf program interpreter");
	}

	private void processImports(TaskMonitor monitor) throws CancelledException {
		monitor.checkCanceled();
		monitor.setMessage("Processing imports...");

		ExternalManager extManager = program.getExternalManager();
		ElfDynamicTable dynamicTable = elf.getDynamicTable();
		if (dynamicTable != null) {
			String[] neededLibs = elf.getDynamicLibraryNames();
			for (String neededLib : neededLibs) {
				try {
					extManager.setExternalPath(neededLib, null, false);
				}
				catch (InvalidInputException e) {
					log("Bad library name: " + neededLib);
				}
			}
		}
	}

	private void processRelocations(TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Processing relocation tables...");

		ElfRelocationTable[] relocationTables = elf.getRelocationTables();
		if (relocationTables.length == 0) {
			return;
		}

		boolean processRelocations = ElfLoaderOptionsFactory.performRelocations(options);
		if (processRelocations && ElfRelocationHandlerFactory.getHandler(elf) == null) {
			log("ELF relocation handler extension not found!  Unable to process relocations.");
		}

		Address defaultBase = getDefaultAddress(elf.adjustAddressForPrelink(0));
		AddressSpace defaultSpace = defaultBase.getAddressSpace();
		long defaultBaseOffset = defaultBase.getAddressableWordOffset();

		int totalCount = 0;
		for (ElfRelocationTable relocationTable : relocationTables) {
			totalCount += relocationTable.getRelocationCount();
		}
		monitor.initialize(totalCount);

		for (ElfRelocationTable relocationTable : relocationTables) {

			monitor.checkCanceled();

			Address relocTableAddr = null;

			ElfSectionHeader section = relocationTable.getTableSectionHeader();
			if (section != null) {
				relocTableAddr = findLoadAddress(section, 0);
			}
			else {
				relocTableAddr = findLoadAddress(relocationTable.getFileOffset(), 1);
			}

			/**
			 * Cases:
			 * 1. elf.isRelocatable()
			 * 	a) sectionToBeRelocated null (may be NULL section?)
			 *  b) sectionToBeRelocated known - offset relative to section load address
			 *
			 * 2. !elf.isRelocatable()
			 *  a) sectionToBeRelocated null (may be NULL section?)
			 *  b) sectionToBeRelocated known - offset relative to image base
			 */

			AddressSpace relocationSpace = defaultSpace;
			long baseOffset = defaultBaseOffset;

			ElfSectionHeader sectionToBeRelocated = relocationTable.getSectionToBeRelocated();
			if (sectionToBeRelocated != null) {
				// relocation offsets are relative to start of section load address
				Address sectionLoadAddr = findLoadAddress(sectionToBeRelocated, 0);
				if (sectionLoadAddr == null) {
					log("Failed to identify relocation base address for relocation table 0x" +
						relocationTable.getAddressOffset() + " [section: " +
						sectionToBeRelocated.getNameAsString() + "]");
					monitor.incrementProgress(relocationTable.getRelocationCount());
					continue;
				}
				relocationSpace = sectionLoadAddr.getAddressSpace();
				if (elf.isRelocatable()) {
					baseOffset = sectionLoadAddr.getAddressableWordOffset();
				}
				else if (relocationSpace != defaultSpace) {
					baseOffset = 0;
				}
			}

			if (relocTableAddr != null) {
				markupRelocationTable(relocTableAddr, relocationTable, monitor);
			}

			ElfRelocationContext context = null;
			if (processRelocations) {
				context =
					ElfRelocationContext.getRelocationContext(this, relocationTable, symbolMap);
			}
			try {
				processRelocationTable(relocationTable, context, relocationSpace, baseOffset,
					monitor);
			}
			finally {
				if (context != null) {
					context.dispose();
				}
			}
		}
	}

	private void processRelocationTable(ElfRelocationTable relocationTable,
			ElfRelocationContext context, AddressSpace relocationSpace, long baseWordOffset,
			TaskMonitor monitor) throws CancelledException {

		ElfSymbol[] symbols = relocationTable.getAssociatedSymbolTable().getSymbols();
		ElfRelocation[] relocs = relocationTable.getRelocations();

		boolean relrTypeUnknown = false;
		long relrRelocationType = 0;
		if (relocationTable.isRelrTable() && context != null) {
			relrRelocationType = context.getRelrRelocationType();
			if (relrRelocationType == 0) {
				relrTypeUnknown = true;
				log("Failed to process RELR relocations - extension does not define RELR type");
			}
		}

		for (ElfRelocation reloc : relocs) {

			monitor.checkCanceled();
			monitor.incrementProgress(1);

			int symbolIndex = reloc.getSymbolIndex();
			String symbolName = null;
			if (symbolIndex >= 0 && symbolIndex < symbols.length) {
				symbolName = symbols[symbolIndex].getNameAsString();
			}

			Address baseAddress = relocationSpace.getTruncatedAddress(baseWordOffset, true);

			// relocation offset (r_offset) is defined to be a byte offset (assume byte size is 1)
			Address relocAddr =
				context != null ? context.getRelocationAddress(baseAddress, reloc.getOffset())
						: baseAddress.addWrap(reloc.getOffset());

			long[] values = new long[] { reloc.getSymbolIndex() };

			byte[] bytes = elf.is64Bit() ? new byte[8] : new byte[4];

			long type = reloc.getType();
			if (relrRelocationType != 0) {
				type = relrRelocationType;
				reloc.setType(relrRelocationType);
			}

			try {
				MemoryBlock relocBlock = memory.getBlock(relocAddr);
				if (relocBlock == null) {
					throw new MemoryAccessException("Block is non-existent");
				}
				if (!relocBlock.isInitialized()) {
					try {
						memory.convertToInitialized(relocBlock, (byte) 0);
					}
					catch (Exception e) {
						Msg.error(this, "Unexpected Exception", e);
						ElfRelocationHandler.markAsUninitializedMemory(program, relocAddr, type,
							reloc.getSymbolIndex(), symbolName, log);
						continue;
					}
				}

				memory.getBytes(relocAddr, bytes);

				if (context != null) {
					if (relrTypeUnknown) {
						ElfRelocationHandler.markAsUnsupportedRelr(program, relocAddr);
					}
					else {
						context.processRelocation(reloc, relocAddr);
					}
				}
			}
			catch (MemoryAccessException e) {
				if (type != 0) { // ignore if type 0 which is always NONE (no relocation performed)
					log("Unable to perform relocation: Type = " + type + " (0x" +
						Long.toHexString(type) + ") at " + relocAddr + " (Symbol = " + symbolName +
						") - " + getMessage(e));
				}
			}
			finally {
				// Save relocation data
				program.getRelocationTable()
						.add(relocAddr, reloc.getType(), values, bytes, symbolName);
			}
		}
	}

	@Override
	public long getOriginalValue(Address addr, boolean signExtend) throws MemoryAccessException {
		byte[] bytes;
		int len = elf.is64Bit() ? 8 : 4;
		Relocation relocation = program.getRelocationTable().getRelocation(addr);
		if (relocation == null) {
			bytes = new byte[len];
			memory.getBytes(addr, bytes);
		}
		else {
			bytes = relocation.getBytes();
		}
		DataConverter dataConverter = DataConverter.getInstance(elf.isBigEndian());
		return signExtend ? dataConverter.getSignedValue(bytes, len)
				: dataConverter.getValue(bytes, len);
	}

	/**
	 * Add reference to previously applied header structure (assumes markupElfHeader previously called)
	 * @param componentName
	 * @param refAddr
	 */
	private void addElfHeaderReferenceMarkup(int componentOrdinal, Address refAddr) {

		Structure struct = (Structure) elf.toDataType();

		Address headerAddr = findLoadAddress(0, struct.getLength());
		if (headerAddr == null) {
			MemoryBlock block = memory.getBlock(ELF_HEADER_BLOCK_NAME);
			if (block == null) {
				return; // ELF header not loaded
			}
			headerAddr = block.getStart();
		}

		Data data = listing.getDefinedDataAt(headerAddr);
		if (data == null || !data.getDataType().isEquivalent(struct)) {
			return;
		}
		Data component = data.getComponent(componentOrdinal);
		if (component != null) {
			component.addOperandReference(0, refAddr, RefType.DATA, SourceType.IMPORTED);
		}
	}

	private void markupElfHeader(TaskMonitor monitor) {

		DataType dt = elf.toDataType();

		Address headerAddr = findLoadAddress(0, dt.getLength());

		// Create block for header if failed to locate load
		try {
			if (headerAddr == null) {
				if (!ElfLoaderOptionsFactory.includeOtherBlocks(options)) {
					return;
				}
				headerAddr = AddressSpace.OTHER_SPACE.getAddress(0);
				MemoryBlock block = createInitializedBlock(null, true, ELF_HEADER_BLOCK_NAME,
					headerAddr, 0, elf.e_ehsize(), "Elf File Header", false, false, false, monitor);
				headerAddr = block.getStart();
			}

			createData(headerAddr, dt);
		}
		catch (Exception e) {
			log("Failed to markup Elf header: " + getMessage(e));
		}
	}

	private void markupProgramHeaders(TaskMonitor monitor) {

		int headerCount = elf.e_phnum();
		int size = elf.e_phentsize() * headerCount;
		if (size == 0) {
			return;
		}

		Structure phStructDt = (Structure) elf.getProgramHeaders()[0].toDataType();
		phStructDt = phStructDt.clone(program.getDataTypeManager());

		Array arrayDt = new ArrayDataType(phStructDt, headerCount, size);

		Address headerAddr = findLoadAddress(elf.e_phoff(), size);

		// Create block for header if failed to locate load
		try {
			if (headerAddr == null) {
				if (!ElfLoaderOptionsFactory.includeOtherBlocks(options)) {
					return;
				}
				headerAddr = AddressSpace.OTHER_SPACE.getAddress(0);
				MemoryBlock block = createInitializedBlock(null, true,
					ELF_PROGRAM_HEADERS_BLOCK_NAME, headerAddr, elf.e_phoff(), arrayDt.getLength(),
					"Elf Program Headers", false, false, false, monitor);
				headerAddr = block.getStart();
			}

			addElfHeaderReferenceMarkup(elf.getPhoffComponentOrdinal(), headerAddr);

			Data array = createData(headerAddr, arrayDt);

			ElfProgramHeader[] programHeaders = elf.getProgramHeaders();
			int vaddrFieldIndex = elf.is64Bit() ? 3 : 2; // p_vaddr structure element index
			for (int i = 0; i < programHeaders.length; i++) {
				Data d = array.getComponent(i);
				d.setComment(CodeUnit.EOL_COMMENT, programHeaders[i].getComment());
				if (programHeaders[i].getType() == ElfProgramHeaderConstants.PT_NULL) {
					continue;
				}
				if (programHeaders[i].getOffset() == 0) {
					continue; // has been stripped
				}
				Address segmentAddr = findLoadAddress(programHeaders[i], 0);
				if (segmentAddr != null) {
					// add reference to p_vaddr component
					Data component = d.getComponent(vaddrFieldIndex);
					component.addOperandReference(0, segmentAddr, RefType.DATA,
						SourceType.IMPORTED);
				}
			}
		}
		catch (Exception e) {
			e.printStackTrace();
			log("Failed to markup Elf program/segment headers: " + getMessage(e));
		}
	}

	private void markupSectionHeaders(TaskMonitor monitor) {

		int headerCount = elf.e_shnum();
		int size = elf.e_shentsize() * headerCount;
		if (size == 0) {
			return;
		}

		Structure shStructDt = (Structure) elf.getSections()[0].toDataType();
		shStructDt = shStructDt.clone(program.getDataTypeManager());

		Array arrayDt = new ArrayDataType(shStructDt, elf.e_shnum(), elf.e_shentsize());

		Address headerAddr = findLoadAddress(elf.e_shoff(), size);

		// Create block for header if failed to locate load
		try {
			if (headerAddr == null) {
				if (!ElfLoaderOptionsFactory.includeOtherBlocks(options)) {
					return;
				}
				headerAddr = AddressSpace.OTHER_SPACE.getAddress(0);
				MemoryBlock block = createInitializedBlock(null, true,
					ELF_SECTION_HEADERS_BLOCK_NAME, headerAddr, elf.e_shoff(), arrayDt.getLength(),
					"Elf Section Headers", false, false, false, monitor);
				headerAddr = block.getStart();
			}

			addElfHeaderReferenceMarkup(elf.getShoffComponentOrdinal(), headerAddr);

			Data array = createData(headerAddr, arrayDt);

			ElfSectionHeader[] sections = elf.getSections();
			for (int i = 0; i < sections.length; i++) {

				Data d = array.getComponent(i);
				String comment = sections[i].getNameAsString();
				String type = sections[i].getTypeAsString();
				if (type != null) {
					comment = comment + " - " + type;
				}
				d.setComment(CodeUnit.EOL_COMMENT, comment);

				Address sectionAddr = findLoadAddress(sections[i], 0);
				if (sectionAddr != null) {
					// add reference to sh_addr component
					Data component = d.getComponent(3);
					component.addOperandReference(0, sectionAddr, RefType.DATA,
						SourceType.IMPORTED);
				}
			}
		}
		catch (Exception e) {
			log("Failed to markup Elf section headers: " + getMessage(e));
		}
	}

	private void markupRelocationTable(Address relocTableAddr, ElfRelocationTable relocTable,
			TaskMonitor monitor) {
		try {
			DataType dataType = relocTable.toDataType();
			if (dataType != null) {
				listing.createData(relocTableAddr, dataType);
			}
			else {
				listing.setComment(relocTableAddr, CodeUnit.PRE_COMMENT,
					"ELF Relocation Table (markup not yet supported)");
			}
		}
		catch (Exception e) {
			log("Failed to properly markup relocation table: " + getMessage(e));
		}
	}

	private AddressSpace getDefaultAddressSpace() {
		return program.getAddressFactory().getDefaultAddressSpace();
	}

	private AddressSpace getDefaultDataSpace() {
		return program.getLanguage().getDefaultDataSpace();
	}

	private AddressSpace getConstantSpace() {
		return program.getAddressFactory().getConstantSpace();
	}

	private void allocateUndefinedSymbolData(HashMap<Address, Integer> dataAllocationMap) {
		for (Address addr : dataAllocationMap.keySet()) {
			// Create undefined data for each data/object symbol
			Integer symbolSize = dataAllocationMap.get(addr);
			if (symbolSize != null) {
				try {
					createUndefined(addr, symbolSize);
				}
				catch (CodeUnitInsertionException e) {
					// ignore conflicts which can be caused by other markup
				}
			}
		}
	}

	private static final Integer AVAILABLE_MEMORY = 1;
	private static final Integer ALLOCATED_MEMORY = 2;

	private AddressSet allocatedRegions = new AddressSet();

	@Override
	public AddressRange allocateLinkageBlock(int alignment, int size, String purpose) {

		ElfLoadAdapter loadAdapter = elf.getLoadAdapter();
		AddressSpace space = getDefaultAddressSpace();

		// Build range map: 1 marks valid addresses region, 2 marks defined blocks
		// Avoid minimum range of addresses
		AddressRangeObjectMap<Integer> map = new AddressRangeObjectMap<>();
		map.setObject(space.getAddress(alignment, true), space.getMaxAddress(), AVAILABLE_MEMORY);
		for (AddressRange range : allocatedRegions.getAddressRanges()) {
			// mark dynamic allocation region as allocated
			map.setObject(range.getMinAddress(), range.getMaxAddress(), ALLOCATED_MEMORY);
		}

		for (MemoryBlock block : memory.getBlocks()) {
			// only consider physical addresses
			Address blockStart = block.getStart().getPhysicalAddress();
			if (!space.equals(blockStart.getAddressSpace())) {
				continue;
			}
			Address blockEnd = block.getEnd().getPhysicalAddress();
			if (MemoryBlock.EXTERNAL_BLOCK_NAME.equals(block.getName())) {
				// allow for possible EXTERNAL block extension during relocation processing
				try {
					blockEnd = blockEnd.addNoWrap(loadAdapter.getExternalBlockReserveSize());
				}
				catch (AddressOverflowException e) {
					blockEnd = space.getMaxAddress();
				}
			}
			map.setObject(blockStart, block.getEnd().getPhysicalAddress(), ALLOCATED_MEMORY);
		}

		// Identify the largest unallocated range
		AddressRange maxRange = null;
		BigInteger maxRangeLength = null;

		// Give preference to last unallocated range whose size should be big-enough
		BigInteger preferredRangeSize =
			BigInteger.valueOf(size <= 0 ? loadAdapter.getPreferredExternalBlockSize() : size);

		AddressRange lastBigUnallocatedRange = null;

		// check AVAILABLE_MEMORY ranges
		AddressRangeIterator rangeIterator = map.getAddressRangeIterator();
		while (rangeIterator.hasNext()) {
			AddressRange range = rangeIterator.next();
			Integer value = map.getObject(range.getMinAddress());
			if (!AVAILABLE_MEMORY.equals(value)) {
				continue;
			}
			BigInteger rangeLength = range.getBigLength();
			if (maxRangeLength == null || maxRangeLength.compareTo(rangeLength) < 0) {
				maxRange = range;
				maxRangeLength = rangeLength;
			}
			Address addr = range.getMinAddress();
			Address alignedAddress = addr.getNewAddress(
				NumericUtilities.getUnsignedAlignedValue(addr.getOffset(), alignment));
			long alignAdjust = alignedAddress.subtract(addr);
			rangeLength = rangeLength.subtract(BigInteger.valueOf(alignAdjust));
			if (rangeLength.compareTo(preferredRangeSize) >= 0) {
				lastBigUnallocatedRange = range;
			}
		}

		if (maxRange == null ||
			(size > 0 && maxRange.getLength() > 0 && maxRange.getLength() < size)) {
			Msg.error(this, "ELF unable to find unallocated memory required for " + purpose + ": " +
				program.getName());
			return null; // NOTE: this will likely cause other errors to follow
		}

		// Return aligned address range
		AddressRange freeRange = maxRange;
		if (lastBigUnallocatedRange != null &&
			lastBigUnallocatedRange.getMinAddress().compareTo(maxRange.getMinAddress()) > 0) {
			// prefer the last unallocated range if it is a big range (need not be the biggest)
			freeRange = lastBigUnallocatedRange;
		}

		Address addr = freeRange.getMinAddress();
		Address alignedAddress = addr.getNewAddress(
			NumericUtilities.getUnsignedAlignedValue(addr.getOffset(), alignment));

		AddressRange range = new AddressRangeImpl(alignedAddress, freeRange.getMaxAddress());
		if (size > 0) {
			long rangeLen = range.getLength();
			if (rangeLen < 0 || rangeLen > size) {
				// reduce size of allocation range
				range = new AddressRangeImpl(range.getMinAddress(),
					range.getMinAddress().add(size - 1));
			}
			// keep track if allocations other than the EXTERNAL block allocation
			allocatedRegions.add(range);
		}
		return range;
	}

	private AddressRange externalBlockLimits;
	private Address lastExternalBlockEntryAddress;
	private Address nextExternalBlockEntryAddress;

	/**
	 * Allocate the next EXTERNAL block entry location based upon the specified size.
	 * @param entrySize entry size
	 * @return Address of EXTERNAL block entry or null if unable to allocate.
	 */
	private Address getNextExternalBlockEntryAddress(int entrySize) {
		if (nextExternalBlockEntryAddress == null) {
			int alignment = elf.getLoadAdapter().getLinkageBlockAlignment();
			externalBlockLimits = allocateLinkageBlock(alignment, -1, "EXTERNAL block");
			nextExternalBlockEntryAddress =
				externalBlockLimits != null ? externalBlockLimits.getMinAddress()
						: Address.NO_ADDRESS;
		}
		Address addr = nextExternalBlockEntryAddress;
		if (addr != Address.NO_ADDRESS) {
			try {
				Address lastAddr = nextExternalBlockEntryAddress.addNoWrap(entrySize - 1);
				if (externalBlockLimits.contains(lastAddr)) {
					lastExternalBlockEntryAddress = lastAddr;
					nextExternalBlockEntryAddress = lastExternalBlockEntryAddress.addNoWrap(1);
					if (!externalBlockLimits.contains(nextExternalBlockEntryAddress)) {
						nextExternalBlockEntryAddress = Address.NO_ADDRESS;
					}
				}
				else {
					// unable to allocation entry size
					nextExternalBlockEntryAddress = Address.NO_ADDRESS;
					return Address.NO_ADDRESS;
				}
			}
			catch (AddressOverflowException e) {
				nextExternalBlockEntryAddress = Address.NO_ADDRESS;
			}
		}
		return addr != Address.NO_ADDRESS ? addr : null;
	}

	/**
	 * Create EXTERNAL memory block based upon {@link #externalBlockLimits} and
	 * {@link #lastExternalBlockEntryAddress}.
	 */
	private void createExternalBlock() {
		if (lastExternalBlockEntryAddress == null) {
			return;
		}
		Address externalBlockAddress = externalBlockLimits.getMinAddress();
		long size = lastExternalBlockEntryAddress.subtract(externalBlockAddress) + 1;
		try {
			MemoryBlock block = memory.createUninitializedBlock(MemoryBlock.EXTERNAL_BLOCK_NAME,
				externalBlockAddress, size, false);

			// assume any value in external is writable.
			block.setWrite(true);
			block.setSourceName(BLOCK_SOURCE_NAME);
			block.setComment(
				"NOTE: This block is artificial and is used to make relocations work correctly");
		}
		catch (Exception e) {
			log("Error creating external memory block: " + " - " + getMessage(e));
		}
	}

	private void processSymbolTables(TaskMonitor monitor) throws CancelledException {

		monitor.setMessage("Processing symbol tables...");

		// Mapped data/object symbol addresses with specific sizes
		HashMap<Address, Integer> dataAllocationMap = new HashMap<>();

		ElfSymbolTable[] symbolTables = elf.getSymbolTables();

		int totalCount = 0;
		for (ElfSymbolTable elfSymbolTable : symbolTables) {
			totalCount += elfSymbolTable.getSymbolCount();
		}
		monitor.initialize(totalCount);

		for (ElfSymbolTable elfSymbolTable : symbolTables) {
			monitor.checkCanceled();

			Address symbolTableAddr = null;

			ElfSectionHeader symbolTableSection = elfSymbolTable.getTableSectionHeader();
			if (symbolTableSection != null) {
				symbolTableAddr = findLoadAddress(symbolTableSection, 0);
			}
			else {
				symbolTableAddr =
					findLoadAddress(elfSymbolTable.getFileOffset(), elfSymbolTable.getLength());
			}

			ElfSymbol[] symbols = elfSymbolTable.getSymbols();

			if (symbolTableAddr != null) {
				markupSymbolTable(symbolTableAddr, elfSymbolTable, monitor);
			}

			processSymbols(symbols, dataAllocationMap, monitor);
		}

		//create an artificial block for the external symbols
		createExternalBlock();

		// create undefined data code units for symbols
		allocateUndefinedSymbolData(dataAllocationMap);
	}

	private void processSymbols(ElfSymbol[] symbols, HashMap<Address, Integer> dataAllocationMap,
			TaskMonitor monitor) throws CancelledException {
		for (ElfSymbol elfSymbol : symbols) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);

			try {

				Address address = calculateSymbolAddress(elfSymbol);
				if (address == null) {
					continue;
				}

				String symName = elfSymbol.getNameAsString();

				// NO_ADDRESS signifies external symbol to be allocated to EXTERNAL block
				boolean usingFakeExternal = false;
				if (address == Address.NO_ADDRESS) {

					if (symName == null) {
						continue; // unexpected
					}

					// check for @<version> or @@<version>
					if (processVersionedExternal(elfSymbol)) {
						continue;
					}

					// check if external symbol previously defined and re-use it
					if (processDuplicateExternal(elfSymbol)) {
						continue;
					}

					address = allocateExternalSymbol(elfSymbol);
					usingFakeExternal = true;
				}

				if (elfSymbol.isObject()) {
					long size = elfSymbol.getSize();
					if (size > 0 && size < Integer.MAX_VALUE) {
						dataAllocationMap.put(address, (int) size);
					}
				}

				evaluateElfSymbol(elfSymbol, address, usingFakeExternal);
			}
			catch (Exception e) {
				log("Error creating symbol: " + elfSymbol.getNameAsString() + " - " +
					getMessage(e));
			}
		}
	}

	/**
	 * Calculate the load address associated with a specified elfSymbol.
	 * @param elfSymbol ELF symbol
	 * @return symbol address or null if symbol not supported and address not determined,
	 * or {@link Address#NO_ADDRESS} if symbol is external and should be allocated to the EXTERNAL block.
	 */
	private Address calculateSymbolAddress(ElfSymbol elfSymbol) {

		if (elfSymbol.getSymbolTableIndex() == 0) {
			return null; // always skip the first symbol, it is NULL
		}

		if (elfSymbol.isFile()) {
			return null; //do not create file symbols... (source file list added to program properties)
		}

		if (elfSymbol.isTLS()) {
			// TODO: Investigate support for TLS symbols
			log("Unsupported Thread-Local Symbol not loaded: " + elfSymbol.getNameAsString());
			return null;
		}

		ElfLoadAdapter loadAdapter = elf.getLoadAdapter();

		// Allow extension to have first shot at calculating symbol address
		try {
			Address address = elf.getLoadAdapter().calculateSymbolAddress(this, elfSymbol);
			if (address != null) {
				return address;
			}
		}
		catch (NoValueException e) {
			return null;
		}

		ElfSectionHeader[] elfSections = elf.getSections();
		short sectionIndex = elfSymbol.getSectionHeaderIndex();
		Address symSectionBase = null;
		AddressSpace defaultSpace = getDefaultAddressSpace();
		AddressSpace defaultDataSpace = getDefaultDataSpace();
		AddressSpace symbolSpace = defaultSpace;
		long symOffset = elfSymbol.getValue();

		if (sectionIndex > 0) {
			if (sectionIndex < elfSections.length) {
				ElfSectionHeader symSection = elf.getSections()[sectionIndex];
				symSectionBase = findLoadAddress(symSection, 0);
				if (symSectionBase == null) {
					log("Unable to place symbol due to non-loaded section: " +
						elfSymbol.getNameAsString() + " - value=0x" +
						Long.toHexString(elfSymbol.getValue()) + ", section=" +
						symSection.getNameAsString());
					return null;
				}
				symbolSpace = symSectionBase.getAddressSpace();
			} // else assume sections have been stripped
			AddressSpace space = symbolSpace.getPhysicalSpace();
			symOffset = loadAdapter.getAdjustedMemoryOffset(symOffset, space);
			if (space == defaultSpace) {
				symOffset =
					elf.adjustAddressForPrelink(symOffset) + getImageBaseWordAdjustmentOffset();
			}
			else if (space == defaultDataSpace) {
				symOffset += getImageDataBase();
			}
		}
		else if (sectionIndex == ElfSectionHeaderConstants.SHN_UNDEF) { // Not section relative 0x0000 (e.g., no sections defined)

			Address regAddr = findMemoryRegister(elfSymbol);
			if (regAddr != null) {
				return regAddr;
			}

			// FIXME: No sections defined or refers to external symbol
			// Uncertain what if any offset adjustments should apply, although the
			// EXTERNAL block is affected by the program image base
			symOffset = loadAdapter.getAdjustedMemoryOffset(symOffset, defaultSpace);
			symOffset += getImageBaseWordAdjustmentOffset();
		}
		else if (sectionIndex == ElfSectionHeaderConstants.SHN_ABS) { // Absolute value/address - 0xfff1
			// TODO: Which space ? Can't distinguish simple constant vs. data vs. code/default space
			// The should potentially be assign a constant address instead (not possible currently)

			// Note: Assume data space - symbols will be "pinned"

			// TODO: it may be inappropriate to adjust since value may not actually be a memory address - what to do?
			// symOffset = loadAdapter.adjustMemoryOffset(symOffset, space);

			Address regAddr = findMemoryRegister(elfSymbol);
			if (regAddr != null) {
				return regAddr;
			}

			symbolSpace = getConstantSpace();
		}
		else if (sectionIndex == ElfSectionHeaderConstants.SHN_COMMON) { // Common symbols - 0xfff2 (
			// TODO: Which space ? Can't distinguish data vs. code/default space
			// I believe COMMON symbols must be allocated based upon their size.  These symbols
			// during the linking phase will generally be placed into a data section (e.g., .data, .bss)

		}
		else { // TODO: Identify which cases if any that this is valid

			// SHN_LORESERVE 0xff00
			// SHN_LOPROC 0xff00
			// SHN_HIPROC 0xff1f
			// SHN_COMMON 0xfff2
			// SHN_HIRESERVE 0xffff

			log("Unable to place symbol: " + elfSymbol.getNameAsString() +
				" - value=0x" + Long.toHexString(elfSymbol.getValue()) + ", section-index=0x" +
				Integer.toHexString(sectionIndex & 0xffff));
			return null;
		}

		Address address = symbolSpace.getTruncatedAddress(symOffset, true);
		if (symbolSpace.isOverlaySpace() && address.getAddressSpace() != symbolSpace) {
			// Ensure that address remains within correct symbol space
			address = symbolSpace.getAddressInThisSpaceOnly(address.getOffset());
		}

		if (elfSymbol.isAbsolute()) {
			// TODO: Many absolute values do not refer to memory at all
			// should we exclude certain absolute symbols (e.g., 0, 1)?

			//we will just use the symbols preferred address...
		}
		else if (elfSymbol.isExternal() || elfSymbol.isCommon()) {
			return Address.NO_ADDRESS;
		}
		else if (elf.isRelocatable()) {
			if (sectionIndex < 0 || sectionIndex >= elfSections.length) {
				log("Error creating symbol: " + elfSymbol.getNameAsString() +
					" - 0x" + Long.toHexString(elfSymbol.getValue()));
				return Address.NO_ADDRESS;
			}
			else if (symSectionBase == null) {
				log("No Memory for symbol: " + elfSymbol.getNameAsString() +
					" - 0x" + Long.toHexString(elfSymbol.getValue()));
				return Address.NO_ADDRESS;
			}
			else {
				// Section relative symbol - ensure that symbol remains in
				// overlay space even if beyond bounds of associated block
				// Note: don't use symOffset variable since it may have been
				//   adjusted for image base
				address = symSectionBase.addWrapSpace(elfSymbol.getValue() *
					symSectionBase.getAddressSpace().getAddressableUnitSize());
			}
		}
		else if (!elfSymbol.isSection() && elfSymbol.getValue() == 0) {
			return Address.NO_ADDRESS;
		}
		else if (elfSymbol.getValue() == 1) {
			// Most likely a Thumb Symbol...
			return Address.NO_ADDRESS;
		}

		return address;
	}

	/**
	 * Find memory register with matching name (ignoring leading and trailing underscore chars).
	 * @param elfSymbol ELF symbol
	 * @return register address if found or null
	 */
	private Address findMemoryRegister(ElfSymbol elfSymbol) {
		String name = elfSymbol.getNameAsString();
		Address regAddr = getMemoryRegister(name, elfSymbol.getValue());
		if (regAddr == null) {
			name = StringUtils.stripStart(name, "_");
			name = StringUtils.stripEnd(name, "_");
			regAddr = getMemoryRegister(name, elfSymbol.getValue());
		}
		return regAddr;
	}

	private Address getMemoryRegister(String name, long value) {
		Register reg = program.getRegister(name);
		if (reg != null && reg.getAddress().isMemoryAddress()) {
			Address a = reg.getAddress();
			if (value == 0 || value == a.getAddressableWordOffset()) {
				return a;
			}
		}
		return null;
	}

	/**
	 * Allocate external symbol storage within what will become the EXTERNAL memory block.
	 * @param elfSymbol external ELF symbol
	 * @return assigned EXTERNAL block address
	 * @throws AddressOutOfBoundsException if unable to allocate EXTERNAL block entry
	 */
	private Address allocateExternalSymbol(ElfSymbol elfSymbol) throws AddressOutOfBoundsException {
		long size = elfSymbol.getSize(); // TODO: Caution - could chew up a large area within EXTERNAL block
		int alignSize = elf.getLoadAdapter().getDefaultAlignment(this);
		// TODO: if symbol is COMMON should we allocate based upon its size ?
		if (elfSymbol.isObject() && size > 0 && size < Integer.MAX_VALUE) { // allocate sized data
			// maintain alignment of externalAddress
			size = NumericUtilities.getUnsignedAlignedValue(size, alignSize);
		}
		else {
			size = alignSize;
		}
		Address address = getNextExternalBlockEntryAddress((int) size);
		if (address == null) {
			throw new AddressOutOfBoundsException("failed to allocate EXTERNAL block entry");
		}
		return address;
	}

	/**
	 * Determine if an external ELF symbol has already been established with the
	 * same name and re-use it.
	 * @param elfSymbol external ELF symbol
	 * @return true if processed as a duplicate external symbol and no additional 
	 * processing is required, else false
	 */
	private boolean processDuplicateExternal(ElfSymbol elfSymbol) {
		if (lastExternalBlockEntryAddress == null) {
			return false;
		}
		String symName = elfSymbol.getNameAsString();
		Symbol s = findExternalBlockSymbol(symName, externalBlockLimits.getMinAddress(),
			lastExternalBlockEntryAddress);
		if (s != null) {
			// NOTE: re-use of other fake external address does not support
			// data allocation.  It may be necessary to ensure that dynamic 
			// symbol table is processed last.
			setElfSymbolAddress(elfSymbol, s.getAddress());
			return true;
		}
		return false;
	}

	/**
	 * Process ELF symbol if it has a versioned name.  Attempt to establish as 
	 * comment on associated external symbol.
	 * @param elfSymbol external ELF symbol
	 * @return true if processed and no additional processing is required, else false
	 */
	private boolean processVersionedExternal(ElfSymbol elfSymbol) {

		String symName = elfSymbol.getNameAsString();
		int index = symName.indexOf("@");
		if (index < 0) {
			return false;
		}

		// TODO: Versioned symbols may also exist on real addresses
		// corresponding to external linkages in the .got, .plt and 
		// other memory locations which may relate to external functions.
		// Unsure if this approach is appropriate since we are not 
		// handling these versioned symbols in a consistent fashion,
		// however their existence can interfere with demangling for
		// externals and related thunks.

		if (lastExternalBlockEntryAddress == null) {
			return false;
		}

		int altIndex = symName.indexOf("@@");
		if (altIndex > 0) {
			index = altIndex;
		}
		String realName = symName.substring(0, index);

		// Find real symbol (assumes real symbol is always processed first)
		Symbol s = findExternalBlockSymbol(realName, externalBlockLimits.getMinAddress(),
			lastExternalBlockEntryAddress);
		if (s == null) {
			return false;
		}

		// Add versioned symbol as comment only
		Address address = s.getAddress();
		String comment = listing.getComment(CodeUnit.PRE_COMMENT, address);
		if (comment == null || comment.length() == 0) {
			comment = symName;
		}
		else {
			comment += "\n" + symName;
		}
		listing.setComment(address, CodeUnit.PRE_COMMENT, comment);
		setElfSymbolAddress(elfSymbol, address);
		return true;
	}

	/**
	 * Find a specific named symbol within the fake EXTERNAL block.
	 * NOTE: It is assumed that ELF will never produced duplicate names.
	 * @param name symbol name
	 * @param extMin EXTERNAL block minimum address
	 * @param extMax EXTERNAL block maximum address
	 * @return matching symbol or null if not found
	 */
	private Symbol findExternalBlockSymbol(String name, Address extMin, Address extMax) {

		// try direct global name lookup first
		SymbolTable symbolTable = program.getSymbolTable();
		SymbolIterator symbols = symbolTable.getSymbols(name);
		for (Symbol symbol : symbols) {
			if (isSymbolInRange(symbol, extMin, extMax)) {
				return symbol;
			}
		}

		// Since we can't do a direct lookup of default thunk names
		// we must iterate over all symbols in the block to find a match
		SymbolIterator symbolIter = symbolTable.getSymbolIterator(extMin, true);
		while (symbolIter.hasNext()) {
			Symbol s = symbolIter.next();
			if (!isSymbolInRange(s, extMin, extMax)) {
				break;
			}
			if (name.equals(s.getName())) {
				return s;
			}
		}
		return null;
	}

	private boolean isSymbolInRange(Symbol s, Address min, Address max) {
		Address symAddr = s.getAddress();
		return (symAddr.compareTo(min) >= 0 && symAddr.compareTo(max) <= 0);
	}

	private void evaluateElfSymbol(ElfSymbol elfSymbol, Address address, boolean isFakeExternal)
			throws InvalidInputException {

		// allow extension to either modify symbol address or fully handle it
		address = elf.getLoadAdapter().evaluateElfSymbol(this, elfSymbol, address, isFakeExternal);
		if (address != null) {

			// Remember where in memory Elf symbols have been mapped
			setElfSymbolAddress(elfSymbol, address);

			if (address.isConstantAddress()) {
				// Do not add constant symbols to program symbol table
				// define as equate instead
				try {
					program.getEquateTable()
							.createEquate(elfSymbol.getNameAsString(), address.getOffset());
				}
				catch (DuplicateNameException | InvalidInputException e) {
					// ignore
				}
				return;
			}

			if (elfSymbol.isSection()) {
				// Do not add section symbols to program symbol table
				return;
			}

			String name = elfSymbol.getNameAsString();
			if (name == null) {
				return;
			}

			try {
				boolean isPrimary = (elfSymbol.getType() == ElfSymbol.STT_FUNC) ||
					(elfSymbol.getType() == ElfSymbol.STT_OBJECT) || (elfSymbol.getSize() != 0);
				// don't displace existing primary unless symbol is a function or object symbol
				if (name.contains("@")) {
					isPrimary = false; // do not make version symbol primary
				}
				else if (!isPrimary && (elfSymbol.isGlobal() || elfSymbol.isWeak())) {
					Symbol existingSym = program.getSymbolTable().getPrimarySymbol(address);
					isPrimary = (existingSym == null);
				}

				createSymbol(address, name, isPrimary, elfSymbol.isAbsolute(), null);

				// NOTE: treat weak symbols as global so that other programs may link to them.
				// In the future, we may want additional symbol flags to denote the distinction
				if ((elfSymbol.isGlobal() || elfSymbol.isWeak()) && !isFakeExternal) {
					program.getSymbolTable().addExternalEntryPoint(address);
				}

				if (elfSymbol.getType() == ElfSymbol.STT_FUNC) {
					Function existingFunction = program.getFunctionManager().getFunctionAt(address);
					if (existingFunction == null) {
						Function f = createOneByteFunction(null, address, false);
						if (f != null) {
							if (isFakeExternal && !f.isThunk()) {
								ExternalLocation extLoc = program.getExternalManager()
										.addExtFunction(Library.UNKNOWN, name, null,
											SourceType.IMPORTED);
								f.setThunkedFunction(extLoc.getFunction());
								// revert thunk function symbol to default source
								Symbol s = f.getSymbol();
								if (s.getSource() != SourceType.DEFAULT) {
									program.getSymbolTable().removeSymbolSpecial(f.getSymbol());
								}
							}
						}
					}
				}
			}
			catch (DuplicateNameException e) {
				throw new RuntimeException("Unexpected Exception", e);
			}
		}
	}

	@Override
	public void setElfSymbolAddress(ElfSymbol elfSymbol, Address address) {
		symbolMap.put(elfSymbol, address);
	}

	@Override
	public Address getElfSymbolAddress(ElfSymbol elfSymbol) {
		return symbolMap.get(elfSymbol);
	}

	@Override
	public void markAsCode(Address address) {
		// TODO: this should be in a common place, so all importers can communicate that something
		// is code or data.
		AddressSetPropertyMap codeProp = program.getAddressSetPropertyMap("CodeMap");
		if (codeProp == null) {
			try {
				codeProp = program.createAddressSetPropertyMap("CodeMap");
			}
			catch (DuplicateNameException e) {
				codeProp = program.getAddressSetPropertyMap("CodeMap");
			}
		}

		if (codeProp != null) {
			codeProp.add(address, address);
		}
	}

	@Override
	public Function createOneByteFunction(String name, Address address, boolean isEntry) {
		Function function = null;
		try {
			FunctionManager functionMgr = program.getFunctionManager();
			function = functionMgr.getFunctionAt(address);
			if (function == null) {
				function = functionMgr.createFunction(null, address, new AddressSet(address),
					SourceType.IMPORTED);
			}
		}
		catch (Exception e) {
			log("Error while creating function at " + address + ": " + getMessage(e));
		}

		try {
			if (name != null) {
				createSymbol(address, name, true, false, null);
			}
			if (isEntry) {
				program.getSymbolTable().addExternalEntryPoint(address);
			}
		}
		catch (Exception e) {
			log("Error while creating symbol " + name + " at " + address + ": " + getMessage(e));
		}
		return function;
	}

	@Override
	public Function createExternalFunctionLinkage(String name, Address functionAddr,
			Address indirectPointerAddr) {

		Function f = program.getFunctionManager().getFunctionAt(functionAddr);
		if (f == null) {
			f = createOneByteFunction(null, functionAddr, false);
			if (f == null) {
				return null;
			}
		}
		else if (f.isThunk()) {
			// linkage already exists
			return f;
		}

		ExternalLocation extLoc = null;
		try {
			extLoc = program.getExternalManager()
					.addExtFunction(Library.UNKNOWN, name, null, SourceType.IMPORTED);
		}
		catch (InvalidInputException e) {
			log.appendMsg("Failed to create external function '" + name + "': " + getMessage(e));
			return null;
		}
		catch (DuplicateNameException e) {
			// TODO: Elf will not have duplicate symbols so we should only have one and we want to use it
			extLoc = program.getExternalManager().getUniqueExternalLocation(Library.UNKNOWN, name);
		}

		if (indirectPointerAddr != null) {
			MemoryBlock block = memory.getBlock(indirectPointerAddr);
			if (block == null) {
				log.appendMsg("Indirect linkage memory not found at: " + indirectPointerAddr);
				return null;
			}
			try {
				if (!block.isInitialized()) {
					memory.convertToInitialized(block, (byte) 0);
				}
				if (program.getDefaultPointerSize() != (elf.is64Bit() ? 8 : 4)) {
					log.appendMsg(
						"Unsupported pointer size for indirect linkage at: " + indirectPointerAddr);
					return null;
				}
				if (elf.is64Bit()) {
					memory.setLong(indirectPointerAddr, functionAddr.getAddressableWordOffset());
				}
				else {
					memory.setInt(indirectPointerAddr,
						(int) functionAddr.getAddressableWordOffset());
				}
			}
			catch (Exception e) {
				log.appendMsg("Failed to establish linkage to external function '" + name + "': " +
					getMessage(e));
				return null;
			}
			// Create constant pointer
			Data data = createData(indirectPointerAddr, PointerDataType.dataType);
			MutabilitySettingsDefinition.DEF.setChoice(data, MutabilitySettingsDefinition.CONSTANT);
		}

		// Create thunk function
		f.setThunkedFunction(extLoc.getFunction());

		// Remove original matching symbol to ensure that demangling only occurs within library namespace.
		// If more than one symbol resides at the linkage location, symbols must remain intact
		// NOTE: proper handling of versioned symbols (e.g., foo@GLIBC_2.0) is still unresolved
		if (indirectPointerAddr == null || !removeOldSymbol(indirectPointerAddr, name)) {
			removeOldSymbol(functionAddr, name);
		}

		return f;
	}

	/**
	 * When transitioning to an external thunk, remove the old symbol on the linkage pointer/thunk
	 * if it is the only symbol at that address.
	 * @param address symbol address
	 * @param name symbol name
	 * @return true if symbol removed, else false
	 */
	private boolean removeOldSymbol(Address address, String name) {
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol[] symbols = symbolTable.getSymbols(address);
		if (symbols.length == 1 && name.equals(symbols[0].getName())) {
			symbolTable.removeSymbolSpecial(symbols[0]);
			return true;
		}
		return false;
	}

	@Override
	public Data createUndefinedData(Address address, int length) {
		try {
			// If it is bigger than 8, just let it go through and create a single undefined
			// Otherwise this would create an array of undefined, might get in the way
			// TODO: how to really handle something bigger.
			if (length > 8) {
				length = 1;
			}
			if (length == 0) {
				length = 1;
			}
			Data d = listing.getDefinedDataAt(address);
			if (d != null && d.getLength() == length) {
				return d;
			}
			listing.createData(address, Undefined.getUndefinedDataType(length));
		}
		catch (CodeUnitInsertionException e) {
			Msg.warn(this, "ELF data markup conflict at " + address);
		}
		catch (DataTypeConflictException e) {
			throw new AssertException("unexpected", e);
		}
		return null;
	}

	@Override
	public Data createData(Address address, DataType dt) {
		try {
			Data d = listing.getDataAt(address);
			if (d == null || !dt.isEquivalent(d.getDataType())) {
				d = DataUtilities.createData(program, address, dt, -1, false,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			}
			return d;
		}
		catch (CodeUnitInsertionException e) {
			Msg.warn(this, "ELF data markup conflict at " + address);
		}
		catch (DataTypeConflictException e) {
			Msg.error(this, "ELF data type markup conflict:" + getMessage(e));
		}
		return null;
	}

//	private static final Integer AVAILABLE_MEMORY = 1;
//	private static final Integer ALLOCATED_MEMORY = 2;
//
//	/**
//	 * Find free address associated with the largest unallocated memory range.
//	 * The first 0x1000 bytes are considered off-limits for this purpose.  The returned
//	 * address will be aligned to the nearest 0x100 byte boundary. 
//	 * NOTE: addition consideration may be need for spaces with odd word sizes
//	 * or small 16-bit memory spaces.   In addition, small processors with 
//	 * shared memory regions may also have additional constraints not considered here.
//	 */
//	private AddressRange findFreeAddressRange(AddressSpace space) {
//
//		if (space != space.getPhysicalSpace()) {
//			throw new AssertException();
//		}
//
//		long alignment = space.getAddressableUnitSize() * 0x1000;
//
//		// Build range map: 1 marks valid addresses region, 2 marks defined blocks
//		// Avoid minimum range of addresses
//		AddressRangeObjectMap<Integer> map = new AddressRangeObjectMap<>();
//		map.setObject(space.getAddress(alignment, true), space.getMaxAddress(), AVAILABLE_MEMORY);
//
//		for (MemoryBlock block : memory.getBlocks()) {
//			// only consider physical addresses
//			Address blockStart = block.getStart().getPhysicalAddress();
//			if (space.equals(blockStart.getAddressSpace())) {
//				map.setObject(blockStart, block.getEnd().getPhysicalAddress(), ALLOCATED_MEMORY);
//			}
//		}
//
//		// Identify the largest unallocated range
//		AddressRange maxRange = null;
//		BigInteger maxRangeLength = null;
//
//		// Give preference to last unallocated range whose size
//		// should be big-enough (i.e., 128 K-Bytes)
//		BigInteger minRangeSize = BigInteger.valueOf(0x20000); // 128 K-Bytes
//		AddressRange lastBigUnallocatedRange = null;
//
//		AddressRangeIterator rangeIterator = map.getAddressRangeIterator();
//		while (rangeIterator.hasNext()) {
//			AddressRange range = rangeIterator.next();
//			Integer value = map.getObject(range.getMinAddress());
//			if (!AVAILABLE_MEMORY.equals(value)) {
//				continue;
//			}
//			BigInteger rangeLength = range.getBigLength();
//			if (maxRangeLength == null || maxRangeLength.compareTo(rangeLength) < 0) {
//				maxRange = range;
//				maxRangeLength = rangeLength;
//			}
//			if (rangeLength.compareTo(bigRange) >= 0) {
//				lastBigUnallocatedRange = range;
//			}
//		}
//
//		if (maxRange == null) {
//			Msg.error(this,
//				"Failed to find unallocated memory required for EXTERNAL block or other relocation artifcacts: " +
//					program.getName());
//			return null; // NOTE: this will likely cause other errors to follow
//		}
//
//		// Return aligned address range
//		AddressRange freeRange = maxRange;
//		if (lastBigUnallocatedRange != null &&
//			lastBigUnallocatedRange.getMinAddress().compareTo(maxRange.getMinAddress()) > 0) {
//			// prefer the last unallocated range if it is a big range (need not be the biggest)
//			freeRange = lastBigUnallocatedRange;
//		}
//
//		Address addr = freeRange.getMinAddress();
//		Address alignedAddress = addr.getNewAddress(getAlignedValue(addr.getOffset(), alignment));
//		if (!maxRange.contains(alignedAddress)) {
//			// TODO: how should we handle this condition - use reduced alignment value
//			alignment = space.getAddressableUnitSize() * 0x10;
//			alignedAddress = addr.getNewAddress(getAlignedValue(addr.getOffset(), alignment));
//		}
//		return new AddressRangeImpl(alignedAddress, freeRange.getMaxAddress());
//	}

	private void markupGnuBuildId(TaskMonitor monitor) {

		ElfSectionHeader sh = elf.getSection(".note.gnu.build-id");
		Address addr = findLoadAddress(sh, 0);
		if (addr == null) {
			return;
		}
		try {
			listing.createData(addr,
				new GnuBuildIdSection(program.getDataTypeManager(), sh.getSize()));
		}
		catch (Exception e) {
			log("Failed to properly markup Gnu Build-Id at " + addr + ": " + getMessage(e));
		}
	}

	private void markupGnuDebugLink(TaskMonitor monitor) {

		ElfSectionHeader sh = elf.getSection(".gnu_debuglink");
		Address addr = findLoadAddress(sh, 0);
		if (addr == null) {
			return;
		}
		try {
			listing.createData(addr,
				new GnuDebugLinkSection(program.getDataTypeManager(), sh.getSize()));
		}
		catch (Exception e) {
			log("Failed to properly markup Gnu DebugLink at " + addr + ": " + getMessage(e));
		}
	}

	private void markupHashTable(TaskMonitor monitor) {

		ElfDynamicTable dynamicTable = elf.getDynamicTable();
		if (dynamicTable == null || !dynamicTable.containsDynamicValue(ElfDynamicType.DT_HASH)) {
			return;
		}

		DataType dt = DWordDataType.dataType;
		Address hashTableAddr = null;
		try {
			long value = dynamicTable.getDynamicValue(ElfDynamicType.DT_HASH);
			if (value == 0) {
				return; // table has been stripped
			}

			hashTableAddr = getDefaultAddress(elf.adjustAddressForPrelink(value));

			Address addr = hashTableAddr;
			Data d = listing.createData(addr, dt);
			d.setComment(CodeUnit.EOL_COMMENT, "Hash Table - nbucket");
			long nbucket = d.getScalar(0).getUnsignedValue();

			addr = addr.add(d.getLength());
			d = listing.createData(addr, dt);
			d.setComment(CodeUnit.EOL_COMMENT, "Hash Table - nchain");
			long nchain = d.getScalar(0).getUnsignedValue();

			addr = addr.add(d.getLength());
			d = listing.createData(addr, new ArrayDataType(dt, (int) nbucket, dt.getLength()));
			d.setComment(CodeUnit.EOL_COMMENT, "Hash Table - buckets");

			addr = addr.add(d.getLength());
			d = listing.createData(addr, new ArrayDataType(dt, (int) nchain, dt.getLength()));
			d.setComment(CodeUnit.EOL_COMMENT, "Hash Table - chains");
		}
		catch (Exception e) {
			log("Failed to properly markup Hash table at " + hashTableAddr + ": " + getMessage(e));
			return;
		}

	}

	private void markupGnuHashTable(TaskMonitor monitor) {

		ElfDynamicTable dynamicTable = elf.getDynamicTable();
		if (dynamicTable == null ||
			!dynamicTable.containsDynamicValue(ElfDynamicType.DT_GNU_HASH)) {
			return;
		}

		DataType dt = DWordDataType.dataType;
		Address hashTableAddr = null;
		try {
			long value = dynamicTable.getDynamicValue(ElfDynamicType.DT_GNU_HASH);
			if (value == 0) {
				return; // table has been stripped
			}

			hashTableAddr = getDefaultAddress(elf.adjustAddressForPrelink(value));

			Address addr = hashTableAddr;
			Data d = listing.createData(addr, dt);
			d.setComment(CodeUnit.EOL_COMMENT, "GNU Hash Table - nbucket");
			long nbucket = d.getScalar(0).getUnsignedValue();

			addr = addr.add(d.getLength());
			d = listing.createData(addr, dt);
			d.setComment(CodeUnit.EOL_COMMENT, "GNU Hash Table - symbase");
			long symbolBase = d.getScalar(0).getUnsignedValue();

			addr = addr.add(d.getLength());
			d = listing.createData(addr, dt);
			d.setComment(CodeUnit.EOL_COMMENT, "GNU Hash Table - bloom_size");
			long bloomSize = d.getScalar(0).getUnsignedValue();

			addr = addr.add(d.getLength());
			d = listing.createData(addr, dt);
			d.setComment(CodeUnit.EOL_COMMENT, "GNU Hash Table - bloom_shift");

			addr = addr.add(d.getLength());
			DataType bloomDataType =
				elf.is64Bit() ? QWordDataType.dataType : DWordDataType.dataType;
			d = listing.createData(addr,
				new ArrayDataType(bloomDataType, (int) bloomSize, bloomDataType.getLength()));
			d.setComment(CodeUnit.EOL_COMMENT, "GNU Hash Table - bloom");

			addr = addr.add(d.getLength());
			d = listing.createData(addr, new ArrayDataType(dt, (int) nbucket, dt.getLength()));
			d.setComment(CodeUnit.EOL_COMMENT, "GNU Hash Table - chains");

			addr = addr.add(d.getLength());
			listing.setComment(addr, CodeUnit.EOL_COMMENT, "GNU Hash Table - chain");

			// Rely on dynamic symbol table for number of symbols
			ElfSymbolTable dynamicSymbolTable = elf.getDynamicSymbolTable();
			if (dynamicSymbolTable == null) {
				Msg.error(this,
					"Failed to markup GNU Hash Table chain data - missing dynamic symbol table");
				return;
			}

			int chainSize = dynamicSymbolTable.getSymbolCount() - (int) symbolBase;
			d = listing.createData(addr, new ArrayDataType(dt, chainSize, dt.getLength()));

		}
		catch (Exception e) {
			log("Failed to properly markup GNU Hash table at " + hashTableAddr + ": " +
				getMessage(e));
			return;
		}

	}

	private void markupSymbolTable(Address symbolTableAddr, ElfSymbolTable symbolTable,
			TaskMonitor monitor) {

		Data array = null;
		try {
			array = listing.createData(symbolTableAddr, symbolTable.toDataType());
		}
		catch (Exception e) {
			log("Failed to properly markup symbol table at " + symbolTableAddr + ": " +
				getMessage(e));
			return;
		}

		ElfSymbol[] symbols = symbolTable.getSymbols();
		for (int i = 0; i < symbols.length; ++i) {
			int stringOffset = symbols[i].getName();
			if (stringOffset == 0) {
				continue;
			}
			Data structData = array.getComponent(i);
			if (structData != null) {
				structData.setComment(CodeUnit.EOL_COMMENT, symbols[i].getNameAsString());
			}
		}
	}

	private void markupDynamicTable(TaskMonitor monitor) {

		// Assume default space for pointers

		Address dynamicTableAddress = null;
		try {
			ElfDynamicTable dynamicTable = elf.getDynamicTable();
			if (dynamicTable == null) {
				return;
			}

			dynamicTableAddress = findLoadAddress(dynamicTable.getFileOffset(), 1);
			if (dynamicTableAddress == null) {
				log("Failed to locate dynamic table at file offset 0x" +
					Long.toHexString(dynamicTable.getFileOffset()));
				return;
			}

			createSymbol(dynamicTableAddress, "_DYNAMIC", false, false, null);

			ElfDynamic[] dynamics = dynamicTable.getDynamics();

			DataType structArray = dynamicTable.toDataType();
			Data dynamicTableData = createData(dynamicTableAddress, structArray);
			if (dynamicTableData == null) {
				return;
			}

			for (int i = 0; i < dynamics.length; i++) {

				Data dynamicData = dynamicTableData.getComponent(i);
				if (dynamicData == null) {
					return;
				}

				long value = dynamics[i].getValue();
				int tagType = dynamics[i].getTag();

				ElfDynamicType dynamicType = elf.getDynamicType(tagType);

				String comment =
					dynamicType != null ? (dynamicType.name + " - " + dynamicType.description)
							: ("DT_0x" + StringUtilities.pad(Integer.toHexString(tagType), '0', 8));
				dynamicData.setComment(CodeUnit.EOL_COMMENT, comment);

				Data valueData = dynamicData.getComponent(1);

				if (dynamicType != null) {
					if (dynamicType.valueType == ElfDynamicValueType.ADDRESS) {
						addDynamicMemoryReference(dynamics[i], valueData, false,
							"_" + dynamicType.name);
					}
					else if (dynamicType.valueType == ElfDynamicValueType.STRING) {
						ElfStringTable dynamicStringTable = elf.getDynamicStringTable();
						if (dynamicStringTable != null) {
							String str = dynamicStringTable.readString(elf.getReader(), value);
							if (str != null) {
								valueData.setComment(CodeUnit.EOL_COMMENT, str);
							}
						}
					}
				}

			}
		}
		catch (Exception e) {
			log("Failed to process dynamic section: " + getMessage(e));
		}
	}

	/**
	 * Add memory reference to dynamic table value and return the referenced address
	 * specified by the value
	 * @param elfDynamic
	 * @param valueData
	 * @param definedMemoryOnly
	 * @param label
	 * @return referenced address specified by the value
	 * @throws InvalidInputException
	 */
	private Address addDynamicMemoryReference(ElfDynamic elfDynamic, Data valueData,
			boolean definedMemoryOnly, String label) throws InvalidInputException {
		Scalar value = valueData.getScalar(0);
		if (value == null || value.getUnsignedValue() == 0) {
			return null;
		}
		Address refAddr = getDefaultAddress(elf.adjustAddressForPrelink(value.getValue()));
		if (!definedMemoryOnly || memory.getBlock(refAddr) != null) {
			program.getReferenceManager()
					.addMemoryReference(valueData.getAddress(), refAddr, RefType.DATA,
						SourceType.ANALYSIS, 0);
			if (label != null) {
				// add label if no label exists of there is just a default label
				Symbol symbol = program.getSymbolTable().getPrimarySymbol(refAddr);
				if (symbol == null || symbol.getSource() == SourceType.DEFAULT) {
					createSymbol(refAddr, "_" + label, false, false, null);
				}
			}
		}
		return refAddr;
	}

	private void processStringTables(TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Processing string tables...");
		monitor.setShowProgressValue(false);

		ElfStringTable[] stringTables = elf.getStringTables();

		long totalLength = 0;
		for (ElfStringTable stringTable : stringTables) {
			totalLength += stringTable.getLength();
		}
		monitor.initialize(totalLength);

		for (ElfStringTable stringTable : stringTables) {
			monitor.checkCanceled();

			Address stringTableAddr = null;

			ElfSectionHeader section = stringTable.getTableSectionHeader();
			if (section != null) {
				stringTableAddr = findLoadAddress(section, 0);
			}
			else {
				stringTableAddr = findLoadAddress(stringTable.getFileOffset(), 1);
			}
			if (stringTableAddr == null) {
//				log("Failed to locate string table at file offset 0x" +
//					Long.toHexString(stringTable.getFileOffset()));
				monitor.incrementProgress(stringTable.getLength()); // skipping table
				continue;
			}

			AddressRange rangeConstraint = getMarkupMemoryRangeConstraint(stringTableAddr);
			if (rangeConstraint == null) {
				monitor.incrementProgress(stringTable.getLength()); // skipping table
				continue;
			}

			long tblLength = stringTable.getLength();
			long limit = Math.min(tblLength, rangeConstraint.getLength());
			if (limit < tblLength) {
				monitor.incrementProgress(tblLength - limit);
			}

			markupStringTable(stringTableAddr, limit, monitor);
		}

		monitor.setShowProgressValue(true);
	}

	private void markupStringTable(Address address, long tableBytesLength, TaskMonitor monitor) {

		MemoryBlock block = memory.getBlock(address);
		if (block == null || tableBytesLength <= 0) {
			return;
		}

		try {
			Address end = address.addNoWrap(tableBytesLength - 1);
			if (end.compareTo(block.getEnd()) > 0) {
				end = block.getEnd();
			}

			address = address.addNoWrap(1);
			while (!monitor.isCancelled() && address.compareTo(end) < 0) {
				int length = createString(address);
				monitor.incrementProgress(length);
				address = address.addNoWrap(length);
			}
		}
		catch (AddressOverflowException | CodeUnitInsertionException e) {
			return; // ignore end of space and code unit collision caused by previous markup
		}
		catch (Exception e) {
			log(e);
		}
	}

	private int createString(Address address)
			throws CodeUnitInsertionException, DataTypeConflictException {
		Data d = listing.getDataAt(address);
		if (d == null || !TerminatedStringDataType.dataType.isEquivalent(d.getDataType())) {
			d = listing.createData(address, TerminatedStringDataType.dataType, -1);
		}
		return d.getLength();
	}

	@Override
	public Address getDefaultAddress(long addressableWordOffset) {
		addressableWordOffset += getImageBaseWordAdjustmentOffset(); // image base adjustment
		return getDefaultAddressSpace().getTruncatedAddress(addressableWordOffset, true);
	}

	/**
	 * Get the load address space for a program segment.
	 * Non-allocated segments may return the OTHER space.
	 * @param elfProgramHeader elf program segment header
	 * @return preferred load address space
	 */
	private AddressSpace getSegmentAddressSpace(ElfProgramHeader elfProgramHeader) {
		if (elfProgramHeader.getType() != ElfProgramHeaderConstants.PT_LOAD &&
			elfProgramHeader.getVirtualAddress() == 0) {
			return AddressSpace.OTHER_SPACE;
		}
		return elf.getLoadAdapter().getPreferredSegmentAddressSpace(this, elfProgramHeader);
	}

	/**
	 * Determine segment preferred physical load address (not overlay address).
	 * While this method can produce the intended load address, there is no guarantee that
	 * the segment data did not get bumped into an overlay area due to a conflict with
	 * another segment or section.
	 * @param elfProgramHeader
	 * @return segment load address
	 */
	private Address getSegmentLoadAddress(ElfProgramHeader elfProgramHeader) {
		AddressSpace space = getSegmentAddressSpace(elfProgramHeader);
		if (!space.isLoadedMemorySpace()) {
			// handle non-loaded sections into the OTHER space
			long addrWordOffset = elfProgramHeader.getVirtualAddress();
			return space.getTruncatedAddress(addrWordOffset, true);
		}

		return elf.getLoadAdapter().getPreferredSegmentAddress(this, elfProgramHeader);
	}

	/**
	 * Determine preferred section load address address space prior to load.
	 * Non-allocated sections may return the OTHER space or an existing OTHER 
	 * overlay established by a program header.
	 * @param elfSectionHeader
	 * @return section load address space
	 */
	private AddressSpace getSectionAddressSpace(ElfSectionHeader elfSectionHeader) {

		if (!elfSectionHeader.isAlloc()) {

			// The alloc bit specifies whether this block exists in memory at runtime.
			//    If it doesn't throw it into an OTHER overlay block.

			// Check for overlay space (previously overlayed on OTHER space)
			AddressSpace space =
				program.getAddressFactory().getAddressSpace(elfSectionHeader.getNameAsString());
			if (space == null) {
				space = AddressSpace.OTHER_SPACE; // overlay not yet created
			}
			return space;
		}

		return elf.getLoadAdapter().getPreferredSectionAddressSpace(this, elfSectionHeader);
	}

	/**
	 * Determine section's load address.  
	 * @param elfSectionHeader
	 * @return section load address
	 */
	private Address getSectionLoadAddress(ElfSectionHeader elfSectionHeader) {

		AddressSpace space = getSectionAddressSpace(elfSectionHeader);
		if (!space.isLoadedMemorySpace()) {
			// handle non-loaded sections into the OTHER space
			long addrWordOffset = elfSectionHeader.getAddress();
			return space.getTruncatedAddress(addrWordOffset, true);
		}

		return elf.getLoadAdapter().getPreferredSectionAddress(this, elfSectionHeader);
	}

	@Override
	public Address findLoadAddress(MemoryLoadable section, long byteOffsetWithinSection) {

		if (section == null) {
			return null;
		}

		List<AddressRange> resolvedLoadAddresses = getResolvedLoadAddresses(section);
		if (resolvedLoadAddresses == null) {

			// assume loaded segment/section superseded by PT_LOAD segment or allocated section

// TODO: Watch out for negative long addresses !!!!!!

			if (section instanceof ElfProgramHeader) {
				ElfProgramHeader programHeader = (ElfProgramHeader) section;
// FIXME! Inconsistent in use of VirtualAddress which is generally an addressable word offset - not byte offset
				long offsetAddr = programHeader.getVirtualAddress() + byteOffsetWithinSection;

				if (programHeader.getType() != ElfProgramHeaderConstants.PT_LOAD) {
					// Check for PT_LOAD segment which may contain requested segment
					ElfProgramHeader loadHeader = elf.getProgramLoadHeaderContaining(offsetAddr);
					if (loadHeader != null) {
						return findLoadAddress(loadHeader,
							offsetAddr - loadHeader.getVirtualAddress());
					}
				}

				// PT_LOAD segment must have been superseded by section load
				ElfSectionHeader sectionHeader = elf.getSectionLoadHeaderContaining(offsetAddr);
				if (sectionHeader != null) {
					return findLoadAddress(sectionHeader, offsetAddr - sectionHeader.getAddress());
				}
			}
			else if (section instanceof ElfSectionHeader) {
				ElfSectionHeader s = (ElfSectionHeader) section;
				if (s.isAlloc()) {
					return getSectionLoadAddress(s);
				}
			}

			return null; // failed to locate
		}

		long offset = byteOffsetWithinSection; // track byte offset within section
		AddressRange containingRange = null;
		for (AddressRange range : resolvedLoadAddresses) {
			long rangeLength = range.getLength();
			if (offset < rangeLength) {
				containingRange = range;
				break;
			}
			offset -= rangeLength;
		}
		if (containingRange == null) {
			if (!resolvedLoadAddresses.isEmpty()) {
				// Not contained within loaded bytes - compute relative to block start.
				// Always return non-overlay address
				return resolvedLoadAddresses.get(0)
						.getMinAddress()
						.add(byteOffsetWithinSection)
						.getPhysicalAddress();
			}
			return null;
		}
		return containingRange.getMinAddress().add(offset);
	}

	/**
	 * Locate an Elf file header/structure within loaded memory based upon its file offset.
	 * Preference is given to an allocated section over segments.
	 * This method assumes filter loads will not be employed for the referenced file
	 * location (e.g., ELF data structures).
	 * TODO: This could be a problem for dynamic
	 * @param fileOffset data offset within file
	 * @param headerSize number of bytes required (minimum value of 1)
	 * @return load address or null if not loaded or load was possibly fragmented.
	 */
	private Address findLoadAddress(long fileOffset, long headerSize) {

		long headerEndOffset = fileOffset + headerSize - 1;

		// Locate possible load of Elf header within section (i.e., start of file)
		Address headerAddr = null;
		for (ElfSectionHeader section : elf.getSections()) {
			if (section.getType() == ElfSectionHeaderConstants.SHT_NOBITS) {
				continue;
			}
			long startOffset = section.getOffset();
			if (startOffset < 0) {
				continue;
			}
			long endOffset = startOffset + section.getSize() - 1;
			if (fileOffset >= startOffset && headerEndOffset <= endOffset) {
				headerAddr = findLoadAddress(section, fileOffset - section.getOffset());
				if (headerAddr != null) {
					return headerAddr;
				}
			}
		}

		// Locate possible load of Elf header within segment
		for (ElfProgramHeader segment : elf.getProgramHeaders()) {
			if (segment.getType() == ElfProgramHeaderConstants.PT_NULL) {
				continue;
			}
			long startOffset = segment.getOffset();
			if (startOffset < 0) {
				continue;
			}
			long endOffset = startOffset + segment.getFileSize() - 1;
			if (fileOffset >= startOffset && headerEndOffset <= endOffset) {
				headerAddr = findLoadAddress(segment, fileOffset - segment.getOffset());
				if (headerAddr != null && segment.getType() == ElfProgramHeaderConstants.PT_LOAD) {
					return headerAddr;
				}
			}
		}

		return headerAddr;
	}

	/**
	 * Expand/create PT_LOAD program header block regions which are zeroed
	 * - to the extent possible.  This should only be done when section headers are
	 * not present.
	 * @param monitor
	 * @throws CancelledException
	 */
	private void expandProgramHeaderBlocks(TaskMonitor monitor) throws CancelledException {
		ElfProgramHeader[] elfProgramHeaders = elf.getProgramHeaders();
		for (int i = 0; i < elfProgramHeaders.length; ++i) {
			monitor.checkCanceled();
			ElfProgramHeader elfProgramHeader = elfProgramHeaders[i];
			if (elfProgramHeaders[i].getType() == ElfProgramHeaderConstants.PT_LOAD) {

				MemoryBlock block = null;
				AddressSpace space;
				Address expandStart;

				long segmentMemorySizeBytes = elfProgramHeader.getAdjustedMemorySize();
				if (segmentMemorySizeBytes <= 0) {
					continue;
				}

				long loadSizeBytes = elfProgramHeader.getAdjustedLoadSize();
				if (loadSizeBytes == 0) {
					expandStart = getSegmentLoadAddress(elfProgramHeader);
					space = expandStart.getAddressSpace();
				}
				else {
					// Identify resolved segment block tail-end
					List<AddressRange> resolvedLoadAddresses =
						getResolvedLoadAddresses(elfProgramHeader);
					AddressRange addressRange =
						resolvedLoadAddresses.get(resolvedLoadAddresses.size() - 1);
					Address endAddr = addressRange.getMaxAddress();
					space = endAddr.getAddressSpace();
					if (space.isOverlaySpace()) {
						continue; // tail-end was displaced by another - do not extend
					}
					block = memory.getBlock(endAddr);
					if (!block.getEnd().equals(endAddr)) {
						continue; // tail-end merged with another - do not extend
					}
					expandStart = endAddr.add(1);
				}

				long fullSizeBytes = segmentMemorySizeBytes;
				if (expandStart == null || fullSizeBytes <= loadSizeBytes) {
					continue; //
				}

				try {
					long expandSize = fullSizeBytes - loadSizeBytes;
					Address expandEnd = expandStart.addNoWrap(expandSize - 1);
					AddressSet intersectRange = memory.intersectRange(expandStart, expandEnd);
					if (!intersectRange.isEmpty()) {
						Address firstIntersectAddr = intersectRange.getFirstRange().getMinAddress();
						if (expandStart.equals(firstIntersectAddr)) {
							continue; // no room for expansion
						}
						expandEnd = firstIntersectAddr.previous();
					}
					if (block == null) {
						// Create new zeroed segment block with no bytes from file
						String blockName = String.format("%s%d", SEGMENT_NAME_PREFIX, i);
						MemoryBlock newBlock = memory.createInitializedBlock(blockName, expandStart,
							expandSize, (byte) 0,
							monitor, false);
						newBlock.setSourceName(BLOCK_SOURCE_NAME);
						newBlock.setComment("Zero-initialized segment");
					}
					else {
						// Expand tail end of segment which had portion loaded from file
						Address oldBlockEnd = block.getEnd();
						MemoryBlock expandBlock =
							memory.createInitializedBlock(block.getName() + ".expand", expandStart,
								expandSize, (byte) 0, monitor, false);
						MemoryBlock extBlock = memory.join(block, expandBlock);
						extBlock.setComment(extBlock.getComment() + " (zero-extended)");
						joinProgramTreeFragments(oldBlockEnd, expandStart);
					}
				}
				catch (Exception e) {
					log("Failed to " + (block != null ? "expand" : "create") + " segment [" + i +
						"," + elfProgramHeader.getDescription() + "] at address " +
						expandStart.toString(true));
				}
			}
		}
	}

	private void joinProgramTreeFragments(Address block1End, Address block2Start) {
		try {
			String[] treeNames = listing.getTreeNames();
			for (String treeName : treeNames) {
				ProgramFragment frag1 = listing.getFragment(treeName, block1End);
				ProgramFragment frag2 = listing.getFragment(treeName, block2Start);
				frag1.move(frag2.getMinAddress(), frag2.getMaxAddress());
				for (ProgramModule module : frag2.getParents()) {
					if (frag2.isEmpty()) {
						module.removeChild(frag2.getName());
					}
				}
			}
		}
		catch (NotEmptyException | NotFoundException e) {
			// ignore
		}
	}

	private void processProgramHeaders(TaskMonitor monitor) throws CancelledException {

		if (elf.isRelocatable() && elf.e_phnum() != 0) {
			log("Ignoring unexpected program headers for relocatable ELF (e_phnum=" +
				elf.e_phnum() + ")");
			return;
		}

		monitor.setMessage("Processing program headers...");

		boolean includeOtherBlocks = ElfLoaderOptionsFactory.includeOtherBlocks(options);

		ElfProgramHeader[] elfProgramHeaders = elf.getProgramHeaders();
		for (int i = 0; i < elfProgramHeaders.length; ++i) {
			monitor.checkCanceled();
			ElfProgramHeader elfProgramHeader = elfProgramHeaders[i];
			if (elfProgramHeader.getType() == ElfProgramHeaderConstants.PT_NULL) {
				continue;
			}
			long fileOffset = elfProgramHeader.getOffset();
			if (elfProgramHeader.getType() != ElfProgramHeaderConstants.PT_LOAD) {
				if (!includeOtherBlocks) {
					continue;
				}
				if (fileOffset < 0 || fileOffset >= fileBytes.getSize()) {
					log("Skipping segment[" + i + ", " + elfProgramHeader.getDescription() +
						"] with invalid file offset");
					continue;
				}
				if (elf.getProgramLoadHeaderContainingFileOffset(fileOffset) != null) {
					continue;
				}
				ElfSectionHeader section = elf.getSectionHeaderContainingFileRange(fileOffset,
					elfProgramHeader.getFileSize());
				if (section != null) {
					log("Skipping segment[" + i + ", " + elfProgramHeader.getDescription() +
						"] included by section " + section.getNameAsString());
					continue;
				}
			}
			if (fileOffset < 0 || fileOffset >= fileBytes.getSize()) {
				log("Skipping PT_LOAD segment[" + i + ", " + elfProgramHeader.getDescription() +
					"] with invalid file offset");
				continue;
			}
			processProgramHeader(elfProgramHeader, i);
		}
	}

	/**
	 * Process the specified program header by ensuring that it has a suitable memory address assigned
	 * and added to the memory resolver.
	 * @param elfProgramHeader ELF program header to be processed
	 * @param segmentNumber program header index number
	 * @throws AddressOutOfBoundsException if an invalid memory address is encountered
	 */
	private void processProgramHeader(ElfProgramHeader elfProgramHeader, int segmentNumber)
			throws AddressOutOfBoundsException {

// FIXME: If physical and virtual addresses do not match this may be an overlay situation.
// If sections exist they should use file offsets to correlate to overlay segment - the
// problem is that we can only handle a single memory block per overlay range - we may need to
// not load segment in this case and defer to section!!  Such situations may also
// occur for mapped memory regions as seen with some Harvard Architecture processors.  The
// process-specific extension should control the outcome.

		Address address = getSegmentLoadAddress(elfProgramHeader);
		AddressSpace space = address.getAddressSpace();

		long addr = elfProgramHeader.getVirtualAddress();
		long loadSizeBytes = elfProgramHeader.getAdjustedLoadSize();
		long fullSizeBytes = elfProgramHeader.getAdjustedMemorySize();

		boolean maintainExecuteBit = elf.e_shnum() == 0;

		if (fullSizeBytes <= 0) {
			log("Skipping zero-length segment [" + segmentNumber + "," +
				elfProgramHeader.getDescription() + "] at address " + address.toString(true));
			return;
		}

		if (!space.isValidRange(address.getOffset(), fullSizeBytes)) {
			log("Skipping unloadable segment [" + segmentNumber + "] at address " +
				address.toString(true) + " (size=" + fullSizeBytes + ")");
			return;
		}

		try {
			// Only allow segment fragmentation if section headers are defined
			boolean isFragmentationOK = (elf.e_shnum() != 0);

			String comment = getSectionComment(addr, fullSizeBytes, space.getAddressableUnitSize(),
				elfProgramHeader.getDescription(), address.isLoadedMemoryAddress());
			if (!maintainExecuteBit && elfProgramHeader.isExecute()) {
				comment += " (disabled execute bit)";
			}

			String blockName = String.format("%s%d", SEGMENT_NAME_PREFIX, segmentNumber);
			if (loadSizeBytes != 0) {
				addInitializedMemorySection(elfProgramHeader, elfProgramHeader.getOffset(),
					loadSizeBytes, address, blockName, elfProgramHeader.isRead(),
					elfProgramHeader.isWrite(),
					maintainExecuteBit ? elfProgramHeader.isExecute() : false, comment,
					isFragmentationOK,
					elfProgramHeader.getType() == ElfProgramHeaderConstants.PT_LOAD);
			}

			// NOTE: Uninitialized portions of segments will be added via expandProgramHeaderBlocks
			// when no sections are present.  When sections are present, we assume sections will
			// be created which correspond to these areas.
		}
		catch (AddressOverflowException e) {
			log("Failed to load segment [" + segmentNumber + "]: " + getMessage(e));
		}
	}

	private String getSectionComment(long addr, long byteSize, int addressableUnitSize,
			String description, boolean loaded) {
		StringBuilder buf = new StringBuilder();
		if (description != null) {
			buf.append(description);
			buf.append(' ');
		}
		if (loaded) {
			if (buf.length() != 0) {
				buf.append(' ');
			}
			BigInteger max = BigInteger.valueOf(addr)
					.add(BigInteger.valueOf(byteSize / addressableUnitSize))
					.subtract(BigInteger.ONE);
			buf.append(String.format("[0x%x - 0x%s]", addr, max.toString(16)));
		}
		else {
			buf.append("[not-loaded]");
		}
		return buf.toString();
	}

	@Override
	public long getImageBaseWordAdjustmentOffset() {
		long imageBase = program.getImageBase().getAddressableWordOffset();
		return imageBase - elf.getImageBase();
	}

	@Override
	public Long getGOTValue() {
		ElfHeader header = getElfHeader();
		ElfDynamicTable dynamic = header.getDynamicTable();
		if (dynamic != null && dynamic.containsDynamicValue(ElfDynamicType.DT_PLTGOT)) {
			try {
				return header.adjustAddressForPrelink(
					dynamic.getDynamicValue(ElfDynamicType.DT_PLTGOT)) +
					getImageBaseWordAdjustmentOffset();
			}
			catch (NotFoundException e) {
				throw new AssertException("unexpected", e);
			}
		}
		Symbol gotSym = SymbolUtilities.getLabelOrFunctionSymbol(program, "_GLOBAL_OFFSET_TABLE_",
			err -> log(err));
		if (gotSym != null) {
			return gotSym.getAddress().getAddressableWordOffset();
		}
		return null;
	}

	/**
	 * Identify start address of relocation area.  Skip any sections with a non-zero address.
	 * When an image is relocatable generally all sections will have a zero address.  It is only
	 * when special sections are present (e.g., __ksymtab) that we may encounter sections with
	 * a non-zero address.
	 * @param monitor task monitor
	 * @return start of relocation area
	 * @throws CancelledException task cancelled
	 */
	private long computeRelocationStartAddress(AddressSpace space, long baseOffset,
			TaskMonitor monitor) throws CancelledException {
		if (!elf.isRelocatable()) {
			return 0; // not applicable
		}
		long relocStartAddr = 0;
		AddressSpace defaultSpace = getDefaultAddressSpace();
		ElfSectionHeader[] sections = elf.getSections();
		for (ElfSectionHeader elfSectionToLoad : sections) {
			monitor.checkCanceled();
			long addr = elfSectionToLoad.getAddress();
			if (addr < 0) {
				relocStartAddr = 0;
				break;
			}
			if (elfSectionToLoad.isAlloc() && addr != 0) {
				AddressSpace loadSpace = getSectionAddressSpace(elfSectionToLoad);
				if (loadSpace.equals(space)) {
					long sectionByteLength = elfSectionToLoad.getAdjustedSize(); // size in bytes
					long sectionLength = sectionByteLength / space.getAddressableUnitSize();
					relocStartAddr = Math.max(relocStartAddr, addr + sectionLength);
				}
			}
		}

		// if more than half the address space is skipped - fall back to default relocation base
		long testOffset = relocStartAddr << 1;
		if (testOffset != defaultSpace.getTruncatedAddress(testOffset, true).getOffset()) {
			relocStartAddr = 0;
		}
		return relocStartAddr + baseOffset;
	}

	private void processSectionHeaders(TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Processing section headers...");

		boolean includeOtherBlocks = ElfLoaderOptionsFactory.includeOtherBlocks(options);

		// establish section address provider for relocatable ELF binaries
		RelocatableImageBaseProvider relocatableImageBaseProvider = null;
		if (elf.isRelocatable()) {
			relocatableImageBaseProvider = new RelocatableImageBaseProvider(monitor);
		}

		ElfSectionHeader[] sections = elf.getSections();
		for (ElfSectionHeader elfSectionToLoad : sections) {
			monitor.checkCanceled();
			int type = elfSectionToLoad.getType();
			if (type != ElfSectionHeaderConstants.SHT_NULL &&
				(includeOtherBlocks || elfSectionToLoad.isAlloc())) {
				long fileOffset = elfSectionToLoad.getOffset();
				if (fileOffset < 0 || fileOffset >= fileBytes.getSize()) {
					log("Skipping section [" + elfSectionToLoad.getNameAsString() +
						"] with invalid file offset");
					continue;
				}
				long size = elfSectionToLoad.getSize();
				if (size <= 0 ||
					(type != ElfSectionHeaderConstants.SHT_NOBITS && size >= fileBytes.getSize())) {
					log("Skipping section [" + elfSectionToLoad.getNameAsString() +
						"] with invalid size");
					continue;
				}
				processSectionHeader(elfSectionToLoad, relocatableImageBaseProvider);
			}
		}
	}

	/**
	 * Process the specified section header by ensuring that it has a suitable memory address assigned
	 * and added to the memory resolver.
	 * @param elfSectionToLoad ELF section header to be processed
	 * @param relocatableImageBaseProvider section address provider for relocatable ELF binaries.
	 * @throws AddressOutOfBoundsException if an invalid memory address is encountered
	 */
	private void processSectionHeader(ElfSectionHeader elfSectionToLoad,
			RelocatableImageBaseProvider relocatableImageBaseProvider)
			throws AddressOutOfBoundsException {

		long addr = elfSectionToLoad.getAddress();
		long sectionByteLength = elfSectionToLoad.getAdjustedSize(); // size in bytes
		long loadOffset = elfSectionToLoad.getOffset(); // file offset in bytes
		Long nextRelocOffset = null;

		// In a relocatable ELF (object module), the address of all sections is zero.
		// Therefore, we shall assign an arbitrary address that
		// will pack the sections together with proper alignment.

		if (elfSectionToLoad.isAlloc() && elf.isRelocatable() && addr == 0) {
			// TODO: if program headers are present (very unlikely for object module) 
			// they should be used to determine section load address since they would 
			// be assigned first.
			AddressSpace space = getSectionAddressSpace(elfSectionToLoad);
			long relocOffset = relocatableImageBaseProvider.getNextRelocatableOffset(space);
			addr = NumericUtilities.getUnsignedAlignedValue(relocOffset,
				elfSectionToLoad.getAddressAlignment());
			elfSectionToLoad.setAddress(addr);
			nextRelocOffset = addr + (sectionByteLength / space.getAddressableUnitSize());
		}

		Address address = null;

		if (sectionByteLength == 0 &&
			elfSectionToLoad.getType() == ElfSectionHeaderConstants.SHT_PROGBITS) {
			// Check for and consume uninitialized portion of PT_LOAD segment if possible
			ElfProgramHeader loadHeader = elf.getProgramLoadHeaderContaining(addr);
			if (loadHeader != null) {
				// NOTE: should never apply to relocatable ELF
				Address segmentStart = getSegmentLoadAddress(loadHeader);
				AddressSpace segmentSpace = segmentStart.getAddressSpace();
				long loadSizeBytes = loadHeader.getAdjustedLoadSize();
				long fullSizeBytes =
					loadHeader.getAdjustedMemorySize() * segmentSpace.getAddressableUnitSize();
				long segmentByteOffset =
					(addr - loadHeader.getVirtualAddress()) * segmentSpace.getAddressableUnitSize();
				// TODO: should we match-up file offset?  This could be difficult
				// if using adjusted sizes
				if (segmentByteOffset >= loadSizeBytes) {
					// create as uninitialized section block
					loadOffset = -1; // don't load bytes
					address = segmentStart.add(segmentByteOffset);
					sectionByteLength = fullSizeBytes - segmentByteOffset;
				}
			}
		}

		if (sectionByteLength == 0) {
			log("Skipping empty section [" + elfSectionToLoad.getNameAsString() + "]");
			return;
		}

		if (address == null) {
			address = getSectionLoadAddress(elfSectionToLoad);
		}
		AddressSpace space = address.getAddressSpace();

		if (!space.isValidRange(address.getOffset(), sectionByteLength)) {
			log("Skipping unloadable section [" + elfSectionToLoad.getNameAsString() +
				"] at address " + address.toString(true) + " (size=" + sectionByteLength + ")");
			return;
		}

		final String blockName = elfSectionToLoad.getNameAsString();

		try {
			if (loadOffset == -1 ||
				elfSectionToLoad.getType() == ElfSectionHeaderConstants.SHT_NOBITS) {
				if (!elfSectionToLoad.isAlloc() &&
					elfSectionToLoad.getType() != ElfSectionHeaderConstants.SHT_PROGBITS) {
					return; // non-allocate at runtime
				}
				String comment =
					getSectionComment(addr, sectionByteLength, space.getAddressableUnitSize(),
						elfSectionToLoad.getTypeAsString(), address.isLoadedMemoryAddress());
				addUninitializedMemorySection(elfSectionToLoad, sectionByteLength, address,
					blockName, true, elfSectionToLoad.isWritable(), elfSectionToLoad.isExecutable(),
					comment, false);
			}
			else {
				String comment =
					getSectionComment(addr, sectionByteLength, space.getAddressableUnitSize(),
						elfSectionToLoad.getTypeAsString(), address.isLoadedMemoryAddress());
				addInitializedMemorySection(elfSectionToLoad, loadOffset, sectionByteLength,
					address, blockName, elfSectionToLoad.isAlloc(), elfSectionToLoad.isWritable(),
					elfSectionToLoad.isExecutable(), comment, false, elfSectionToLoad.isAlloc());
			}
		}
		catch (AddressOverflowException e) {
			log("Failed to load section [" + elfSectionToLoad.getNameAsString() + "]: " +
				getMessage(e));
		}

		if (nextRelocOffset != null) {
			relocatableImageBaseProvider.setNextRelocatableOffset(space, nextRelocOffset);
		}
	}

	private String pad(int value) {
		return StringUtilities.pad("" + value, ' ', 4);
	}

	private Data createUndefined(Address addr, int size) throws CodeUnitInsertionException {

		MemoryBlock block = memory.getBlock(addr);
		if (block == null) {
			return null;
		}
		DataType undefined = Undefined.getUndefinedDataType(size);
		return listing.createData(addr, undefined);
	}

	@Override
	public Symbol createSymbol(Address addr, String name, boolean isPrimary, boolean pinAbsolute,
			Namespace namespace) throws InvalidInputException {

		// TODO: At this point, we should be marking as data or code
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol sym = symbolTable.createLabel(addr, name, namespace, SourceType.IMPORTED);
		if (isPrimary) {
			checkPrimary(sym);
		}
		if (pinAbsolute && !sym.isPinned()) {
			sym.setPinned(true);
		}
		return sym;
	}

	/**
	 * check if new symbol needs to grab the primary label.
	 * Elf sometimes has multiple symbols at a location marking the type of instruction of data at the location.
	 * @param sym - new symbol to be made primary (some exclusions apply)
	 * @return revised symbol
	 */
	private Symbol checkPrimary(Symbol sym) {

		if (sym == null || sym.isPrimary()) {
			return sym;
		}

		String name = sym.getName();
		Address addr = sym.getAddress();

		if (name.indexOf("@") > 0) { // <sym>@<version> or <sym>@@<version>
			return sym; // do not make versioned symbols primary
		}

		// if starts with a $, probably a markup symbol, like $t,$a,$d
		if (name.startsWith("$")) {
			return sym;
		}

		// if sym starts with a non-letter give preference to an existing symbol which does
		if (!Character.isAlphabetic(name.codePointAt(0))) {
			Symbol primarySymbol = program.getSymbolTable().getPrimarySymbol(addr);
			if (primarySymbol != null && primarySymbol.getSource() != SourceType.DEFAULT &&
				Character.isAlphabetic(primarySymbol.getName().codePointAt(0))) {
				return sym;
			}
		}

		SetLabelPrimaryCmd cmd = new SetLabelPrimaryCmd(addr, name, sym.getParentNamespace());
		if (cmd.applyTo(program)) {
			return program.getSymbolTable().getSymbol(name, addr, sym.getParentNamespace());
		}

		Msg.error(this, cmd.getStatusMsg());

		return sym;
	}

	/**
	 * Get a suitable input stream for loading a memory block defined by a specified loadable.
	 * @param loadable Corresponding ElfSectionHeader or ElfProgramHeader for the memory block to be created.
	 * @param start memory load address
	 * @param fileOffset byte provider offset
	 * @param dataLength the in-memory data length in bytes (actual bytes read from dataInput may be more)
	 * @return input stream for loading memory block
	 * @throws IOException
	 */
	private InputStream getInitializedBlockInputStream(MemoryLoadable loadable, Address start,
			long fileOffset, long dataLength) throws IOException {
		InputStream dataInput = elf.getReader().getByteProvider().getInputStream(fileOffset);
		return elf.getLoadAdapter()
				.getFilteredLoadInputStream(this, loadable, start, dataLength, dataInput);
	}

	private String formatFloat(float value, int maxDecimalPlaces) {
		NumberFormat format = NumberFormat.getNumberInstance();
		format.setMaximumIntegerDigits(maxDecimalPlaces);
		float roundUpFactor = 1.0F / (10.0F * maxDecimalPlaces);
		return format.format(value + roundUpFactor);
	}

	private long checkBlockLimit(String sectionName, long dataLength, boolean initialized)
			throws IOException {

		long available = Memory.MAX_BINARY_SIZE - program.getMemory().getNumAddresses();
		if (dataLength < 0 || dataLength > available) {
			String msg = "Failed to create memory blocks which exceed the fixed " +
				Memory.MAX_BINARY_SIZE_GB + " GByte total memory size limit";
			log("ERROR: " + msg);
			throw new IOException(msg);
		}

		int maxSectionSizeGBytes = Memory.MAX_BLOCK_SIZE_GB;
		long maxSectionSizeBytes = Memory.MAX_BLOCK_SIZE;

		if (dataLength > maxSectionSizeBytes) {
			float sizeGB = (float) dataLength / (float) Memory.GBYTE;
			String msg = "Truncating " + formatFloat(sizeGB, 1) + " GByte '" + sectionName +
				"' section to " + maxSectionSizeGBytes + " GByte fixed size limit";
			log("ERROR: " + msg);
			return maxSectionSizeBytes;
		}
		return dataLength;
	}

	@Override
	protected MemoryBlock createInitializedBlock(MemoryLoadable loadable, boolean isOverlay,
			String name, Address start, long fileOffset, long dataLength, String comment, boolean r,
			boolean w, boolean x, TaskMonitor monitor)
			throws IOException, AddressOverflowException, CancelledException {

		long revisedLength = checkBlockLimit(name, dataLength, true);

		if (isDiscardableFillerSegment(loadable, name, start, fileOffset, dataLength)) {
			Msg.debug(this,
				"Discarding " + dataLength + "-byte alignment/filler " + name + " at " + start);
			return null;
		}

		// TODO: MemoryBlockUtil poorly and inconsistently handles duplicate name errors (can throw RuntimeException).
		// Are we immune from such errors? If not, how should they be handled?

		if (start.isNonLoadedMemoryAddress()) {
			r = false;
			w = false;
			x = false;
		}

		Msg.debug(this,
			"Loading block " + name + " at " + start + " from file offset " + fileOffset);

		long endOffset = fileOffset + revisedLength - 1;
		if (endOffset >= fileBytes.getSize()) {
			revisedLength = fileBytes.getSize() - fileOffset;
			log("Truncating block load for " + name + " which exceeds file length");
		}

		String blockComment = comment;
		if (dataLength != revisedLength) {
			blockComment += " (section truncated)";
		}

		MemoryBlock block = null;
		try {
			if (elf.getLoadAdapter().hasFilteredLoadInputStream(this, loadable, start)) {
				// block is unable to map directly to file bytes - load from input stream
				try (InputStream dataInput =
					getInitializedBlockInputStream(loadable, start, fileOffset, revisedLength)) {
					block = MemoryBlockUtils.createInitializedBlock(program, isOverlay, name, start,
						dataInput, revisedLength, blockComment, BLOCK_SOURCE_NAME, r, w, x, log,
						monitor);
				}
			}
			else {
				// create block using direct mapping to file bytes
				block = MemoryBlockUtils.createInitializedBlock(program, isOverlay, name, start,
					fileBytes, fileOffset, revisedLength, blockComment, BLOCK_SOURCE_NAME, r, w, x,
					log);
			}
		}
		finally {
			if (block == null) {
				Address end = start.addNoWrap(revisedLength - 1);
				Msg.error(this, "Unexpected ELF memory bock load conflict when creating '" + name +
					"' at " + start.toString(true) + "-" + end.toString(true));
			}
		}
		return block;
	}

	@Override
	protected MemoryBlock createUninitializedBlock(MemoryLoadable loadable, boolean isOverlay,
			String name, Address start, long dataLength, String comment, boolean r, boolean w,
			boolean x) throws IOException, AddressOverflowException {

		// TODO: MemoryBlockUtil poorly and inconsistently handles duplicate name errors (can throw RuntimeException).
		// Are we immune from such errors? If not, how should they be handled?

		long revisedLength = checkBlockLimit(name, dataLength, false);

		if (start.isNonLoadedMemoryAddress()) {
			r = false;
			w = false;
			x = false;
		}

		if (dataLength != revisedLength) {
			comment += " (section truncated)";
		}

		return MemoryBlockUtils.createUninitializedBlock(program, isOverlay, name, start,
			revisedLength, comment, BLOCK_SOURCE_NAME, r, w, x, log);
	}

	private class RelocatableImageBaseProvider {

		Map<Integer, Long> nextRelocationOffsetMap = new HashMap<>();

		RelocatableImageBaseProvider(TaskMonitor monitor) throws CancelledException {
			AddressSpace defaultSpace = getDefaultAddressSpace();
			AddressSpace defaultDataSpace = getDefaultDataSpace();
			long baseOffset =
				computeRelocationStartAddress(defaultSpace, elf.getImageBase(), monitor);
			nextRelocationOffsetMap.put(defaultSpace.getUnique(), baseOffset);
			if (defaultDataSpace != defaultSpace) {
				baseOffset =
					computeRelocationStartAddress(defaultDataSpace, getImageDataBase(), monitor);
				nextRelocationOffsetMap.put(defaultDataSpace.getUnique(), baseOffset);
			}
			// In the future, an extension could introduce additional space entries 
		}

		void setNextRelocatableOffset(AddressSpace space, Long nextRelocOffset) {
			int unique = space.getUnique();
			nextRelocationOffsetMap.put(unique, nextRelocOffset);
		}

		long getNextRelocatableOffset(AddressSpace space) {
			int unique = space.getUnique();
			Long nextRelocOffset = nextRelocationOffsetMap.get(unique);
			return nextRelocOffset == null ? 0 : nextRelocOffset;
		}
	}

}
