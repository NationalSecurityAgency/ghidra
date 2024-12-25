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
import java.util.*;
import java.util.Map.Entry;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.RelocationException;
import ghidra.app.util.bin.format.coff.*;
import ghidra.app.util.bin.format.coff.relocation.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class CoffLoader extends AbstractLibrarySupportLoader {

	public final static String COFF_NAME = "Common Object File Format (COFF)";
	public static final String FAKE_LINK_OPTION_NAME = "Attempt to link sections located at 0x0";
	static final boolean FAKE_LINK_OPTION_DEFAULT = true;

	// where do sections start if they're all zero???  this affects object files
	// and if we're high enough (!!!) the scalar operand analyzer will work
	// properly with external symbols laid down
	private static final int EMPTY_START_OFFSET = 0x2000;

	/**
	 * @return true if this loader assumes the Microsoft variant of the COFF format
	 */
	public boolean isMicrosoftFormat() {
		return false;
	}

	/**
	 * Try to determine if this COFF file was produced by the Microsoft Visual Studio tools
	 * Currently we look for specific sections that are indicative of Visual Studio
	 *   The .drectve contains options that are passed to the linker
	 *   The .debug$S is a non-standard debug section (which usually has the string "Microsoft" in it)
	 * These particular sections seem to be universally present over many versions of Visual Studio
	 * GNU bfd recognizes these sections as Microsoft Visual Studio specific
	 * @param header is the CoffFileHeader with parse() or parseSectionHeaders() run
	 * @return true is (either section is present and) we think this is Visual Studio
	 */
	private boolean isVisualStudio(CoffFileHeader header) {
		List<CoffSectionHeader> sections = header.getSections();
		for (CoffSectionHeader section : sections) {
			String name = section.getName();
			if (name.startsWith(".drectve") || name.startsWith(".debug$S")) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Checks to see if the COFF is CLI.
	 *
	 * @param header The COFF's headers.
	 * @return True if the COFF is CLI; otherwise, false.
	 */
	private boolean isCLI(CoffFileHeader header) {
		return header.getSections().stream().anyMatch(s -> s.getName().startsWith(".cormeta"));
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (!CoffFileHeader.isValid(provider)) {
			return loadSpecs;
		}

		CoffFileHeader header = new CoffFileHeader(provider);
		header.parseSectionHeaders(provider);

		if (isVisualStudio(header) != isMicrosoftFormat()) {
			// Only one of the CoffLoader/MSCoffLoader will survive this check
			return loadSpecs;
		}
		String secondary = isCLI(header) ? "cli" : Integer.toString(header.getFlags() & 0xffff);
		List<QueryResult> results =
			QueryOpinionService.query(getName(), header.getMachineName(), secondary);
		for (QueryResult result : results) {
			loadSpecs.add(new LoadSpec(this, header.getImageBase(isMicrosoftFormat()), result));
		}
		if (loadSpecs.isEmpty()) {
			loadSpecs.add(new LoadSpec(this, header.getImageBase(false), true));
		}

		return loadSpecs;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram);
		if (!loadIntoProgram) {
			list.add(new Option(FAKE_LINK_OPTION_NAME, FAKE_LINK_OPTION_DEFAULT));
		}
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		if (options != null) {
			for (Option option : options) {
				String name = option.getName();
				if (name.equals(FAKE_LINK_OPTION_NAME)) {
					if (!Boolean.class.isAssignableFrom(option.getValueClass())) {
						return "Invalid type for option: " + name + " - " + option.getValueClass();
					}
				}
			}
		}
		return super.validateOptions(provider, loadSpec, options, program);
	}

	private boolean performFakeLinking(List<Option> options) {
		boolean performFakeLinking = FAKE_LINK_OPTION_DEFAULT;
		if (options != null) {
			for (Option option : options) {
				String optName = option.getName();
				if (optName.equals(FAKE_LINK_OPTION_NAME)) {
					performFakeLinking = (Boolean) option.getValue();
				}
			}
		}
		return performFakeLinking;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws IOException, CancelledException {

		boolean performFakeLinking = performFakeLinking(options);

		CoffFileHeader header = new CoffFileHeader(provider);
		header.parse(provider, monitor);

		Map<CoffSectionHeader, Address> sectionsMap = new HashMap<>();
		Map<CoffSymbol, Symbol> symbolsMap = new HashMap<>();

		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);

		try {
			processSectionHeaders(provider, header, program, fileBytes, monitor, log, sectionsMap,
				performFakeLinking);
			processSymbols(header, program, monitor, log, sectionsMap, symbolsMap);
			processEntryPoint(header, program, monitor, log);
			processRelocations(header, program, sectionsMap, symbolsMap, log, monitor);
			markupHeaders(header, program, fileBytes, log, monitor);
		}
		catch (AddressOverflowException e) {
			throw new IOException(e);
		}
	}

	private void processEntryPoint(CoffFileHeader header, Program program, TaskMonitor monitor,
			MessageLog log) {

		AoutHeader optionalHeader = header.getOptionalHeader();
		if (optionalHeader != null) {
			int lentry = optionalHeader.getEntry();
			try {
				Address entry = CoffSectionHeader.getAddress(program.getLanguage(), lentry,
					program.getLanguage().getDefaultSpace());
				program.getSymbolTable().addExternalEntryPoint(entry);
				program.getSymbolTable().createLabel(entry, "entry", SourceType.IMPORTED);
			}
			catch (Exception e) {
				log.appendMsg(
					"Unable to create entry point symbol at " + Integer.toHexString(lentry));
				log.appendMsg("\t" + e.getMessage());
			}
		}
	}

	private void processSymbols(CoffFileHeader header, Program program, TaskMonitor monitor,
			MessageLog log, Map<CoffSectionHeader, Address> sectionsMap,
			Map<CoffSymbol, Symbol> symbolsMap) {

		Address externalAddress = findFreeAddress(program);
		if (externalAddress == null) {
			log.appendMsg("Serious problem, there is no memory at all for symbols!");
			return;
		}
		Address externalAddressStart = externalAddress;

		SymbolTable symbolTable = program.getSymbolTable();

		List<CoffSymbol> symbols = header.getSymbols();

		monitor.setMessage("Creating Symbols");

		for (CoffSymbol symbol : symbols) {
			if (monitor.isCancelled()) {
				break;
			}
			if (symbol.isSection()) {
				continue;
			}
/*
			if (symbol.getStorageClass() != CoffSymbolStorageClass.C_STAT &&
				symbol.getStorageClass() != CoffSymbolStorageClass.C_EXT &&
				symbol.getStorageClass() != CoffSymbolStorageClass.C_LABEL) {
				continue;
			}
 */
			Address address = null;
			try {
				short sectionNum = symbol.getSectionNumber();
				if (sectionNum == CoffSymbolSectionNumber.N_UNDEF) {//external symbols
					address = externalAddress;
					String name = symbol.getName();
					Symbol sym = symbolTable.getGlobalSymbol(name, address);
					if (sym == null) {
						sym = symbolTable.createLabel(externalAddress, name, SourceType.IMPORTED);
					}

					symbolsMap.put(symbol, sym);

					externalAddress = externalAddress
							.add(getPointerSizeAligned(externalAddress.getAddressSpace()));
				}
				else if (sectionNum < CoffSymbolSectionNumber.N_DEBUG) {
					log.appendMsg("Strange symbol " + symbol + " : " + symbol.getBasicType() +
						" - from section " + sectionNum);
				}
				else if (sectionNum == CoffSymbolSectionNumber.N_DEBUG) {
					// skip debug symbols
					continue;
				}
				else {
					CoffSectionHeader section = null;
					if (sectionNum == CoffSymbolSectionNumber.N_ABS) { // absolute symbols {
						// usually corresponds to IO or memory registers
						address = CoffSectionHeader.getAddress(program.getLanguage(),
							symbol.getValue(), program.getLanguage().getDefaultDataSpace());
						// TODO: need a way to create an absolute symbol which does not get relocated with image base change
					}
					else { // section symbols
						section = header.getSections().get(sectionNum - 1);
						Address sectionStartAddr = sectionsMap.get(section);
						if (sectionStartAddr == null) {
							log.appendMsg("Unable to process symbol " + symbol.getName() + " : " +
								symbol.getBasicType() + " - could not locate related section.");
							continue;
						}

						address = CoffSectionHeader.getAddress(program.getLanguage(),
							symbol.getValue(), section);
					}

					String symName = symbol.getName();
					switch (symbol.getStorageClass()) {
						case CoffSymbolStorageClass.C_BLOCK:
							symName = "BLOCK_" + symName;
							break;
						case CoffSymbolStorageClass.C_FCN:
							// these are .bf, .lf and .ef dummy symbols
							// skip them because their values don't
							// translate into anything in Ghidra
							continue;
						case CoffSymbolStorageClass.C_EOS:
							symName = "EOS_" + symName;
							break;
						case CoffSymbolStorageClass.C_FILE:
							symName = "FILE_" + symName;
							break;
						case CoffSymbolStorageClass.C_LINE:
							symName = "LINE_" + symName;
							break;

						default:
					}

					Symbol existingSym = symbolTable.getPrimarySymbol(address);
					String name = symbol.getName();
					Symbol sym = symbolTable.getGlobalSymbol(name, address);
					if (sym == null) {
						sym = symbolTable.createLabel(address, name, SourceType.IMPORTED);
					}
					if (existingSym == null || !existingSym.isPrimary() ||
						symbol.getStorageClass() == CoffSymbolStorageClass.C_EXT) {
						sym.setPrimary();
					}
					if (symbol.getDerivedType(1) == CoffSymbolType.DT_FCN &&
						symbol.getStorageClass() != CoffSymbolStorageClass.C_STAT) {
						// ONLY DO THIS IF THE SYMBOL IS A FUNCTION!
						symbolTable.addExternalEntryPoint(address);
						markAsFunction(program, sym.getName(), address);
					}

					symbolsMap.put(symbol, sym);
				}
			}
			catch (Exception e) {
				log.appendMsg("Unable to create symbol " + symbol.getName() + " at 0x" +
					Long.toHexString(symbol.getValue()));
			}
		}

		createExternalBlock(program, monitor, log, externalAddress, externalAddressStart);
	}

	private void createExternalBlock(Program program, TaskMonitor monitor, MessageLog log,
			Address externalAddress, Address externalAddressStart) {
		//create an artificial block for the external symbols
		if (!externalAddressStart.equals(externalAddress)) {
			long size = externalAddress.subtract(externalAddressStart);
			try {
				MemoryBlock block = program.getMemory()
						.createUninitializedBlock(MemoryBlock.EXTERNAL_BLOCK_NAME,
							externalAddressStart, size, false);

				// assume any value in external is writable.
				block.setWrite(true);

				// Mark block as an artificial fabrication
				block.setArtificial(true);

				Address current = externalAddressStart;
				while (current.compareTo(externalAddress) < 0) {
					createUndefined(program.getListing(), program.getMemory(), current,
						externalAddress.getAddressSpace().getPointerSize());
					current = current.add(externalAddress.getAddressSpace().getPointerSize());
				}
			}
			catch (Exception e) {
				log.appendMsg("Error creating external memory block: " + " - " + e.getMessage());
			}
		}
	}

	private Data createUndefined(Listing listing, Memory memory, Address addr, int size)
			throws CodeUnitInsertionException {
		MemoryBlock block = memory.getBlock(addr);
		if (block == null || !block.isInitialized()) {
			return null;
		}
		DataType undefined = Undefined.getUndefinedDataType(size);
		return listing.createData(addr, undefined);
	}

	private Address findFreeAddress(Program program) {
		Memory memory = program.getMemory();
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		// Don't consider overlay blocks for max addr
		Address maxAddr = memory.getMinAddress();
		if (maxAddr == null) {
			return null;
		}
		MemoryBlock[] blocks = memory.getBlocks();
		for (MemoryBlock block : blocks) {
			// get the physical address in case it is an overlay address
			Address blockEnd = block.getEnd().getPhysicalAddress();
			if (blockEnd.compareTo(maxAddr) > 0) {
				maxAddr = blockEnd;
			}
		}

		// Always Align the fake External Address Space
		Address externAddress = null;
		long newOffset = maxAddr.getOffset() % getPointerSizeAligned(space);
		newOffset = (getPointerSizeAligned(space) - newOffset);
		newOffset += 0x1000;
		maxAddr = maxAddr.getPhysicalAddress();
		externAddress = maxAddr.add(newOffset);
		return externAddress;
	}

	private int getPointerSizeAligned(AddressSpace space) {
		int pointerSizeUnaligned = space.getPointerSize();
		if (pointerSizeUnaligned <= 8) {
			return 8;
		}
		if (pointerSizeUnaligned <= 16) {
			return 16;
		}
		if (pointerSizeUnaligned <= 32) {
			return 32;
		}
		if (pointerSizeUnaligned <= 64) {
			return 64;
		}
		return pointerSizeUnaligned;
	}

	private void processSectionHeaders(ByteProvider provider, CoffFileHeader header,
			Program program, FileBytes fileBytes, TaskMonitor monitor, MessageLog log,
			Map<CoffSectionHeader, Address> map, boolean performFakeLinking)
			throws AddressOverflowException, IOException {

		monitor.setMessage("Process sections...");

		final Language language = program.getLanguage();

		List<CoffSectionHeader> sections = header.getSections();

		if (performFakeLinking) {
			possiblyRelocateSections(program, header, map);
		}

		int sectionNumber = 0;
		for (CoffSectionHeader section : sections) {
			++sectionNumber;
			if (monitor.isCancelled()) {
				break;
			}

			MemoryBlock block = null;

			final int sectionSize = section.getSize(language);

			Address sectionAddr = section.getPhysicalAddress(language);

			if (sectionSize == 0 || section.getFlags() == 0) {
				log.appendMsg("Empty Section, Created Symbol: " + section.getName());
				// don't create a block, but record the section to get at the address!
				block = program.getMemory().getBlock(sectionAddr);
				try {
					program.getSymbolTable()
							.createLabel(sectionAddr, section.getName(), SourceType.IMPORTED);
					// TODO: sectionSize somewhere for case where flags==0 ?
				}
				catch (InvalidInputException e) {
					// unexpected
				}
			}
			else if (!section.isAllocated()) {
				block = createInitializedBlock(provider, program, fileBytes, monitor, log, language,
					sectionNumber, section, sectionSize, sectionAddr, true);
				if (block != null) {
					log.appendMsg("Created Overlay Block: " + section + " @ " + sectionAddr);
				}
			}
			else if (section.isUninitializedData()) {
				block = MemoryBlockUtils.createUninitializedBlock(program, false, section.getName(),
					sectionAddr, sectionSize,
					"PhysAddr:0x" + Integer.toHexString(section.getPhysicalAddress()) + " " +
						"Size:0x" + Integer.toHexString(sectionSize) + " " + "Flags:0x" +
						Integer.toHexString(section.getFlags()),
					null/*source*/, section.isReadable(), section.isWritable(),
					section.isExecutable(), log);
				if (block != null) {
					log.appendMsg("Created Uninitialized Block: " + section + " @ " + sectionAddr);
				}
			}
			else {
				block = createInitializedBlock(provider, program, fileBytes, monitor, log, language,
					sectionNumber, section, sectionSize, sectionAddr, false);
				if (block != null) {
					log.appendMsg("Created Initialized Block: " + section + " @ " + sectionAddr);
				}
			}

			if (block != null) {
				sectionAddr = block.getStart();
			}
			map.put(section, sectionAddr);
		}
	}

	private MemoryBlock createInitializedBlock(ByteProvider provider, Program program,
			FileBytes fileBytes, TaskMonitor monitor, MessageLog log, final Language language,
			int sectionNumber, CoffSectionHeader section, final int sectionSize,
			Address sectionAddr, boolean isOverlay) throws AddressOverflowException, IOException {

		String name = section.getName();
		if (isOverlay) {
			name += "-" + sectionNumber;
		}
		MemoryBlock block = null;
		try {
			if (section.isProcessedBytes(language)) {
				try (InputStream dataStream = section.getRawDataStream(provider, language)) {
					block = MemoryBlockUtils.createInitializedBlock(program, isOverlay, name,
						sectionAddr, dataStream, sectionSize,
						"PhysAddr:0x" + Integer.toHexString(section.getPhysicalAddress()) + " " +
							"Size:0x" + Integer.toHexString(sectionSize) + " " + "Flags:0x" +
							Integer.toHexString(section.getFlags()),
						null/*source*/, section.isReadable(), section.isWritable(),
						section.isExecutable(), log, monitor);
				}
			}
			else {
				block = MemoryBlockUtils.createInitializedBlock(program, isOverlay, name,
					sectionAddr, fileBytes, section.getPointerToRawData(), sectionSize,
					"PhysAddr:0x" + Integer.toHexString(section.getPhysicalAddress()) + " " +
						"Size:0x" + Integer.toHexString(sectionSize) + " " + "Flags:0x" +
						Integer.toHexString(section.getFlags()),
					null/*source*/, section.isReadable(), section.isWritable(),
					section.isExecutable(), log);
			}
		}
		catch (RuntimeException e) {
			log.appendMsg(
				"Unable to create non-loaded block " + section + ". No memory block was created.");
			log.appendException(e);
		}
		return block;
	}

	private void possiblyRelocateSections(Program program, CoffFileHeader header,
			Map<CoffSectionHeader, Address> map) {
		// 1. loop over all sections
		//    put all sections not at 0 into address set
		//    put all sections at 0 into "totals" map, accounting for later alignment needs
		// 2. look for space before minimum of taken addresses
		// 3. or, look for space after maximum of taken addresses

		Language language = program.getLanguage();
		AddressFactory addressFactory = program.getAddressFactory();
		AddressSpace defaultAddressSpace = addressFactory.getDefaultAddressSpace();

		AddressSet nonZeroSet = new AddressSet();

		int totalZeroSectionSize = 0;
		Map<String, Integer> zeroSectionSizes = new TreeMap<>();
		Map<String, Integer> zeroSectionOffsets = new TreeMap<>();

		List<CoffSectionHeader> sections = header.getSections();
		for (CoffSectionHeader section : sections) {
			int physicalAddress = section.getPhysicalAddress();
			int size = section.getSize(language);
			if (physicalAddress == 0) {
				// We don't know the exact offset now, so assume worst-case alignment penalty
				int alignedSize = size + getSectionAlignment(section) - 1;
				String name = section.getName();
				zeroSectionSizes.compute(name,
					(k, v) -> (v == null ? alignedSize : v + alignedSize));

				totalZeroSectionSize += alignedSize;
			}
			else {
				if (size > 0) {
					Address start = defaultAddressSpace.getAddress(physicalAddress);
					Address end = defaultAddressSpace.getAddress(physicalAddress + size - 1);
					if (nonZeroSet.contains(start, end)) {
						Msg.warn(this, "Section " + section.getName() +
							" overlaps another non-zero section (hope it's going in an overlay!)");
					}
					nonZeroSet.addRange(start, end);
				}
			}
		}

		Address maxAddress = nonZeroSet.getMaxAddress();
		int offset = (maxAddress == null ? EMPTY_START_OFFSET - 1
				: (int) (maxAddress.getOffset() & 0xffffffff));
		long sum = offset;
		sum += totalZeroSectionSize;
		if (sum <= 0x100000000L) {
			offset += 1;
			// Each group of sections with the same name should be aligned at least at 256 bytes
			for (Entry<String, Integer> entry : zeroSectionSizes.entrySet()) {
				offset = (offset + DEFAULT_ALIGNMENT - 1) / DEFAULT_ALIGNMENT * DEFAULT_ALIGNMENT;
				zeroSectionOffsets.put(entry.getKey(), offset);
				offset += zeroSectionSizes.get(entry.getKey());
			}
			int sectionNumber = 1;
			for (CoffSectionHeader section : sections) {
				int physicalAddress = section.getPhysicalAddress();
				if (physicalAddress == 0) {
					String name = section.getName();
					int alignment = getSectionAlignment(section);
					offset = (zeroSectionOffsets.get(name) + alignment - 1) / alignment * alignment;
					relocateSection(header, section, sectionNumber, offset);
					zeroSectionOffsets.put(name, offset + section.getSize(language));
				}
				++sectionNumber;
			}
		}
	}

	private static final int DEFAULT_ALIGNMENT = 0x100;

	/**
	 * Query a section header for alignment information. The base version of this method assumes 
	 * no alignment information is stored in the section header. Subclasses may implement a 
	 * platform-specific check for alignment information.
	 * 
	 * @param section header object for the section 
	 * @return the alignment requested by the section
	 */
	protected int getSectionAlignment(CoffSectionHeader section) {
		return 1;
	}

	private void relocateSection(CoffFileHeader header, CoffSectionHeader section,
			int sectionNumber, int offset) {
		section.move(offset);
		List<CoffSymbol> symbols = header.getSymbols();
		for (CoffSymbol coffSymbol : symbols) {
			if (!coffSymbol.isSection() && coffSymbol.getSectionNumber() == sectionNumber) {
				coffSymbol.move(offset);
			}
		}
	}

	private void processRelocations(CoffFileHeader header, Program program,
			Map<CoffSectionHeader, Address> sectionsMap, Map<CoffSymbol, Symbol> symbolsMap,
			MessageLog log, TaskMonitor monitor) {

		CoffRelocationHandler handler = CoffRelocationHandlerFactory.getHandler(header);
		if (handler == null) {
			String msg = String.format("No COFF relocation handler for machine type 0x%x",
				(Short) header.getMachine());
			log.appendMsg(msg);
			Msg.error(this, program.getName() + ": " + msg);
		}

		CoffRelocationContext relocationContext =
			new CoffRelocationContext(program, header, symbolsMap);
		int failureCount = 0;

		for (CoffSectionHeader section : header.getSections()) {
			if (monitor.isCancelled()) {
				break;
			}

			Address sectionStartAddr = sectionsMap.get(section);
			if (sectionStartAddr == null) {
				int relocCount = section.getRelocationCount();
				if (relocCount > 0) {
					failureCount += relocCount;
					String msg = "Unable to process " + relocCount + " relocations for section " +
						section.getName() + ". No memory block was created.";
					log.appendMsg(msg);
					Msg.error(this, program.getName() + ": " + msg);
				}
				continue;
			}

			relocationContext.resetContext(section);

			Address failedAddr = null;
			for (CoffRelocation relocation : section.getRelocations()) {
				if (monitor.isCancelled()) {
					break;
				}

				// Sections are defined with physical address while relocations use virtual address.
				// Must adjust relocation address to physical.
				// NOTE: Relocation address offset assumed to always be a byte-offset
				Address address =
					sectionStartAddr.add(relocation.getAddress() - section.getVirtualAddress());
				short relocationType = relocation.getType();

				Status status = Status.FAILURE;
				int byteLength = 0;

				if (handler == null) {
					++failureCount;
					handleRelocationError(program, address, relocationType,
						"No COFF relocation handler", null);
				}
				else {
					try {
						if (address.equals(failedAddr)) {
							// skip relocation if previous failed relocation was at the same address
							// since it is likely dependent on the previous failed relocation result
							++failureCount;
							status = Status.SKIPPED;

							String logMessage =
								String.format("Skipped dependent COFF Relocation type 0x%x at %s",
									relocationType, address.toString());
							Msg.error(this, program.getName() + ": " + logMessage);
						}
						else {
							RelocationResult result =
								handler.relocate(address, relocation, relocationContext);
							status = result.status();
							byteLength = result.byteLength();

							if (status == Status.UNSUPPORTED) {
								++failureCount;
								failedAddr = address;
								handleRelocationError(program, address, relocationType,
									"unsupported type", null);
							}
							else if (status == Status.FAILURE) {
								++failureCount;
								failedAddr = address;
								handleRelocationError(program, address, relocationType,
									"unknown reason", null);
							}
						}
					}
					catch (MemoryAccessException e) {
						++failureCount;
						failedAddr = address;
						handleRelocationError(program, address, relocationType,
							"error accessing memory", null);
					}
					catch (RelocationException e) {
						++failureCount;
						failedAddr = address;
						handleRelocationError(program, address, relocationType, e.getMessage(),
							null);
					}
					catch (Exception e) { // handle unexpected exceptions
						++failureCount;
						failedAddr = address;
						String msg = e.getMessage();
						if (msg == null) {
							msg = e.toString();
						}
						handleRelocationError(program, address, relocationType, msg, e);
					}
				}

				// The relocation symbol may be null when either not required by a relocation or
				// not found with symbol index
				Symbol symbol =
					symbolsMap.get(header.getSymbolAtIndex(relocation.getSymbolIndex()));

				program.getRelocationTable()
						.add(address, status, relocation.getType(),
							new long[] { relocation.getSymbolIndex() }, byteLength,
							symbol != null ? symbol.getName() : "<null>");
			}
		}

		if (failureCount != 0) {
			String msg = "Failed to process a total of " + failureCount +
				" relocations.  See log and error bookmarks for details.";
			log.appendMsg(msg);
			Msg.error(this, program.getName() + ": " + msg);
		}
	}

	private void handleRelocationError(Program program, Address address, Short relocationType,
			String message, Exception causeToReport) {
		String bookmarkMessage =
			String.format("Failed to apply COFF Relocation type 0x%x: %s", relocationType, message);
		program.getBookmarkManager()
				.setBookmark(address, BookmarkType.ERROR, "Relocations", bookmarkMessage);
		String logMessage = String.format("Failed to apply COFF Relocation type 0x%x at %s: %s",
			relocationType, address.toString(), message);
		Msg.error(this, program.getName() + ": " + logMessage, causeToReport);
	}

	private void markupHeaders(CoffFileHeader header, Program program, FileBytes fileBytes,
			MessageLog log, TaskMonitor monitor) {
		monitor.setMessage("Marking up headers...");
		try {
			Map<Long, DataType> dtMap = new HashMap<>();
			long blockSize = 0;

			// Header
			dtMap.put(blockSize, header.toDataType());
			blockSize += header.sizeof();

			// Optional Header
			AoutHeader optionalHeader = header.getOptionalHeader();
			if (header.getOptionalHeader() != null) {
				dtMap.put(blockSize, optionalHeader.toDataType());
				blockSize += header.getOptionalHeaderSize();
			}

			// Sections
			for (CoffSectionHeader section : header.getSections()) {
				DataType dt = section.toDataType();
				dtMap.put(blockSize, dt);
				blockSize += dt.getLength();
			}

			// Create memory block
			Address headerSpaceAddr = AddressSpace.OTHER_SPACE.getAddress(0);
			MemoryBlock headerBlock =
				MemoryBlockUtils.createInitializedBlock(program, true, "HEADER", headerSpaceAddr,
					fileBytes, 0, blockSize, "", "", false, false, false, log);
			Address addr = headerBlock.getStart();

			// Create data
			for (long offset : dtMap.keySet()) {
				DataUtilities.createData(program, addr.add(offset), dtMap.get(offset), -1,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			}

		}
		catch (Exception e) {
			log.appendMsg("Failed to markup headers");
		}
	}

	@Override
	public String getName() {
		return COFF_NAME;
	}

	class CoffPair {
		public long offset;
		public long size;

		CoffPair(long offset, long size) {
			this.offset = offset;
			this.size = size;
		}
	}
}
