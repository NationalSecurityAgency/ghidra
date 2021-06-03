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
import java.math.BigInteger;
import java.util.*;

import generic.continues.GenericFactory;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.mz.DOSHeader;
import ghidra.app.util.bin.format.pe.*;
import ghidra.app.util.bin.format.pe.ImageCor20Header.ImageCor20Flags;
import ghidra.app.util.bin.format.pe.ImageRuntimeFunctionEntries._IMAGE_RUNTIME_FUNCTION_ENTRY;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.app.util.bin.format.pe.debug.DebugCOFFSymbol;
import ghidra.app.util.bin.format.pe.debug.DebugDirectoryParser;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.MessageLogContinuesFactory;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.Options;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Microsoft Portable Executable (PE) loader.
 */
public class PeLoader extends AbstractPeDebugLoader {

	/** The name of the PE loader */
	public final static String PE_NAME = "Portable Executable (PE)";

	/** The name of the PE headers memory block. */
	public static final String HEADERS = "Headers";

	/** The minimum length a file has to be for it to qualify as a possible PE. */
	private static final long MIN_BYTE_LENGTH = 4;

	/** PE loader option to control parsing CLI headers */
	public static final String PARSE_CLI_HEADERS_OPTION_NAME = "Parse CLI headers (if present)";
	static final boolean PARSE_CLI_HEADERS_OPTION_DEFAULT = true;

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (provider.length() < MIN_BYTE_LENGTH) {
			return loadSpecs;
		}

		PortableExecutable pe = PortableExecutable.createPortableExecutable(
			RethrowContinuesFactory.INSTANCE, provider, SectionLayout.FILE, false, false);
		NTHeader ntHeader = pe.getNTHeader();
		if (ntHeader != null && ntHeader.getOptionalHeader() != null) {
			long imageBase = ntHeader.getOptionalHeader().getImageBase();
			String machineName = ntHeader.getFileHeader().getMachineName();
			String compiler = CompilerOpinion.stripFamily(CompilerOpinion.getOpinion(pe, provider));
			for (QueryResult result : QueryOpinionService.query(getName(), machineName, compiler)) {
				loadSpecs.add(new LoadSpec(this, imageBase, result));
			}
			if (loadSpecs.isEmpty()) {
				loadSpecs.add(new LoadSpec(this, imageBase, true));
			}
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws IOException, CancelledException {

		if (monitor.isCancelled()) {
			return;
		}

		GenericFactory factory = MessageLogContinuesFactory.create(log);
		PortableExecutable pe = PortableExecutable.createPortableExecutable(factory, provider,
			SectionLayout.FILE, false, shouldParseCliHeaders(options));

		NTHeader ntHeader = pe.getNTHeader();
		if (ntHeader == null) {
			return;
		}
		OptionalHeader optionalHeader = ntHeader.getOptionalHeader();
		FileHeader fileHeader = ntHeader.getFileHeader();

		monitor.setMessage("Completing PE header parsing...");
		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);
		try {
			Map<SectionHeader, Address> sectionToAddress =
				processMemoryBlocks(pe, program, fileBytes, monitor, log);

			monitor.setCancelEnabled(false);
			optionalHeader.processDataDirectories(monitor);
			monitor.setCancelEnabled(true);
			optionalHeader.validateDataDirectories(program);

			DataDirectory[] datadirs = optionalHeader.getDataDirectories();
			layoutHeaders(program, pe, ntHeader, datadirs);
			for (DataDirectory datadir : datadirs) {
				if (datadir == null || !datadir.hasParsedCorrectly()) {
					continue;
				}
				if (datadir.hasParsedCorrectly()) {
					datadir.markup(program, false, monitor, log, ntHeader);
				}
			}

			setProcessorContext(fileHeader, program, monitor, log);

			processExports(optionalHeader, program, monitor, log);
			processImports(optionalHeader, program, monitor, log);
			processDelayImports(optionalHeader, program, monitor, log);
			processRelocations(optionalHeader, program, monitor, log);
			processDebug(optionalHeader, fileHeader, sectionToAddress, program, monitor);
			processProperties(optionalHeader, program, monitor);
			processComments(program.getListing(), monitor);
			processSymbols(fileHeader, sectionToAddress, program, monitor, log);
			processImageRuntimeFunctionEntries(fileHeader, program, monitor, log);

			processEntryPoints(ntHeader, program, monitor);
			String compiler = CompilerOpinion.getOpinion(pe, provider).toString();
			program.setCompiler(compiler);

		}
		catch (AddressOverflowException e) {
			throw new IOException(e);
		}
		catch (DuplicateNameException e) {
			throw new IOException(e);
		}
		catch (CodeUnitInsertionException e) {
			throw new IOException(e);
		}
		catch (DataTypeConflictException e) {
			throw new IOException(e);
		}
		catch (MemoryAccessException e) {
			throw new IOException(e);
		}
		monitor.setMessage("[" + program.getName() + "]: done!");
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram);
		if (!loadIntoProgram) {
			list.add(new Option(PARSE_CLI_HEADERS_OPTION_NAME, PARSE_CLI_HEADERS_OPTION_DEFAULT,
				Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-parseCliHeaders"));
		}
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		if (options != null) {
			for (Option option : options) {
				String name = option.getName();
				if (name.equals(PARSE_CLI_HEADERS_OPTION_NAME)) {
					if (!Boolean.class.isAssignableFrom(option.getValueClass())) {
						return "Invalid type for option: " + name + " - " + option.getValueClass();
					}
				}
			}
		}
		return super.validateOptions(provider, loadSpec, options, program);
	}

	@Override
	protected boolean isCaseInsensitiveLibraryFilenames() {
		return true;
	}

	private boolean shouldParseCliHeaders(List<Option> options) {
		if (options != null) {
			for (Option option : options) {
				String optName = option.getName();
				if (optName.equals(PARSE_CLI_HEADERS_OPTION_NAME)) {
					return (Boolean) option.getValue();
				}
			}
		}
		return PARSE_CLI_HEADERS_OPTION_DEFAULT;
	}

	private void layoutHeaders(Program program, PortableExecutable pe, NTHeader ntHeader,
			DataDirectory[] datadirs) {
		try {
			DataType dt = pe.getDOSHeader().toDataType();
			Address start = program.getImageBase();
			DataUtilities.createData(program, start, dt, -1, false,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			dt = pe.getRichHeader().toDataType();
			if (dt != null) {
				start = program.getImageBase().add(pe.getRichHeader().getOffset());
				DataUtilities.createData(program, start, dt, -1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			}

			dt = ntHeader.toDataType();
			start = program.getImageBase().add(pe.getDOSHeader().e_lfanew());
			DataUtilities.createData(program, start, dt, -1, false,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			FileHeader fh = ntHeader.getFileHeader();
			SectionHeader[] sections = fh.getSectionHeaders();
			int index = fh.getPointerToSections();
			start = program.getImageBase().add(index);
			for (SectionHeader section : sections) {
				dt = section.toDataType();
				DataUtilities.createData(program, start, dt, -1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				setComment(CodeUnit.EOL_COMMENT, start, section.getName());
				start = start.add(dt.getLength());
			}
		}
		catch (Exception e1) {
			Msg.error(this, "Error laying down header structures " + e1);
		}
	}

	private void processImageRuntimeFunctionEntries(FileHeader fileHeader, Program program,
			TaskMonitor monitor, MessageLog log) {

		// Check to see that we have exception data to process
		SectionHeader irfeHeader = null;
		for (SectionHeader header : fileHeader.getSectionHeaders()) {
			if (header.getName().contains(".pdata")) {
				irfeHeader = header;
				break;
			}
		}

		if (irfeHeader == null) {
			return;
		}

		Address start = program.getImageBase().add(irfeHeader.getVirtualAddress());

		List<_IMAGE_RUNTIME_FUNCTION_ENTRY> irfes = fileHeader.getImageRuntimeFunctionEntries();

		if (irfes.isEmpty()) {
			return;
		}

		// TODO: This is x86-64 architecture-specific and needs to be generalized.
		ImageRuntimeFunctionEntries.createData(program, start, irfes);

		// Each RUNTIME_INFO contains an address to an UNWIND_INFO structure
		// which also needs to be laid out. When they contain chaining data
		// they're recursive but the toDataType() function handles that.
		for (_IMAGE_RUNTIME_FUNCTION_ENTRY entry : irfes) {
			entry.createData(program);
		}
	}

	private void processSymbols(FileHeader fileHeader, Map<SectionHeader, Address> sectionToAddress,
			Program program, TaskMonitor monitor, MessageLog log) {
		List<DebugCOFFSymbol> symbols = fileHeader.getSymbols();
		int errorCount = 0;
		for (DebugCOFFSymbol symbol : symbols) {
			if (!processDebugCoffSymbol(symbol, fileHeader, sectionToAddress, program, monitor)) {
				++errorCount;
			}
		}

		if (errorCount != 0) {
			log.appendMsg(
				"Failed to apply " + errorCount + " symbols contained within unknown sections.");
		}
	}

	private void processProperties(OptionalHeader optionalHeader, Program prog,
			TaskMonitor monitor) {
		if (monitor.isCancelled()) {
			return;
		}
		Options props = prog.getOptions(Program.PROGRAM_INFO);
		props.setInt("SectionAlignment", optionalHeader.getSectionAlignment());
		props.setBoolean(RelocationTable.RELOCATABLE_PROP_NAME,
			prog.getRelocationTable().getSize() > 0);
	}

	private void processRelocations(OptionalHeader optionalHeader, Program prog,
			TaskMonitor monitor, MessageLog log) {

		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage("[" + prog.getName() + "]: processing relocation tables...");

		DataDirectory[] dataDirectories = optionalHeader.getDataDirectories();
		if (dataDirectories.length <= OptionalHeader.IMAGE_DIRECTORY_ENTRY_BASERELOC) {
			return;
		}
		BaseRelocationDataDirectory brdd =
			(BaseRelocationDataDirectory) dataDirectories[OptionalHeader.IMAGE_DIRECTORY_ENTRY_BASERELOC];
		if (brdd == null) {
			return;
		}

		AddressSpace space = prog.getAddressFactory().getDefaultAddressSpace();
		RelocationTable relocTable = prog.getRelocationTable();

		Memory memory = prog.getMemory();

		BaseRelocation[] relocs = brdd.getBaseRelocations();
		long originalImageBase = optionalHeader.getOriginalImageBase();
		AddressRange brddRange =
			new AddressRangeImpl(space.getAddress(originalImageBase + brdd.getVirtualAddress()),
				space.getAddress(originalImageBase + brdd.getVirtualAddress() + brdd.getSize()));
		AddressRange headerRange = new AddressRangeImpl(space.getAddress(originalImageBase),
			space.getAddress(originalImageBase + optionalHeader.getSizeOfHeaders()));
		DataConverter conv = LittleEndianDataConverter.INSTANCE;

		for (BaseRelocation reloc : relocs) {
			if (monitor.isCancelled()) {
				return;
			}
			int baseAddr = reloc.getVirtualAddress();
			int count = reloc.getCount();
			for (int j = 0; j < count; ++j) {
				int type = reloc.getType(j);
				if (type == BaseRelocation.IMAGE_REL_BASED_ABSOLUTE) {
					continue;
				}
				int offset = reloc.getOffset(j);
				long addr = Conv.intToLong(baseAddr + offset) + optionalHeader.getImageBase();
				Address relocAddr = space.getAddress(addr);

				try {
					byte[] bytes = optionalHeader.is64bit() ? new byte[8] : new byte[4];
					memory.getBytes(relocAddr, bytes);
					if (optionalHeader.wasRebased()) {
						long val = optionalHeader.is64bit() ? conv.getLong(bytes)
								: conv.getInt(bytes) & 0xFFFFFFFFL;
						val =
							val - (originalImageBase & 0xFFFFFFFFL) + optionalHeader.getImageBase();
						byte[] newbytes = optionalHeader.is64bit() ? conv.getBytes(val)
								: conv.getBytes((int) val);
						if (type == BaseRelocation.IMAGE_REL_BASED_HIGHLOW) {
							memory.setBytes(relocAddr, newbytes);
						}
						else if (type == BaseRelocation.IMAGE_REL_BASED_DIR64) {
							memory.setBytes(relocAddr, newbytes);
						}
						else {
							Msg.error(this, "Non-standard relocation type " + type);
						}
					}

					relocTable.add(relocAddr, type, null, bytes, null);

				}
				catch (MemoryAccessException e) {
					log.appendMsg("Relocation does not exist in memory: " + relocAddr);
				}
				if (brddRange.contains(relocAddr)) {
					Msg.error(this, "Self-modifying relocation table at " + relocAddr);
					return;
				}
				if (headerRange.contains(relocAddr)) {
					Msg.error(this, "Header modified at " + relocAddr);
					return;
				}
			}
		}
	}

	private void processImports(OptionalHeader optionalHeader, Program program, TaskMonitor monitor,
			MessageLog log) {

		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage("[" + program.getName() + "]: processing imports...");

		DataDirectory[] dataDirectories = optionalHeader.getDataDirectories();
		if (dataDirectories.length <= OptionalHeader.IMAGE_DIRECTORY_ENTRY_IMPORT) {
			return;
		}
		ImportDataDirectory idd =
			(ImportDataDirectory) dataDirectories[OptionalHeader.IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (idd == null) {
			return;
		}

		AddressFactory af = program.getAddressFactory();
		AddressSpace space = af.getDefaultAddressSpace();

		Listing listing = program.getListing();
		ReferenceManager refManager = program.getReferenceManager();

		ImportInfo[] imports = idd.getImports();
		for (ImportInfo importInfo : imports) {
			if (monitor.isCancelled()) {
				return;
			}

			long addr = Conv.intToLong(importInfo.getAddress()) + optionalHeader.getImageBase();

			//If not 64bit make sure address is not larger
			//than 32bit. On WindowsCE some sections are
			//declared to roll over.
			if (!optionalHeader.is64bit()) {
				addr &= Conv.INT_MASK;
			}

			Address address = space.getAddress(addr);

			setComment(CodeUnit.PRE_COMMENT, address, importInfo.getComment());

			Data data = listing.getDefinedDataAt(address);
			if (data == null || !(data.getValue() instanceof Address)) {
				continue;
			}

			Address extAddr = (Address) data.getValue();
			if (extAddr != null) {
				// remove the existing mem reference that was created
				// when making a pointer
				data.removeOperandReference(0, extAddr);
//	            symTable.removeSymbol(symTable.getDynamicSymbol(extAddr));

				try {
					refManager.addExternalReference(address, importInfo.getDLL().toUpperCase(),
						importInfo.getName(), extAddr, SourceType.IMPORTED, 0, RefType.DATA);
				}
				catch (DuplicateNameException e) {
					log.appendMsg("External location not created: " + e.getMessage());
				}
				catch (InvalidInputException e) {
					log.appendMsg("External location not created: " + e.getMessage());
				}
			}
		}
	}

	private void processDelayImports(OptionalHeader optionalHeader, Program program,
			TaskMonitor monitor, MessageLog log) {

		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage("[" + program.getName() + "]: processing delay imports...");

		DataDirectory[] dataDirectories = optionalHeader.getDataDirectories();
		if (dataDirectories.length <= OptionalHeader.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) {
			return;
		}

		DelayImportDataDirectory didd =
			(DelayImportDataDirectory) dataDirectories[OptionalHeader.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
		if (didd == null) {
			return;
		}

		log.appendMsg("Delay imports detected...");

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Listing listing = program.getListing();
		ReferenceManager refManager = program.getReferenceManager();
		FunctionManager funcManager = program.getFunctionManager();

		DelayImportDescriptor[] descriptors = didd.getDelayImportDescriptors();
		for (DelayImportDescriptor descriptor : descriptors) {
			if (monitor.isCancelled()) {
				return;
			}

			// Get address of the first entry in the import address table
			Address iatBaseAddr = space.getAddress(descriptor.isUsingRVA()
					? descriptor.getAddressOfIAT() + optionalHeader.getImageBase()
					: descriptor.getAddressOfIAT());

			for (ImportInfo importInfo : descriptor.getImportList()) {

				// Get the offset from the import list. -1 is the default (no offset)
				long offset = importInfo.getAddress();
				if (offset < 0) {
					break;
				}

				// Get address of current position in the import address table
				Address iatAddr = iatBaseAddr.add(offset);
				Data iatData = listing.getDataAt(iatAddr);
				if (iatData == null || !(iatData.getValue() instanceof Address)) {
					continue;
				}

				// Create external reference
				try {
					refManager.addExternalReference(iatAddr, importInfo.getDLL(),
						importInfo.getName(), null, SourceType.IMPORTED, 0, RefType.DATA);
				}
				catch (DuplicateNameException | InvalidInputException e) {
					log.appendMsg("Failed to create Delay Load external function at: " + iatAddr);
				}

				// Create delay load proxy function
				Address proxyFuncAddr = (Address) iatData.getValue();
				if (funcManager.getFunctionAt(proxyFuncAddr) == null) {
					try {
						funcManager.createFunction("DelayLoad_" + importInfo.getName(),
							proxyFuncAddr, new AddressSet(proxyFuncAddr), SourceType.IMPORTED);
					}
					catch (InvalidInputException | OverlappingFunctionException e) {
						log.appendMsg(
							"Failed to create Delay Load proxy function at: " + proxyFuncAddr);
					}
				}
			}
		}
	}

	/**
	 * Mark this location as code in the CodeMap.
	 * The analyzers will pick this up and disassemble the code.
	 *
	 * TODO: this should be in a common place, so all importers can communicate that something
	 * is code or data.
	 *
	 * @param program The program to mark up.
	 * @param address The location.
	 */
	private void markAsCode(Program program, Address address) {
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

	private void setProcessorContext(FileHeader fileHeader, Program program, TaskMonitor monitor,
			MessageLog log) {

		try {
			String machineName = fileHeader.getMachineName();
			if ("450".equals(machineName) || "452".equals(machineName)) {
				Register tmodeReg = program.getProgramContext().getRegister("TMode");
				if (tmodeReg == null) {
					return;
				}
				RegisterValue thumbMode = new RegisterValue(tmodeReg, BigInteger.ONE);
				AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
				program.getProgramContext()
						.setRegisterValue(space.getMinAddress(), space.getMaxAddress(), thumbMode);
			}
		}
		catch (ContextChangeException e) {
			throw new AssertException("instructions should not exist");
		}
	}

	private void processExports(OptionalHeader optionalHeader, Program program, TaskMonitor monitor,
			MessageLog log) {

		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage("[" + program.getName() + "]: processing exports...");

		DataDirectory[] dataDirectories = optionalHeader.getDataDirectories();
		if (dataDirectories.length <= OptionalHeader.IMAGE_DIRECTORY_ENTRY_EXPORT) {
			return;
		}
		ExportDataDirectory edd =
			(ExportDataDirectory) dataDirectories[OptionalHeader.IMAGE_DIRECTORY_ENTRY_EXPORT];

		if (edd == null) {
			return;
		}

		AddressFactory af = program.getAddressFactory();
		AddressSpace space = af.getDefaultAddressSpace();
		SymbolTable symTable = program.getSymbolTable();
		Listing listing = program.getListing();
		ReferenceManager refManager = program.getReferenceManager();

		ExportInfo[] exports = edd.getExports();
		for (ExportInfo export : exports) {
			if (monitor.isCancelled()) {
				return;
			}

			Address address = space.getAddress(export.getAddress());
			setComment(CodeUnit.PRE_COMMENT, address, export.getComment());
			symTable.addExternalEntryPoint(address);

			String name = export.getName();
			try {
				symTable.createLabel(address, name, SourceType.IMPORTED);
			}
			catch (InvalidInputException e) {
				// Don't create invalid symbol
			}

			try {
				symTable.createLabel(address, SymbolUtilities.ORDINAL_PREFIX + export.getOrdinal(),
					SourceType.IMPORTED);
			}
			catch (InvalidInputException e) {
				// Don't create invalid symbol
			}

			// When exported symbol is a forwarder,
			// a string exists at the address of the export
			// Therefore, create a string data object to prevent
			// disassembler from attempting to create
			// code here. If code was created, it would be incorrect
			// and offcut.
			if (export.isForwarded()) {
				try {
					listing.createData(address, TerminatedStringDataType.dataType, -1);
					Data data = listing.getDataAt(address);
					if (data != null) {
						Object obj = data.getValue();
						if (obj instanceof String) {
							String str = (String) obj;
							int dotpos = str.indexOf('.');

							if (dotpos < 0) {
								dotpos = 0;//TODO
							}

							// get the name of the dll
							String dllName = str.substring(0, dotpos) + ".dll";

							// get the name of the symbol
							String expName = str.substring(dotpos + 1);

							try {
								refManager.addExternalReference(address, dllName.toUpperCase(),
									expName, null, SourceType.IMPORTED, 0, RefType.DATA);
							}
							catch (DuplicateNameException e) {
								log.appendMsg("External location not created: " + e.getMessage());
							}
							catch (InvalidInputException e) {
								log.appendMsg("External location not created: " + e.getMessage());
							}
						}
					}
				}
				catch (CodeUnitInsertionException e) {
					// Nothing to do...just continue on
				}
			}
		}
	}

	private Map<SectionHeader, Address> processMemoryBlocks(PortableExecutable pe, Program prog,
			FileBytes fileBytes, TaskMonitor monitor, MessageLog log)
			throws AddressOverflowException {

		AddressFactory af = prog.getAddressFactory();
		AddressSpace space = af.getDefaultAddressSpace();
		Map<SectionHeader, Address> sectionToAddress = new HashMap<>();

		if (monitor.isCancelled()) {
			return sectionToAddress;
		}
		monitor.setMessage("[" + prog.getName() + "]: processing memory blocks...");

		NTHeader ntHeader = pe.getNTHeader();
		FileHeader fileHeader = ntHeader.getFileHeader();
		OptionalHeader optionalHeader = ntHeader.getOptionalHeader();

		SectionHeader[] sections = fileHeader.getSectionHeaders();
		if (sections.length == 0) {
			Msg.warn(this, "No sections found");
		}

		// Header block
		int virtualSize = (int) Math.min(getVirtualSize(pe, sections, space), fileBytes.getSize());
		long addr = optionalHeader.getImageBase();
		Address address = space.getAddress(addr);

		boolean r = true;
		boolean w = false;
		boolean x = false;
		MemoryBlockUtils.createInitializedBlock(prog, false, HEADERS, address, fileBytes, 0,
			virtualSize, "", "", r, w, x, log);

		// Section blocks
		try {
			for (int i = 0; i < sections.length; ++i) {
				if (monitor.isCancelled()) {
					return sectionToAddress;
				}

				addr = sections[i].getVirtualAddress() + optionalHeader.getImageBase();

				address = space.getAddress(addr);

				r = ((sections[i].getCharacteristics() &
					SectionFlags.IMAGE_SCN_MEM_READ.getMask()) != 0x0);
				w = ((sections[i].getCharacteristics() &
					SectionFlags.IMAGE_SCN_MEM_WRITE.getMask()) != 0x0);
				x = ((sections[i].getCharacteristics() &
					SectionFlags.IMAGE_SCN_MEM_EXECUTE.getMask()) != 0x0);

				int rawDataSize = sections[i].getSizeOfRawData();
				int rawDataPtr = sections[i].getPointerToRawData();
				virtualSize = sections[i].getVirtualSize();
				if (rawDataSize != 0 && rawDataPtr != 0) {
					int dataSize =
						((rawDataSize > virtualSize && virtualSize > 0) || rawDataSize < 0)
								? virtualSize
								: rawDataSize;
					if (ntHeader.checkRVA(dataSize) ||
						(0 < dataSize && dataSize < pe.getFileLength())) {
						if (!ntHeader.checkRVA(dataSize)) {
							Msg.warn(this, "OptionalHeader.SizeOfImage < size of " +
								sections[i].getName() + " section");
						}
						String sectionName = sections[i].getReadableName();
						if (sectionName.isBlank()) {
							sectionName = "SECTION." + i;
						}
						MemoryBlockUtils.createInitializedBlock(prog, false, sectionName, address,
							fileBytes, rawDataPtr, dataSize, "", "", r, w, x, log);
						sectionToAddress.put(sections[i], address);
					}
					if (rawDataSize == virtualSize) {
						continue;
					}
					else if (rawDataSize > virtualSize) {
						// virtual size fully initialized
						continue;
					}
					// remainder of virtual size is uninitialized
					if (rawDataSize < 0) {
						Msg.error(this,
							"Section[" + i + "] has invalid size " +
								Integer.toHexString(rawDataSize) + " (" +
								Integer.toHexString(virtualSize) + ")");
						break;
					}
					virtualSize -= rawDataSize;
					address = address.add(rawDataSize);
				}

				if (virtualSize == 0) {
					Msg.error(this, "Section[" + i + "] has size zero");
				}
				else {
					int dataSize = (virtualSize > 0 || rawDataSize < 0) ? virtualSize : 0;
					if (dataSize > 0) {
						MemoryBlockUtils.createUninitializedBlock(prog, false,
							sections[i].getReadableName(), address, dataSize, "", "", r, w, x, log);
						sectionToAddress.put(sections[i], address);
					}
				}

			}
		}
		catch (IllegalStateException ise) {
			if (optionalHeader.getFileAlignment() != optionalHeader.getSectionAlignment()) {
				throw new IllegalStateException(ise);
			}
			Msg.warn(this, "Section header processing aborted");
		}

		return sectionToAddress;
	}

	private int getVirtualSize(PortableExecutable pe, SectionHeader[] sections,
			AddressSpace space) {
		DOSHeader dosHeader = pe.getDOSHeader();
		OptionalHeader optionalHeader = pe.getNTHeader().getOptionalHeader();
		int virtualSize = optionalHeader.is64bit() ? Constants.IMAGE_SIZEOF_NT_OPTIONAL64_HEADER
				: Constants.IMAGE_SIZEOF_NT_OPTIONAL32_HEADER;
		virtualSize += FileHeader.IMAGE_SIZEOF_FILE_HEADER + 4;
		virtualSize += dosHeader.e_lfanew();
		if (optionalHeader.getSizeOfHeaders() > virtualSize) {
			virtualSize = (int) optionalHeader.getSizeOfHeaders();
		}

		if (optionalHeader.getFileAlignment() == optionalHeader.getSectionAlignment()) {
			if (optionalHeader.getFileAlignment() <= 0x800) {
				Msg.warn(this,
					"File and section alignments identical - possible driver or sectionless image");
			}
		}
		//long max = space.getMaxAddress().getOffset() - optionalHeader.getImageBase();
		//if (virtualSize > max) {
		//	virtualSize = (int) max;
		//	Msg.error(this, "Possible truncation of image at "+Long.toHexString(optionalHeader.getImageBase()));
		//}
		return virtualSize;
	}

	private void processEntryPoints(NTHeader ntHeader, Program prog, TaskMonitor monitor) {
		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage("[" + prog.getName() + "]: processing entry points...");

		OptionalHeader optionalHeader = ntHeader.getOptionalHeader();
		AddressFactory af = prog.getAddressFactory();
		AddressSpace space = af.getDefaultAddressSpace();
		SymbolTable symTable = prog.getSymbolTable();

		long entry = optionalHeader.getAddressOfEntryPoint();
		int ptr = ntHeader.rvaToPointer((int) entry);
		if (ptr < 0) {
			if (entry != 0 ||
				(ntHeader.getFileHeader().getCharacteristics() & FileHeader.IMAGE_FILE_DLL) == 0) {
				Msg.warn(this, "Virtual entry point at " + Long.toHexString(entry));
			}
		}
		Address baseAddr = space.getAddress(entry);
		long imageBase = optionalHeader.getImageBase();
		Address entryAddr = baseAddr.addWrap(imageBase);
		entry += optionalHeader.getImageBase();

		// get IL entry if it has one
		Address ILEntryPointVA = getILEntryPoint(optionalHeader);
		if (ILEntryPointVA != null) {
			// The OptionalHeader can specify a single-instruction native code
			// entry point even in IL-only binaries for backwards compatibility
			if (entry > 0) {
				try {
					symTable.createLabel(entryAddr, "__x86_CIL_", SourceType.IMPORTED);
					markAsCode(prog, entryAddr);
					symTable.addExternalEntryPoint(entryAddr);
				}
				catch (InvalidInputException e) {
					Msg.warn(this,
						"Backwards compatible native entry point in the CIL binary couldn't be processed");
				}
			}

			// Replace native entry point address with IL entry point
			entryAddr = ILEntryPointVA;
		}

		try {
			// mark up entry (either Native or IL)
			symTable.createLabel(entryAddr, "entry", SourceType.IMPORTED);
			markAsCode(prog, entryAddr);
		}
		catch (InvalidInputException e) {
			// ignore
		}

		symTable.addExternalEntryPoint(entryAddr);
	}

	// @return IL entry point, or null if the binary has a native Entry point
	private Address getILEntryPoint(OptionalHeader optionalHeader) {
		// Check to see if this binary has a COMDescriptorDataDirectory in it. If so,
		// it might be a .NET binary, and if it is and only has a managed code entry point
		// the value at entry is actually a table index and and row index that we parse in
		// the ImageCor20Header class. Use that to create the entry label instead later.

		DataDirectory[] dataDirectories = optionalHeader.getDataDirectories();
		for (DataDirectory element : dataDirectories) {
			if (element == null) {
				continue;
			}
			if (!(element instanceof COMDescriptorDataDirectory)) {
				continue;
			}

			COMDescriptorDataDirectory comDescriptorDataDirectory =
				(COMDescriptorDataDirectory) element;
			ImageCor20Header imageCor20Header = comDescriptorDataDirectory.getHeader();
			if (imageCor20Header == null) {
				continue;
			}

			if ((imageCor20Header.getFlags() &
				ImageCor20Flags.COMIMAGE_FLAGS_NATIVE_ENTRYPOINT) != ImageCor20Flags.COMIMAGE_FLAGS_NATIVE_ENTRYPOINT) {
				continue;
			}
			// Check the flag to see if there's a native code entry point, and if
			// not this binary has an IL entry that we should label
			return imageCor20Header.getEntryPointVA();
		}

		return null;
	}

	private void processDebug(OptionalHeader optionalHeader, FileHeader fileHeader,
			Map<SectionHeader, Address> sectionToAddress, Program program, TaskMonitor monitor) {
		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage("[" + program.getName() + "]: processing debug information...");

		DataDirectory[] dataDirectories = optionalHeader.getDataDirectories();
		if (dataDirectories.length <= OptionalHeader.IMAGE_DIRECTORY_ENTRY_DEBUG) {
			return;
		}
		DebugDataDirectory ddd =
			(DebugDataDirectory) dataDirectories[OptionalHeader.IMAGE_DIRECTORY_ENTRY_DEBUG];

		if (ddd == null) {
			return;
		}

		DebugDirectoryParser parser = ddd.getParser();
		if (parser == null) {
			return;
		}

		processDebug(parser, fileHeader, sectionToAddress, program, monitor);
	}

	@Override
	public String getName() {
		return PE_NAME;
	}

	public static class CompilerOpinion {
		static final char[] errString_borland =
			"This program must be run under Win32\r\n$".toCharArray();
		static final char[] errString_GCC_VS =
			"This program cannot be run in DOS mode.\r\r\n$".toCharArray();
		static final char[] errString_Clang =
			"This program cannot be run in DOS mode.$".toCharArray();
		static final int[] asm16_Borland = { 0xBA, 0x10, 0x00, 0x0E, 0x1F, 0xB4, 0x09, 0xCD, 0x21,
			0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x90, 0x90 };
		static final int[] asm16_GCC_VS_Clang =
			{ 0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21 };

		public enum CompilerEnum {

			VisualStudio("visualstudio:unknown"),
			GCC("gcc:unknown"),
			Clang("clang:unknown"),
			GCC_VS("visualstudiogcc"),
			GCC_VS_Clang("visualstudiogccclang"),
			BorlandPascal("borland:pascal"),
			BorlandCpp("borland:c++"),
			BorlandUnk("borland:unknown"),
			CLI("cli"),
			Unknown("unknown");

			private String label;

			private CompilerEnum(String label) {
				this.label = label;
			}

			@Override
			public String toString() {
				return label;
			}
		}

		// Treat string as upto 3 colon separated fields describing a compiler  --   <product>:<language>:version
		public static String stripFamily(CompilerEnum val) {
			if (val == CompilerEnum.BorlandCpp) {
				return "borlandcpp";
			}
			if (val == CompilerEnum.BorlandPascal) {
				return "borlanddelphi";
			}
			if (val == CompilerEnum.BorlandUnk) {
				return "borlandcpp";
			}
			String compilerid = val.toString();
			int colon = compilerid.indexOf(':');
			if (colon > 0) {
				return compilerid.substring(0, colon);
			}
			return compilerid;
		}

		private static SectionHeader getSectionHeader(String name, SectionHeader[] list) {
			for (SectionHeader element : list) {
				if (element.getName().equals(name)) {
					return element;
				}
			}
			return null;
		}

		/**
		 * Return true if chararray appears in full, starting at offset bytestart in bytearray
		 * @param bytearray the array of bytes containing the potential match
		 * @param bytestart the potential start of the match
		 * @param chararray the array of characters to match
		 * @return true if there is a full match
		 */
		private static boolean compareBytesToChars(byte[] bytearray, int bytestart,
				char[] chararray) {
			int i = 0;
			if (bytestart + chararray.length < bytearray.length) {
				for (; i < chararray.length; ++i) {
					if (chararray[i] != (char) bytearray[bytestart + i]) {
						break;
					}
				}
			}
			return (i == chararray.length);
		}

		public static CompilerEnum getOpinion(PortableExecutable pe, ByteProvider provider)
				throws IOException {
			CompilerEnum compilerType = CompilerEnum.Unknown;
			CompilerEnum offsetChoice = CompilerEnum.Unknown;
			CompilerEnum asmChoice = CompilerEnum.Unknown;
			CompilerEnum errStringChoice = CompilerEnum.Unknown;
			BinaryReader br = new BinaryReader(provider, true);

			DOSHeader dh = pe.getDOSHeader();

			// Check for managed code (.NET)
			if (pe.getNTHeader().getOptionalHeader().isCLI()) {
				return CompilerEnum.CLI;
			}

			// Determine based on PE Header offset
			if (dh.e_lfanew() == 0x80) {
				offsetChoice = CompilerEnum.GCC_VS;
			}
			else if (dh.e_lfanew() == 0x78) {
				offsetChoice = CompilerEnum.Clang;
			}
			else if (dh.e_lfanew() < 0x80) {
				offsetChoice = CompilerEnum.Unknown;
			}
			else {

				// Check for "DanS"
				int val1 = br.readInt(0x80);
				int val2 = br.readInt(0x80 + 4);

				if (val1 != 0 && val2 != 0 && (val1 ^ val2) == 0x536e6144) {
					compilerType = CompilerEnum.VisualStudio;
					return compilerType;
				}
				else if (dh.e_lfanew() == 0x100) {
					offsetChoice = CompilerEnum.BorlandPascal;
				}
				else if (dh.e_lfanew() == 0x200) {
					offsetChoice = CompilerEnum.BorlandCpp;
				}
				else if (dh.e_lfanew() > 0x300) {
					compilerType = CompilerEnum.Unknown;
					return compilerType;
				}
				else {
					offsetChoice = CompilerEnum.Unknown;
				}
			} // End PE header offset check

			int counter;
			byte[] asm = provider.readBytes(0x40, 256);
			for (counter = 0; counter < asm16_Borland.length; counter++) {
				if ((asm[counter] & 0xff) != (asm16_Borland[counter] & 0xff)) {
					break;
				}
			}
			if (counter == asm16_Borland.length) {
				asmChoice = CompilerEnum.BorlandUnk;
			}
			else {
				for (counter = 0; counter < asm16_GCC_VS_Clang.length; counter++) {
					if ((asm[counter] & 0xff) != (asm16_GCC_VS_Clang[counter] & 0xff)) {
						break;
					}
				}
				if (counter == asm16_GCC_VS_Clang.length) {
					asmChoice = CompilerEnum.GCC_VS_Clang;
				}
				else {
					asmChoice = CompilerEnum.Unknown;
				}
			}
			// Check for error message
			int errStringOffset = -1;
			for (int i = 10; i < asm.length - 3; i++) {
				if (asm[i] == 'T' && asm[i + 1] == 'h' && asm[i + 2] == 'i' && asm[i + 3] == 's') {
					errStringOffset = i;
					break;
				}
			}

			if (errStringOffset == -1) {
				asmChoice = CompilerEnum.Unknown;
			}
			else {
				if (compareBytesToChars(asm, errStringOffset, errString_borland)) {
					errStringChoice = CompilerEnum.BorlandUnk;
					if (offsetChoice == CompilerEnum.BorlandCpp ||
						offsetChoice == CompilerEnum.BorlandPascal) {
						compilerType = offsetChoice;
						return compilerType;
					}
				}
				else if (compareBytesToChars(asm, errStringOffset, errString_GCC_VS)) {
					errStringChoice = CompilerEnum.GCC_VS;
				}
				else if (compareBytesToChars(asm, errStringOffset, errString_Clang)) {
					errStringChoice = CompilerEnum.Clang;
				}
				else {
					errStringChoice = CompilerEnum.Unknown;
				}
			}

			// Check for AddressOfStart and PointerToSymbol
			if (errStringChoice == CompilerEnum.GCC_VS && asmChoice == CompilerEnum.GCC_VS_Clang &&
				dh.e_lfanew() == 0x80) {
				// Trying to determine if we have gcc or old VS

				// Look for the "Visual Studio" library identifier
//				if (mem.findBytes(mem.getMinAddress(), "Visual Studio".getBytes(),
//						null, true, monitor) != null) {
//					compilerType = COMPIL_VS;
//					return compilerType;
//				}

				// Now look for offset to code (0x1000 for gcc) and PointerToSymbols
				// (0 for VS, non-zero for gcc)
				int addrCode = br.readInt(dh.e_lfanew() + 40);
				if (addrCode != 0x1000) {
					compilerType = CompilerEnum.VisualStudio;
					return compilerType;
				}

				int ptrSymTable = br.readInt(dh.e_lfanew() + 12);
				if (ptrSymTable != 0) {
					compilerType = CompilerEnum.GCC;
					return compilerType;
				}
			}
			else if ((offsetChoice == CompilerEnum.Clang ||
				errStringChoice == CompilerEnum.Clang) && asmChoice == CompilerEnum.GCC_VS_Clang) {
				compilerType = CompilerEnum.Clang;
				return compilerType;
			}
			else if (errStringChoice == CompilerEnum.Unknown || asmChoice == CompilerEnum.Unknown) {
				compilerType = CompilerEnum.Unknown;
				return compilerType;
			}

			if (errStringChoice == CompilerEnum.BorlandUnk ||
				asmChoice == CompilerEnum.BorlandUnk) {
				// Pretty sure it's Borland, but didn't get 0x100 or 0x200
				compilerType = CompilerEnum.BorlandUnk;
				return compilerType;
			}

			if ((offsetChoice == CompilerEnum.GCC_VS) || (errStringChoice == CompilerEnum.GCC_VS)) {
				// Pretty sure it's either gcc or Visual Studio
				compilerType = CompilerEnum.GCC_VS;
			}
			else {
				// Not sure what it is
				compilerType = CompilerEnum.Unknown;
			}

			// Reaching this point implies that we did not find "DanS and we didn't
			// see the Borland DOS complaint
			boolean probablyNotVS = false;
			// TODO: See if we have an .idata segment and what type it is
			// Need to make sure that this is the right check to be making
			SectionHeader[] headers = pe.getNTHeader().getFileHeader().getSectionHeaders();
			if (getSectionHeader(".idata", headers) != null) {
				probablyNotVS = true;
			}

			if (getSectionHeader("CODE", headers) != null) {
				compilerType = CompilerEnum.BorlandPascal;
				return compilerType;
			}

			SectionHeader segment = getSectionHeader(".bss", headers);
			if ((segment != null)/* && segment.getType() == BSS_TYPE */) {
				compilerType = CompilerEnum.GCC;
				return compilerType;
//			} else if (segment != null) {
//				compilerType = CompilerEnum.BorlandCpp;
//				return compilerType;
			}
			else if (!probablyNotVS) {
				compilerType = CompilerEnum.VisualStudio;
				return compilerType;
			}

			if (getSectionHeader(".tls", headers) != null) {
				// expect Borland - prefer cpp since CODE segment didn't occur
				compilerType = CompilerEnum.BorlandCpp;
			}

			return compilerType;
		}
	}
}
