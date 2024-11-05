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

import com.google.common.primitives.Bytes;

import ghidra.app.plugin.core.analysis.rust.RustConstants;
import ghidra.app.plugin.core.analysis.rust.RustUtilities;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.info.ElfInfoItem.ItemWithAddress;
import ghidra.app.util.bin.format.golang.GoBuildId;
import ghidra.app.util.bin.format.golang.GoBuildInfo;
import ghidra.app.util.bin.format.golang.rtti.GoRttiMapper;
import ghidra.app.util.bin.format.mz.DOSHeader;
import ghidra.app.util.bin.format.pe.*;
import ghidra.app.util.bin.format.pe.ImageCor20Header.ImageCor20Flags;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.app.util.bin.format.pe.debug.DebugCOFFSymbol;
import ghidra.app.util.bin.format.pe.debug.DebugDirectoryParser;
import ghidra.app.util.bin.format.swift.SwiftUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.Options;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
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

		PortableExecutable pe = new PortableExecutable(provider, getSectionLayout(), false, false);
		NTHeader ntHeader = pe.getNTHeader();
		if (ntHeader != null && ntHeader.getOptionalHeader() != null) {
			long imageBase = ntHeader.getOptionalHeader().getImageBase();
			String machineName = ntHeader.getFileHeader().getMachineName();
			String compilerFamily = CompilerOpinion.getOpinion(pe, provider, null,
				TaskMonitor.DUMMY, new MessageLog()).family;
			for (QueryResult result : QueryOpinionService.query(getName(), machineName,
				compilerFamily)) {
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

		PortableExecutable pe = new PortableExecutable(provider, getSectionLayout(), false,
			shouldParseCliHeaders(options));

		NTHeader ntHeader = pe.getNTHeader();
		if (ntHeader == null) {
			return;
		}
		OptionalHeader optionalHeader = ntHeader.getOptionalHeader();

		monitor.setMessage("Completing PE header parsing...");
		FileBytes fileBytes = createFileBytes(provider, program, monitor);
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

			processExports(optionalHeader, program, monitor, log);
			processImports(optionalHeader, program, monitor, log);
			processDelayImports(optionalHeader, program, monitor, log);
			processRelocations(optionalHeader, program, monitor, log);
			processDebug(optionalHeader, ntHeader, sectionToAddress, program, options, monitor);
			processProperties(optionalHeader, ntHeader, program, monitor);
			processComments(program.getListing(), monitor);
			processSymbols(ntHeader, sectionToAddress, program, monitor, log);

			processEntryPoints(ntHeader, program, monitor);
			String compiler =
				CompilerOpinion.getOpinion(pe, provider, program, monitor, log).toString();
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
		catch (MemoryAccessException e) {
			throw new IOException(e);
		}
		monitor.setMessage("[" + program.getName() + "]: done!");
	}

	protected SectionLayout getSectionLayout() {
		return SectionLayout.FILE;
	}

	protected FileBytes createFileBytes(ByteProvider provider, Program program, TaskMonitor monitor)
			throws IOException, CancelledException {
		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);
		return fileBytes;
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
			DataUtilities.createData(program, start, dt, -1,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			dt = pe.getRichHeader().toDataType();
			if (dt != null) {
				start = program.getImageBase().add(pe.getRichHeader().getOffset());
				DataUtilities.createData(program, start, dt, -1,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			}

			dt = ntHeader.toDataType();
			start = program.getImageBase().add(pe.getDOSHeader().e_lfanew());
			DataUtilities.createData(program, start, dt, -1,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			FileHeader fh = ntHeader.getFileHeader();
			SectionHeader[] sections = fh.getSectionHeaders();
			int index = fh.getPointerToSections();
			start = program.getImageBase().add(index);
			for (SectionHeader section : sections) {
				dt = section.toDataType();
				DataUtilities.createData(program, start, dt, -1,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				setComment(CodeUnit.EOL_COMMENT, start, section.getName());
				start = start.add(dt.getLength());
			}
		}
		catch (Exception e1) {
			Msg.error(this, "Error laying down header structures " + e1);
		}
	}

	private void processSymbols(NTHeader ntHeader, Map<SectionHeader, Address> sectionToAddress,
			Program program, TaskMonitor monitor, MessageLog log) {
		FileHeader fileHeader = ntHeader.getFileHeader();
		List<DebugCOFFSymbol> symbols = fileHeader.getSymbols();
		int errorCount = 0;
		for (DebugCOFFSymbol symbol : symbols) {
			if (!processDebugCoffSymbol(symbol, ntHeader, sectionToAddress, program, monitor)) {
				++errorCount;
			}
		}

		if (errorCount != 0) {
			log.appendMsg(
				"Failed to apply " + errorCount + " symbols contained within unknown sections.");
		}
	}

	private void processProperties(OptionalHeader optionalHeader, NTHeader ntHeader, Program prog,
			TaskMonitor monitor) {
		if (monitor.isCancelled()) {
			return;
		}
		Options props = prog.getOptions(Program.PROGRAM_INFO);
		props.setInt("SectionAlignment", optionalHeader.getSectionAlignment());
		props.setBoolean(RelocationTable.RELOCATABLE_PROP_NAME,
			prog.getRelocationTable().getSize() > 0);

		if (GoRttiMapper.isGolangProgram(prog)) {
			processGolangProperties(optionalHeader, ntHeader, prog, monitor);
		}
	}

	private void processGolangProperties(OptionalHeader optionalHeader, NTHeader ntHeader,
			Program prog, TaskMonitor monitor) {

		ItemWithAddress<GoBuildId> buildId = GoBuildId.findBuildId(prog);
		if (buildId != null) {
			buildId.item().markupProgram(prog, buildId.address());
		}
		ItemWithAddress<GoBuildInfo> buildInfo = GoBuildInfo.findBuildInfo(prog);
		if (buildInfo != null) {
			buildInfo.item().markupProgram(prog, buildInfo.address());
		}

	}

	private void processRelocations(OptionalHeader optionalHeader, Program prog,
			TaskMonitor monitor, MessageLog log) {
		// We don't currently support relocations in PE's because we always load at the preferred
		// image base, but we'll go though them anyway and add them to the relocation table

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

		for (BaseRelocation reloc : brdd.getBaseRelocations()) {
			if (monitor.isCancelled()) {
				return;
			}
			int baseAddr = reloc.getVirtualAddress();
			for (int i = 0; i < reloc.getCount(); ++i) {
				long addr = optionalHeader.getImageBase() + baseAddr + reloc.getOffset(i);
				relocTable.add(space.getAddress(addr), Status.SKIPPED, reloc.getType(i), null, null,
					null);
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

		ImportInfo[] imports = idd.getImports();
		for (ImportInfo importInfo : imports) {
			if (monitor.isCancelled()) {
				return;
			}

			long addr =
				Integer.toUnsignedLong(importInfo.getAddress()) + optionalHeader.getImageBase();

			//If not 64bit make sure address is not larger
			//than 32bit. On WindowsCE some sections are
			//declared to roll over.
			if (!optionalHeader.is64bit()) {
				addr &= 0x00000000ffffffffL;
			}

			Address address = space.getAddress(addr);

			setComment(CodeUnit.PRE_COMMENT, address, importInfo.getComment());

			Data data = listing.getDefinedDataAt(address);
			if (data != null && data.isPointer()) {
				addExternalReference(data, importInfo, log);
			}
		}
	}

	protected void addExternalReference(Data pointerData, ImportInfo importInfo, MessageLog log) {
		Address extAddr = (Address) pointerData.getValue();
		if (extAddr != null) {
			// remove the existing mem reference that was created when making a pointer
			pointerData.removeOperandReference(0, extAddr);
//	            symTable.removeSymbol(symTable.getDynamicSymbol(extAddr));

			try {
				ReferenceManager refManager = pointerData.getProgram().getReferenceManager();
				refManager.addExternalReference(pointerData.getAddress(),
					importInfo.getDLL().toUpperCase(), importInfo.getName(), extAddr,
					SourceType.IMPORTED, 0, RefType.DATA);
			}
			catch (DuplicateNameException e) {
				log.appendMsg("External location not created: " + e.getMessage());
			}
			catch (InvalidInputException e) {
				log.appendMsg("External location not created: " + e.getMessage());
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
	 * Mark this location as code in the CodeMap. The analyzers will pick this up and disassemble
	 * the code.
	 *
	 * TODO: this should be in a common place, so all importers can communicate that something is
	 * code or data.
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

	protected Map<SectionHeader, Address> processMemoryBlocks(PortableExecutable pe, Program prog,
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

				String sectionName = sections[i].getReadableName();
				if (sectionName.isBlank()) {
					sectionName = "SECTION." + i;
				}

				r = ((sections[i].getCharacteristics() &
					SectionFlags.IMAGE_SCN_MEM_READ.getMask()) != 0x0);
				w = ((sections[i].getCharacteristics() &
					SectionFlags.IMAGE_SCN_MEM_WRITE.getMask()) != 0x0);
				x = ((sections[i].getCharacteristics() &
					SectionFlags.IMAGE_SCN_MEM_EXECUTE.getMask()) != 0x0);

				int rawDataSize = sections[i].getSizeOfRawData();
				int rawDataPtr = sections[i].getPointerToRawData();
				virtualSize = sections[i].getVirtualSize();
				MemoryBlock block = null;
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
						block = MemoryBlockUtils.createInitializedBlock(prog, false, sectionName,
							address, fileBytes, rawDataPtr, dataSize, "", "", r, w, x, log);
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
						if (block != null) {
							MemoryBlock paddingBlock =
								MemoryBlockUtils.createInitializedBlock(prog, false, sectionName,
									address, dataSize, "", "", r, w, x, log);
							if (paddingBlock != null) {
								try {
									prog.getMemory().join(block, paddingBlock);
								}
								catch (Exception e) {
									log.appendMsg(e.getMessage());
								}
							}
						}
						else {
							MemoryBlockUtils.createUninitializedBlock(prog, false, sectionName,
								address, dataSize, "", "", r, w, x, log);
							sectionToAddress.putIfAbsent(sections[i], address);
						}
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

	protected int getVirtualSize(PortableExecutable pe, SectionHeader[] sections,
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

	private void processDebug(OptionalHeader optionalHeader, NTHeader ntHeader,
			Map<SectionHeader, Address> sectionToAddress, Program program, List<Option> options,
			TaskMonitor monitor) {
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

		processDebug(parser, ntHeader, sectionToAddress, program, options, monitor);
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
		static final byte[] asm16_Borland =
			{ (byte) 0xBA, 0x10, 0x00, 0x0E, 0x1F, (byte) 0xB4, 0x09, (byte) 0xCD, 0x21,
				(byte) 0xB8, 0x01, 0x4C, (byte) 0xCD, 0x21, (byte) 0x90, (byte) 0x90 };
		static final byte[] asm16_GCC_VS_Clang = { 0x0e, 0x1f, (byte) 0xba, 0x0e, 0x00, (byte) 0xb4,
			0x09, (byte) 0xcd, 0x21, (byte) 0xb8, 0x01, 0x4c, (byte) 0xcd, 0x21 };
		static final byte[] THIS_BYTES = "This".getBytes();

		public enum CompilerEnum {

			VisualStudio("visualstudio:unknown", "visualstudio"),
			GCC("gcc:unknown", "gcc"),
			Clang("clang:unknown", "clang"),
			BorlandPascal("borland:pascal", "borlanddelphi"),
			BorlandCpp("borland:c++", "borlandcpp"),
			BorlandUnk("borland:unknown", "borlandcpp"),
			CLI("cli", "cli"),
			Rustc(RustConstants.RUST_COMPILER, RustConstants.RUST_COMPILER),
			GOLANG("golang", "golang"),
			Swift(SwiftUtils.SWIFT_COMPILER, SwiftUtils.SWIFT_COMPILER),
			Unknown("unknown", "unknown"),

			// The following values represent the presence of ambiguous indicators
			// and should not be returned by the compiler opinion method.
			GCC_VS(null, null), // GCC | VS
			GCC_VS_Clang(null, null), // GCC | VS | CLANG
			;

			public final String label; // value stored as ProgramInformation.Compiler property
			public final String family; // used for Opinion secondary query param

			CompilerEnum(String label, String secondary) {
				this.label = label;
				this.family = secondary;
			}

			@Override
			public String toString() {
				return label;
			}
		}

		/**
		 * Return true if chararray appears in full, starting at offset bytestart in bytearray
		 * 
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

		public static CompilerEnum getOpinion(PortableExecutable pe, ByteProvider provider,
				Program program, TaskMonitor monitor, MessageLog log) throws IOException {

			CompilerEnum offsetChoice = CompilerEnum.Unknown;
			CompilerEnum asmChoice = CompilerEnum.Unknown;
			CompilerEnum errStringChoice = CompilerEnum.Unknown;
			BinaryReader br = new BinaryReader(provider, true);

			DOSHeader dh = pe.getDOSHeader();

			// Check for Rust.  Program object is required, which may be null.
			if (program != null && RustUtilities.isRust(program.getMemory().getBlock(".rdata"))) {
				try {
					int extensionCount = RustUtilities.addExtensions(program, monitor,
						RustConstants.RUST_EXTENSIONS_WINDOWS);
					log.appendMsg("Installed " + extensionCount + " Rust cspec extensions");
				}
				catch (IOException e) {
					log.appendMsg("Rust error: " + e.getMessage());
				}
				return CompilerEnum.Rustc;
			}
			
			// Check for Swift
			List<String> sectionNames =
				Arrays.stream(pe.getNTHeader().getFileHeader().getSectionHeaders())
						.map(section -> section.getName())
						.toList();
			if (SwiftUtils.isSwift(sectionNames)) {
				return CompilerEnum.Swift;
			}

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
			else if (dh.e_lfanew() >= 0x80) {

				// Check for "DanS"
				int val1 = br.readInt(0x80);
				int val2 = br.readInt(0x80 + 4);

				if (val1 != 0 && val2 != 0 && (val1 ^ val2) == 0x536e6144 /* "DanS" */) {
					// Rich Image Header is present
					return CompilerEnum.VisualStudio;
				}

				if (dh.e_lfanew() == 0x100) {
					offsetChoice = CompilerEnum.BorlandPascal; // Could also be Borland-C
				}
				else if (dh.e_lfanew() == 0x200) {
					offsetChoice = CompilerEnum.BorlandCpp;
				}
				else if (dh.e_lfanew() > 0x300) {
					return CompilerEnum.Unknown;
				}
			} // End PE header offset check

			byte[] asm = provider.readBytes(0x40, 256);
			asmChoice = CompilerEnum.Unknown;
			if (Arrays.compare(asm, 0, asm16_Borland.length, asm16_Borland, 0,
				asm16_Borland.length) == 0) {
				asmChoice = CompilerEnum.BorlandUnk;
			}
			else if (Arrays.compare(asm, 0, asm16_GCC_VS_Clang.length, asm16_GCC_VS_Clang, 0,
				asm16_GCC_VS_Clang.length) == 0) {
				asmChoice = CompilerEnum.GCC_VS_Clang;
			}

			// Check for error message
			int errStringOffset = Bytes.indexOf(asm, THIS_BYTES);
			if (errStringOffset == -1) {
				asmChoice = CompilerEnum.Unknown;
			}
			else {
				if (compareBytesToChars(asm, errStringOffset, errString_borland)) {
					if (offsetChoice == CompilerEnum.BorlandCpp ||
						offsetChoice == CompilerEnum.BorlandPascal) {
						return offsetChoice;
					}
					errStringChoice = CompilerEnum.BorlandUnk;
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
//					return CompilerEnum.VisualStudio
//				}

				if (isGolang(pe, provider)) {
					return CompilerEnum.GOLANG;
				}

				// Now look for PointerToSymbols (0 for VS, non-zero for gcc)
				int ptrSymTable = br.readInt(dh.e_lfanew() + 12);
				if (ptrSymTable != 0) {
					return CompilerEnum.GCC;
				}
			}
			else if ((offsetChoice == CompilerEnum.Clang ||
				errStringChoice == CompilerEnum.Clang) && asmChoice == CompilerEnum.GCC_VS_Clang) {
				return CompilerEnum.Clang;
			}
			else if (errStringChoice == CompilerEnum.Unknown || asmChoice == CompilerEnum.Unknown) {
				return CompilerEnum.Unknown;
			}

			if (errStringChoice == CompilerEnum.BorlandUnk ||
				asmChoice == CompilerEnum.BorlandUnk) {
				// Pretty sure it's Borland, but didn't get 0x100 or 0x200
				return CompilerEnum.BorlandUnk;
			}

//			if ((offsetChoice == CompilerEnum.GCC_VS) || (errStringChoice == CompilerEnum.GCC_VS)) {
//				// Pretty sure it's either gcc or Visual Studio
//				compilerType = CompilerEnum.GCC_VS;
//				// TODO: nothing feeds off of this state
//			}

			// Reaching this point implies that we did not find "DanS and we didn't
			// see the Borland DOS complaint

			FileHeader fileHeader = pe.getNTHeader().getFileHeader();
			if (fileHeader.getSectionHeader("CODE") != null) {
				// NOTE: Could be Borland-C 
				return CompilerEnum.BorlandPascal;
			}

			if (fileHeader.getSectionHeader(".bss") != null) {
				return CompilerEnum.GCC;
			}

			if (fileHeader.getSectionHeader(".idata") == null) {
				// assume VS if .idata not found
				return CompilerEnum.VisualStudio;
			}

			if (fileHeader.getSectionHeader(".tls") != null) {
				// assume Borland - prefer cpp since CODE segment didn't occur
				return CompilerEnum.BorlandCpp;
			}

			return CompilerEnum.Unknown;
		}

		private static boolean isGolang(PortableExecutable pe, ByteProvider provider) {
			boolean buildIdPresent = false;
			boolean buildInfoPresent = false;

			SectionHeader textSection = pe.getNTHeader().getFileHeader().getSectionHeader(".text");
			if (textSection != null) {
				try (InputStream is = textSection.getDataStream()) {
					GoBuildId buildId = GoBuildId.read(is);
					buildIdPresent = buildId != null;
				}
				catch (IOException e) {
					// fail
				}
			}

			SectionHeader dataSection = pe.getNTHeader().getFileHeader().getSectionHeader(".data");
			if (dataSection != null) {
				try (InputStream is = dataSection.getDataStream()) {
					buildInfoPresent = GoBuildInfo.isPresent(is);
				}
				catch (IOException e) {
					// fail
				}
			}
			return buildIdPresent || buildInfoPresent;
		}
	}
}
