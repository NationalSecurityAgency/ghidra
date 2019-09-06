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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.*;

import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.cmd.label.AddUniqueLabelCmd;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.pef.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class PefLoader extends AbstractLibrarySupportLoader {

	public final static String PEF_NAME = "Preferred Executable Format (PEF)";
	private static final long MIN_BYTE_LENGTH = 40;

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (provider.length() < MIN_BYTE_LENGTH) {
			return loadSpecs;
		}

		try {
			ContainerHeader header = new ContainerHeader(provider);
			List<QueryResult> results =
				QueryOpinionService.query(getName(), header.getArchitecture(), null);
			for (QueryResult result : results) {
				loadSpecs.add(new LoadSpec(this, header.getImageBase(), result));
			}
			if (loadSpecs.isEmpty()) {
				loadSpecs.add(new LoadSpec(this, header.getImageBase(), true));
			}
		}
		catch (PefException e) {
			// not a problem, it's not a pef
		}

		return loadSpecs;
	}

	@Override
	public void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws IOException, CancelledException {

		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);

		ImportStateCache importState = null;
		try {
			ContainerHeader header = new ContainerHeader(provider);
			monitor.setMessage("Completing PEF header parsing...");
			monitor.setCancelEnabled(false);
			header.parse();
			monitor.setCancelEnabled(true);

			importState = new ImportStateCache(program, header);

			program.setExecutableFormat(getName());

			processSections(header, program, fileBytes, importState, log, monitor);
			processExports(header, program, importState, log, monitor);
			processImports(header, program, importState, log, monitor);
			processRelocations(header, program, importState, log, monitor);
			processTocSymbol(header, program, importState, log, monitor);
			processMainSymbol(header, program, importState, log, monitor);
			processInitSymbol(header, program, importState, log, monitor);
			processTermSymbol(header, program, importState, log, monitor);
		}
		catch (PefException e) {
			throw new IOException(e);
		}
		catch (AddressOverflowException e) {
			throw new IOException(e);
		}
		finally {
			if (importState != null) {
				importState.dispose();
			}
		}
	}

	/**
	 * TODO determine how to correctly identify TOC location
	 */
	private void processTocSymbol(ContainerHeader header, Program program,
			ImportStateCache importState, MessageLog log, TaskMonitor monitor) {
		SymbolTable symbolTable = program.getSymbolTable();
		List<SectionHeader> sections = header.getSections();
		if (sections.size() < 2) {
			return;
		}
		SectionHeader dataSection = sections.get(1);
		if (!dataSection.isWrite()) {//is not a data section...
			return;
		}
		Address tocAddress = importState.getTocAddress();
		if (tocAddress == null) {
			MemoryBlock dataBlock = importState.getMemoryBlockForSection(dataSection);
			tocAddress = dataBlock.getStart();
		}
		try {
			symbolTable.createLabel(tocAddress, PefConstants.TOC, SourceType.IMPORTED);
			CreateDataCmd cmd = new CreateDataCmd(tocAddress, new PointerDataType());
			cmd.applyTo(program);
		}
		catch (Exception e) {
			log.appendException(e);
		}
	}

	private void processMainSymbol(ContainerHeader header, Program program,
			ImportStateCache importState, MessageLog log, TaskMonitor monitor) {
		SymbolTable symbolTable = program.getSymbolTable();

		LoaderInfoHeader loader = header.getLoader();

		int mainSectionIndex = loader.getMainSection();
		if (mainSectionIndex != -1) {
			SectionHeader mainSection = header.getSections().get(mainSectionIndex);
			MemoryBlock mainBlock = importState.getMemoryBlockForSection(mainSection);
			Address mainAddress = mainBlock.getStart().add(loader.getMainOffset());
			try {
				symbolTable.createLabel(mainAddress, PefConstants.MAIN, SourceType.IMPORTED);
			}
			catch (Exception e) {
				log.appendException(e);
			}

			if (mainSection.getSectionKind() == SectionKind.PackedData ||
				mainSection.getSectionKind() == SectionKind.UnpackedData ||
				mainSection.getSectionKind() == SectionKind.ExecutableData) {

				CreateDataCmd cmd = new CreateDataCmd(mainAddress, new PointerDataType());
				cmd.applyTo(program);

				Data data = program.getListing().getDefinedDataAt(mainAddress);
				if (data == null) {
					log.appendMsg("Unable to create data at main data structure.");
				}
				else {
					Address address = (Address) data.getValue();
					if (program.getMemory().contains(address)) {
						try {
							symbolTable.createLabel(address, "entry", SourceType.IMPORTED);
							symbolTable.createLabel(address, "main", SourceType.IMPORTED);
						}
						catch (Exception e) {
							log.appendException(e);
						}
						program.getSymbolTable().addExternalEntryPoint(address);
					}
				}
			}
		}
	}

	private void processInitSymbol(ContainerHeader header, Program program,
			ImportStateCache importState, MessageLog log, TaskMonitor monitor) {
		SymbolTable symbolTable = program.getSymbolTable();

		LoaderInfoHeader loader = header.getLoader();

		int initSectionIndex = loader.getInitSection();
		if (initSectionIndex != -1) {
			SectionHeader initSection = header.getSections().get(initSectionIndex);
			MemoryBlock initBlock = importState.getMemoryBlockForSection(initSection);
			Address address = initBlock.getStart().add(loader.getInitOffset());
			try {
				symbolTable.createLabel(address, PefConstants.INIT, SourceType.IMPORTED);
				CreateDataCmd cmd = new CreateDataCmd(address, new PointerDataType());
				cmd.applyTo(program);
			}
			catch (Exception e) {
				log.appendException(e);
			}
		}
	}

	private void processTermSymbol(ContainerHeader header, Program program,
			ImportStateCache importState, MessageLog log, TaskMonitor monitor) {
		SymbolTable symbolTable = program.getSymbolTable();

		LoaderInfoHeader loader = header.getLoader();

		int termSectionIndex = loader.getTermSection();
		if (termSectionIndex != -1) {
			SectionHeader termSection = header.getSections().get(termSectionIndex);
			MemoryBlock termBlock = importState.getMemoryBlockForSection(termSection);
			Address address = termBlock.getStart().add(loader.getTermOffset());
			try {
				symbolTable.createLabel(address, PefConstants.TERM, SourceType.IMPORTED);
				CreateDataCmd cmd = new CreateDataCmd(address, new PointerDataType());
				cmd.applyTo(program);
			}
			catch (Exception e) {
				log.appendException(e);
			}
		}
	}

	private void processImports(ContainerHeader header, Program program,
			ImportStateCache importState, MessageLog log, TaskMonitor monitor) {

		LoaderInfoHeader loader = header.getLoader();
		List<ImportedLibrary> libraries = loader.getImportedLibraries();
		List<ImportedSymbol> symbols = loader.getImportedSymbols();
		int symbolIndex = 0;

		MemoryBlock importBlock = makeFakeImportBlock(program, symbols, log, monitor);
		if (importBlock == null) {
			return;
		}

		Address start = importBlock.getStart();

		for (ImportedLibrary library : libraries) {
			if (monitor.isCancelled()) {
				return;
			}

			String libraryName = SymbolUtilities.replaceInvalidChars(library.getName(), true);

			int symbolCount = library.getImportedSymbolCount();
			int symbolStart = library.getFirstImportedSymbol();

			int totalSymbolCount = symbolStart + symbolCount;

			for (int i = symbolStart; i < totalSymbolCount; ++i) {
				if (monitor.isCancelled()) {
					return;
				}

				if (symbolIndex % 100 == 0) {
					monitor.setMessage(
						"Processing import " + symbolIndex + " of " + symbols.size());
				}
				++symbolIndex;

				String symbolName =
					SymbolUtilities.replaceInvalidChars(symbols.get(i).getName(), true);

				boolean success = importState.createLibrarySymbol(library, symbolName, start);
				if (!success) {
					log.appendMsg("Unable to create symbol.");
				}

				createPointer(program, start, log);
				program.getReferenceManager().removeAllReferencesFrom(start);
				addExternalReference(program, start, libraryName, symbolName, log);

				start = start.add(4);
			}
		}
	}

	private void createPointer(Program program, Address start, MessageLog log) {
		try {
			program.getListing().createData(start, new PointerDataType(), 4);
		}
		catch (Exception e) {
			log.appendMsg(e.getMessage());
		}
	}

	private void addExternalReference(Program program, Address start, String libraryName,
			String symbolName, MessageLog log) {
		try {
			program.getReferenceManager().addExternalReference(start, libraryName, symbolName, null,
				SourceType.IMPORTED, 0, RefType.DATA);
		}
		catch (Exception e) {
			log.appendMsg(e.getMessage());
		}
	}

	private MemoryBlock makeFakeImportBlock(Program program, List<ImportedSymbol> symbols,
			MessageLog log, TaskMonitor monitor) {
		int size = symbols.size() * 4;
		if (size == 0) {
			return null;
		}
		Address start = getImportSectionAddress(program);
		try {
			return program.getMemory().createInitializedBlock("IMPORTS", start, size, (byte) 0x00,
				monitor, false);
		}
		catch (Exception e) {
			log.appendException(e);
		}
		return null;
	}

	private void processRelocations(ContainerHeader header, Program program,
			ImportStateCache importState, MessageLog log, TaskMonitor monitor) {
		List<LoaderRelocationHeader> relocationHeaders = header.getLoader().getRelocations();
		for (LoaderRelocationHeader relocationHeader : relocationHeaders) {
			if (monitor.isCancelled()) {
				return;
			}
			RelocationState state =
				new RelocationState(header, relocationHeader, program, importState);
			List<Relocation> relocations = relocationHeader.getRelocations();
			int relocationIndex = 0;
			for (Relocation relocation : relocations) {
				if (monitor.isCancelled()) {
					return;
				}
				if (relocationIndex % 100 == 0) {
					monitor.setMessage(
						"Processing relocation " + relocationIndex + " of " + relocations.size());
				}
				++relocationIndex;

				relocation.apply(importState, state, header, program, log, monitor);
			}
			state.dispose();
		}
	}

	private void processExports(ContainerHeader header, Program program,
			ImportStateCache importState, MessageLog log, TaskMonitor monitor) {
		monitor.setMessage("Processing exports...");
		List<SectionHeader> sections = header.getSections();
		LoaderInfoHeader loader = header.getLoader();
		List<ExportedSymbol> exportedSymbols = loader.getExportedSymbols();
		for (ExportedSymbol symbol : exportedSymbols) {
			if (monitor.isCancelled()) {
				return;
			}
			if (symbol.getSectionIndex() == ExportedSymbol.kPEFAbsoluteExport) {//TODO
			}
			else if (symbol.getSectionIndex() == ExportedSymbol.kPEFReexportedImport) {//TODO
			}
			else {
				SectionHeader section = sections.get(symbol.getSectionIndex());
				MemoryBlock block = importState.getMemoryBlockForSection(section);
				Address symbolAddr = block.getStart().add(symbol.getSymbolValue());
				AddUniqueLabelCmd cmd =
					new AddUniqueLabelCmd(symbolAddr, symbol.getName(), null, SourceType.IMPORTED);
				if (!cmd.applyTo(program)) {
					log.appendMsg(cmd.getStatusMsg());
				}
			}
		}
	}

	private void processSections(ContainerHeader header, Program program, FileBytes fileBytes,
			ImportStateCache importState, MessageLog log, TaskMonitor monitor)
			throws AddressOverflowException, IOException {

		List<SectionHeader> sections = header.getSections();
		for (SectionHeader section : sections) {
			if (monitor.isCancelled()) {
				return;
			}

			Address start = getSectionAddressAligned(section, program);

			monitor.setMessage("Creating section at 0x" + start + "...");

			if (!section.getSectionKind().isInstantiated()) {
				continue;
			}

			if (section.getSectionKind() == SectionKind.PackedData) {
				byte[] unpackedData = section.getUnpackedData(monitor);
				ByteArrayInputStream is = new ByteArrayInputStream(unpackedData);
				MemoryBlockUtils.createInitializedBlock(program, false, section.getName(), start,
					is, unpackedData.length, section.getSectionKind().toString(), null,
					section.isRead(), section.isWrite(), section.isExecute(), log, monitor);
			}
			else {
				MemoryBlockUtils.createInitializedBlock(program, false, section.getName(), start,
					fileBytes, section.getContainerOffset(), section.getUnpackedLength(),
					section.getSectionKind().toString(), null, section.isRead(), section.isWrite(),
					section.isExecute(), log);
			}

			importState.setMemoryBlockForSection(section, program.getMemory().getBlock(start));

			if (section.getUnpackedLength() < section.getTotalLength()) {
				start = start.add(section.getUnpackedLength());

				MemoryBlockUtils.createUninitializedBlock(program, false, section.getName(), start,
					section.getTotalLength() - section.getUnpackedLength(),
					section.getSectionKind().toString(), null, section.isRead(), section.isWrite(),
					section.isExecute(), log);
			}
		}
	}

	private Address getSectionAddressAligned(SectionHeader section, Program program) {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		if (section.getDefaultAddress() != 0) {
			return space.getAddress(section.getDefaultAddress() & 0xffffffffL);
		}
		MemoryBlock[] blocks = program.getMemory().getBlocks();
		if (blocks.length == 0) {
			return space.getAddress(PefConstants.BASE_ADDRESS);
		}
		int last = blocks.length - 1;
		long address = blocks[last].getEnd().getOffset();
		long alignment = (long) Math.pow(2, section.getAlignment());
		long remainder = address % alignment;
		return space.getAddress(address + (alignment - remainder));
	}

	/**
	 * Determines an address to place the
	 * ficticous IMPORT memory block.
	 * The block will appear on a 16 byte alignment following
	 * the last block.
	 */
	private Address getImportSectionAddress(Program program) {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Address start = program.getMaxAddress();
		/*
		 * indicates the program does not have any memory blocks.
		 * it sounds crazy but it does happen. see CarbonLibStub.
		 */
		if (start == null) {
			return space.getAddress(0);
		}
		long offset = start.getOffset();
		long alignment = offset % 0x10;
		if (alignment != 0) {
			alignment = 0x10 - alignment;
		}
		return space.getAddress(offset + alignment);
	}

	@Override
	public String getName() {
		return PEF_NAME;
	}
}
