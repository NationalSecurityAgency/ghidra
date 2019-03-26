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
package ghidra.app.cmd.formats;

import ghidra.app.cmd.data.CreateStringCmd;
import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.pef.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.cmd.BinaryAnalysisCommand;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.List;

public class PefBinaryAnalysisCommand extends FlatProgramAPI implements BinaryAnalysisCommand,
		AnalysisWorker {
	private MessageLog messages = new MessageLog();

	public PefBinaryAnalysisCommand() {
		super();
	}

	@Override
	public boolean canApply(Program program) {
		try {
			ByteProvider provider =
				new MemoryByteProvider(program.getMemory(),
					program.getAddressFactory().getDefaultAddressSpace());
			new ContainerHeader(provider);
			return true;
		}
		catch (Exception e) {
			return false;
		}
	}

	@Override
	public boolean analysisWorkerCallback(Program program, Object workerContext, TaskMonitor monitor)
			throws Exception, CancelledException {
		ByteProvider provider =
			new MemoryByteProvider(currentProgram.getMemory(),
				program.getAddressFactory().getDefaultAddressSpace());
		try {
			ContainerHeader header = new ContainerHeader(provider);
			header.parse();

			Address address = addr(0);
			DataType headerDT = header.toDataType();
			createData(address, headerDT);
			createFragment(headerDT.getName(), address, headerDT.getLength());

			Address sectionStartAddress = address.add(headerDT.getLength());

			processSections(header, sectionStartAddress);
			processLoaders(header);

			return true;
		}
		catch (PefException e) {
			messages.appendMsg("Not a binary PEF program: ContainerHeader not found.");
			return false;
		}
	}

	@Override
	public String getWorkerName() {
		return getName();
	}

	@Override
	public boolean applyTo(Program program, TaskMonitor monitor) throws Exception {
		set(program, monitor);

		// Modify program and prevent events from triggering follow-on analysis
		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(currentProgram);
		return manager.scheduleWorker(this, null, false, monitor);
	}

	@Override
	public String getName() {
		return "PEF Header Annotation";
	}

	@Override
	public MessageLog getMessages() {
		return messages;
	}

	private Address processSections(ContainerHeader header, Address address) throws Exception {
		monitor.setMessage("Sections...");
		List<SectionHeader> sections = header.getSections();
		for (SectionHeader section : sections) {
			if (monitor.isCancelled()) {
				break;
			}
			setPlateComment(address, section.toString());
			DataType dt = section.toDataType();
			createData(address, dt);
			createFragment(dt.getName(), address, dt.getLength());
			address = address.add(dt.getLength());
			processSectionData(section);
		}
		return address;
	}

	private void processSectionData(SectionHeader section) throws Exception {
		//this section breaks down into fragments later
		if (section.getSectionKind() == SectionKind.Loader) {
			return;
		}

		int size = section.getContainerLength();
		if (size == 0) {
			return;
		}

		int alignment = section.getContainerOffset() % 4;
		if (alignment != 0) {
			Msg.info(this, "section alignment");
		}

		Address sectionAddr = toAddr(section.getContainerOffset() + alignment);
		createFragment("SectionData-" + section.getName(), sectionAddr, size);
	}

	private void processLoaders(ContainerHeader header) throws Exception {
		LoaderInfoHeader loader = header.getLoader();

		SectionHeader section = loader.getSection();
		Address address = toAddr(section.getContainerOffset());
		DataType loaderDT = loader.toDataType();
		createData(address, loaderDT);
		createFragment(loaderDT.getName(), address, loaderDT.getLength());

		processImportLibraries(loader);
		processImportedSymbols(loader);
		processLoaderRelocations(loader);
		processLoaderStringTable(loader);
		processLoaderExports(loader);
	}

	private void processLoaderExports(LoaderInfoHeader loader) throws Exception {
		monitor.setMessage("Processing loader exports...");

		Address address =
			toAddr(loader.getExportHashOffset() + loader.getSection().getContainerOffset());

		List<ExportedSymbolHashSlot> exportedHashSlots = loader.getExportedHashSlots();
		for (ExportedSymbolHashSlot slot : exportedHashSlots) {
			if (monitor.isCancelled()) {
				break;
			}
			DataType dt = slot.toDataType();
			createData(address, dt);
			createFragment(dt.getName(), address, dt.getLength());
			address = address.add(dt.getLength());
		}

		List<ExportedSymbolKey> exportedSymbolKeys = loader.getExportedSymbolKeys();
		for (ExportedSymbolKey key : exportedSymbolKeys) {
			if (monitor.isCancelled()) {
				break;
			}
			DataType dt = key.toDataType();
			createData(address, dt);
			createFragment(dt.getName(), address, dt.getLength());
			address = address.add(dt.getLength());
		}

		if ((address.getOffset() % 4) != 0) {
			Msg.info(this, "here");
		}
		address = address.add(address.getOffset() % 4);//align

		List<ExportedSymbol> exportedSymbols = loader.getExportedSymbols();
		for (ExportedSymbol symbol : exportedSymbols) {
			if (monitor.isCancelled()) {
				break;
			}
			setPlateComment(address, symbol.toString());
			DataType dt = symbol.toDataType();
			createData(address, dt);
			createFragment(dt.getName(), address, dt.getLength());
			address = address.add(dt.getLength());
		}
	}

	/**
	 * The loader string table contains strings that specify
	 * the names of imported and exported symbols and imported libraries.
	 * Strings for imported symbols and libraries must be null terminated,
	 * but strings for exported symbols do not have this requirement.
	 * The length is determined using the upper-16 of the hash value.
	 */
	private void processLoaderStringTable(LoaderInfoHeader loader) throws Exception {
		monitor.setMessage("Processing loader string table...");

		Address start =
			toAddr(loader.getLoaderStringsOffset() + loader.getSection().getContainerOffset());
		Address end =
			toAddr(loader.getExportHashOffset() + loader.getSection().getContainerOffset());

		createFragment("LoaderStringTable", start, end.subtract(start) + 1);

		List<ImportedLibrary> importedLibraries = loader.getImportedLibraries();
		for (ImportedLibrary library : importedLibraries) {
			Address current = start.add(library.getNameOffset());
			CreateStringCmd cmd = new CreateStringCmd(current, -1, false);
			cmd.applyTo(currentProgram);
		}

		List<ImportedSymbol> symbols = loader.getImportedSymbols();
		for (ImportedSymbol symbol : symbols) {
			Address current = start.add(symbol.getSymbolNameOffset());
			CreateStringCmd cmd = new CreateStringCmd(current, -1, false);
			cmd.applyTo(currentProgram);
		}

		List<ExportedSymbolKey> exportedKeys = loader.getExportedSymbolKeys();
		List<ExportedSymbol> exportedSymbols = loader.getExportedSymbols();
		for (int i = 0; i < exportedSymbols.size(); ++i) {
			Address current = start.add(exportedSymbols.get(i).getNameOffset());
			CreateStringCmd cmd =
				new CreateStringCmd(current, exportedKeys.get(i).getNameLength(), false);
			cmd.applyTo(currentProgram);
		}
	}

	private Address processLoaderRelocations(LoaderInfoHeader loader) throws Exception {
		long offset =
			loader.getSection().getContainerOffset() + LoaderInfoHeader.SIZEOF +
				(loader.getImportedLibraryCount() * ImportedLibrary.SIZEOF) +
				(loader.getTotalImportedSymbolCount() * ImportedSymbol.SIZEOF);
		Address address = toAddr(offset);

		monitor.setMessage("Processing loader relocation...");
		for (LoaderRelocationHeader loaderRelocation : loader.getRelocations()) {
			if (monitor.isCancelled()) {
				break;
			}
			DataType dt = loaderRelocation.toDataType();
			createData(address, dt);
			createFragment(dt.getName(), address, dt.getLength());
			address = address.add(dt.getLength());

			address = processRelocation(address, loaderRelocation);
		}
		return address;
	}

	private Address processRelocation(Address address, LoaderRelocationHeader loaderRelocation)
			throws Exception {
		monitor.setMessage("Processing relocations...");
		List<Relocation> relocations = loaderRelocation.getRelocations();
		for (Relocation relocation : relocations) {
			if (monitor.isCancelled()) {
				break;
			}
			DataType dt = relocation.toDataType();
			createData(address, dt);
			createFragment("Relocation", address, dt.getLength());
			address = address.add(dt.getLength());
		}
		return address;
	}

	private Address processImportedSymbols(LoaderInfoHeader loader) throws DuplicateNameException,
			IOException, Exception {
		long offset =
			loader.getSection().getContainerOffset() + LoaderInfoHeader.SIZEOF +
				(loader.getImportedLibraryCount() * ImportedLibrary.SIZEOF);
		Address address = toAddr(offset);

		monitor.setMessage("Processing symbol table entries...");
		List<ImportedSymbol> importedSymbols = loader.getImportedSymbols();
		for (int i = 0; i < importedSymbols.size(); ++i) {
			ImportedSymbol symbol = importedSymbols.get(i);
			if (monitor.isCancelled()) {
				break;
			}
			setPlateComment(address, "0x" + Integer.toHexString(i) + " " + symbol.toString());
			DataType dt = symbol.toDataType();
			createData(address, dt);
			createFragment(dt.getName(), address, dt.getLength());
			address = address.add(dt.getLength());
		}
		return address;
	}

	private Address processImportLibraries(LoaderInfoHeader loader) throws DuplicateNameException,
			IOException, Exception {
		long offset = loader.getSection().getContainerOffset() + LoaderInfoHeader.SIZEOF;

		Address address = toAddr(offset);

		monitor.setMessage("Processing imported libraries...");
		for (ImportedLibrary library : loader.getImportedLibraries()) {
			if (monitor.isCancelled()) {
				break;
			}
			setPlateComment(address, library.toString());
			DataType dt = library.toDataType();
			createData(address, dt);
			createFragment(dt.getName(), address, dt.getLength());
			address = address.add(dt.getLength());
		}
		return address;
	}

	private Address addr(long offset) {
		return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}
}
