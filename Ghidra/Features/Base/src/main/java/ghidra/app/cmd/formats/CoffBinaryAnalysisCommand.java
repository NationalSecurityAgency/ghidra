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

import java.util.List;

import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.coff.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.framework.cmd.BinaryAnalysisCommand;
import ghidra.framework.options.Options;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NotEmptyException;
import ghidra.util.task.TaskMonitor;

public class CoffBinaryAnalysisCommand extends FlatProgramAPI
		implements BinaryAnalysisCommand, AnalysisWorker {

	private MessageLog messages = new MessageLog();

	public CoffBinaryAnalysisCommand() {
		super();
	}

	@Override
	public boolean canApply(Program program) {
		try {
			Options options = program.getOptions(Program.PROGRAM_INFO);
			String format = options.getString("Executable Format", null);
			if (!BinaryLoader.BINARY_NAME.equals(format)) {
				return false;
			}
			Memory memory = program.getMemory();
			short magic =
				memory.getShort(program.getAddressFactory().getDefaultAddressSpace().getAddress(0));
			return CoffMachineType.isMachineTypeDefined(magic);
		}
		catch (Exception e) {
			return false;
		}
	}

	@Override
	public boolean analysisWorkerCallback(Program program, Object workerContext,
			TaskMonitor monitor) throws Exception, CancelledException {

		ByteProvider provider = new MemoryByteProvider(currentProgram.getMemory(),
			currentProgram.getAddressFactory().getDefaultAddressSpace());

		CoffFileHeader header = new CoffFileHeader(provider);

		if (!CoffMachineType.isMachineTypeDefined(header.getMagic())) {
			return false;

		}
		header.parse(provider, monitor);

		applyDataTypes(header);
		removeEmptyFragments();

		return true;
	}

	@Override
	public String getWorkerName() {
		return getName();
	}

	@Override
	public boolean applyTo(Program program, TaskMonitor monitor) throws Exception {
		set(program, monitor);

		// Modify program and prevent events from triggering follow-on analysis
		AutoAnalysisManager aam = AutoAnalysisManager.getAnalysisManager(currentProgram);
		return aam.scheduleWorker(this, null, false, monitor);
	}

	@Override
	public String getName() {
		return "COFF Header Annotation";
	}

	@Override
	public MessageLog getMessages() {
		return messages;
	}

	private void removeEmptyFragments() throws NotEmptyException {
		monitor.setMessage("Removing empty fragments...");
		String[] treeNames = currentProgram.getListing().getTreeNames();
		for (String treeName : treeNames) {
			if (monitor.isCancelled()) {
				break;
			}
			ProgramModule rootModule = currentProgram.getListing().getRootModule(treeName);
			Group[] children = rootModule.getChildren();
			for (Group child : children) {
				if (monitor.isCancelled()) {
					break;
				}
				if (child instanceof ProgramFragment) {
					ProgramFragment fragment = (ProgramFragment) child;
					if (fragment.isEmpty()) {
						rootModule.removeChild(fragment.getName());
					}
				}
			}
		}
	}

	private void applyDataTypes(CoffFileHeader header) throws Exception {
		processFileHeader(header);
		processOptionalHeader(header);
		processSectionHeaders(header);
		processSymbols(header);
		processStrings(header);
	}

	private void processOptionalHeader(CoffFileHeader header) throws Exception {
		if (header.getOptionalHeaderSize() == 0) {
			return;
		}
		AoutHeader optionalHeader = header.getOptionalHeader();
		Address address = toAddr(header.sizeof());
		DataType dt = optionalHeader.toDataType();
		createData(address, dt);
		createFragment(dt.getName(), address, dt.getLength());
	}

	private void processStrings(CoffFileHeader header) throws Exception {
		monitor.setMessage("Processing strings...");
		Address start = toAddr(header.getSymbolTablePointer() +
			(header.getSymbolTableEntries() * CoffConstants.SYMBOL_SIZEOF));
		Address address = start;
		createData(address, new DWordDataType());
		createLabel(address, "Number_of_strings", true);
		address = address.add(4);
		while (address.compareTo(currentProgram.getMaxAddress()) < 0) {
			if (monitor.isCancelled()) {
				break;
			}
			Data data = createData(address, new StringDataType());
			address = address.add(data.getLength());
		}
		createFragment("Strings", start, address.subtract(start));
	}

	private void processSymbols(CoffFileHeader header) throws Exception {
		monitor.setMessage("Processing symbols...");
		Address start = toAddr(header.getSymbolTablePointer());
		long length = header.getSymbolTableEntries() * CoffConstants.SYMBOL_SIZEOF;
		Address address = start;
		List<CoffSymbol> symbols = header.getSymbols();
		for (int i = 0; i < symbols.size(); ++i) {
			if (monitor.isCancelled()) {
				break;
			}
			CoffSymbol symbol = symbols.get(i);

			DataType dt = symbol.toDataType();
			createData(address, dt);
			setPlateComment(address, symbol.getName());
			address = address.add(dt.getLength());

			List<CoffSymbolAux> auxiliarySymbols = symbol.getAuxiliarySymbols();
			for (CoffSymbolAux auxSymbol : auxiliarySymbols) {
				DataType auxDT = auxSymbol.toDataType();
				createData(address, auxDT);
				setPlateComment(address, "Auxiliary for " + symbol.getName());
				address = address.add(auxDT.getLength());
			}
		}
		createFragment("Symbols", start, length);
	}

	private void processSectionHeaders(CoffFileHeader header) throws Exception {
		monitor.setMessage("Processing sections...");
		List<CoffSectionHeader> sections = header.getSections();
		Address address = toAddr(header.sizeof() + header.getOptionalHeaderSize());
		for (CoffSectionHeader section : sections) {
			if (monitor.isCancelled()) {
				break;
			}

			DataType dt = section.toDataType();
			createData(address, dt);
			createFragment(dt.getName(), address, dt.getLength());
			setPlateComment(address, section.getName());
			address = address.add(dt.getLength());

			processSectionRelocations(section);
			processSectionLineNumbers(section);

			if (section.getSize(currentProgram.getLanguage()) == 0 ||
				section.isUninitializedData()) {//file does not contain any bytes...
				continue;
			}

			//create a fragment for the section's raw data
			Address byteAddress = toAddr(section.getPointerToRawData());
			long length = section.getSize(currentProgram.getLanguage());
			createFragment(section.getName() + "-Data", byteAddress, length);
		}
	}

	private void processSectionLineNumbers(CoffSectionHeader section) throws Exception {
		monitor.setMessage("Processing section line numbers...");
		if (section.getLineNumberCount() == 0) {
			return;
		}
		Address start = toAddr(section.getPointerToLineNumbers());
		long length = section.getLineNumberCount() * CoffLineNumber.SIZEOF;
		Address address = start;
		List<CoffLineNumber> lineNumbers = section.getLineNumbers();
		for (CoffLineNumber lineNumber : lineNumbers) {
			if (monitor.isCancelled()) {
				break;
			}
			DataType dt = lineNumber.toDataType();
			createData(address, dt);
			address = address.add(dt.getLength());
		}
		createFragment(section.getName() + "-LineNumbers", start, length);
	}

	private void processSectionRelocations(CoffSectionHeader section) throws Exception {
		monitor.setMessage("Processing section relocations...");
		if (section.getRelocationCount() == 0) {
			return;
		}
		int relocationSize = 0;
		Address start = toAddr(section.getPointerToRelocations());
		Address address = start;
		List<CoffRelocation> relocations = section.getRelocations();
		for (CoffRelocation relocation : relocations) {
			if (monitor.isCancelled()) {
				break;
			}
			relocationSize += relocation.sizeof();
			DataType dt = relocation.toDataType();
			createData(address, dt);
			address = address.add(dt.getLength());
		}
		createFragment(section.getName() + "-Relocations", start, relocationSize);
	}

	private void processFileHeader(CoffFileHeader header) throws Exception {
		DataType dt = header.toDataType();
		Address startAddr = toAddr(0);
		createData(startAddr, dt);
		createFragment(dt.getName(), startAddr, dt.getLength());
	}
}
