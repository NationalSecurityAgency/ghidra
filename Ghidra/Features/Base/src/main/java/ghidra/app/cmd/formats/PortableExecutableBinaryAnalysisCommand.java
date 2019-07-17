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

import java.io.IOException;
import java.util.List;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.mz.DOSHeader;
import ghidra.app.util.bin.format.pe.*;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.app.util.bin.format.pe.debug.DebugCOFFSymbol;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.cmd.BinaryAnalysisCommand;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class PortableExecutableBinaryAnalysisCommand extends FlatProgramAPI
		implements BinaryAnalysisCommand, AnalysisWorker {
	private MessageLog messages = new MessageLog();

	public PortableExecutableBinaryAnalysisCommand() {
		super();
	}

	@Override
	public boolean canApply(Program program) {
		try {
			Memory memory = program.getMemory();

			ByteProvider provider = new MemoryByteProvider(memory,
				program.getAddressFactory().getDefaultAddressSpace());

			FactoryBundledWithBinaryReader reader = new FactoryBundledWithBinaryReader(
				RethrowContinuesFactory.INSTANCE, provider, !program.getLanguage().isBigEndian());

			DOSHeader dosHeader = DOSHeader.createDOSHeader(reader);

			if (dosHeader.isDosSignature()) {

				reader.setPointerIndex( dosHeader.e_lfanew( ) );

				short peMagic = reader.readNextShort();//we should be pointing at the PE magic value!

				return ( peMagic & 0x0000ffff ) == Constants.IMAGE_NT_SIGNATURE;
			}
		}
		catch (Exception e) {
		}
		return false;
	}

	@Override
	public boolean analysisWorkerCallback(Program program, Object workerContext,
			TaskMonitor monitor) throws Exception, CancelledException {

		ByteProvider provider = new MemoryByteProvider(currentProgram.getMemory(),
			program.getAddressFactory().getDefaultAddressSpace());

		PortableExecutable pe =
			PortableExecutable.createPortableExecutable(RethrowContinuesFactory.INSTANCE, provider,
				SectionLayout.FILE);

		DOSHeader dos = pe.getDOSHeader();
		if (dos == null || dos.e_magic() != DOSHeader.IMAGE_DOS_SIGNATURE) {
			messages.appendMsg("Not a binary PE program: DOS header not found.");
			return false;
		}

		NTHeader nt = pe.getNTHeader();
		if (nt == null) {
			messages.appendMsg("Not a binary PE program: NT header not found.");
			return false;
		}

		createDataTypes(pe);

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
		return "PE Header Annotation";
	}

	@Override
	public MessageLog getMessages() {
		return messages;
	}

	private boolean createDataTypes(PortableExecutable pe) throws Exception {
		DOSHeader dos = pe.getDOSHeader();
		NTHeader nt = pe.getNTHeader();
		if (nt == null) {
			return false;
		}

		processDOSHeader(dos);
		processNTHeader(dos, nt);
		processSections(nt);
		processDataDirectories(nt);
		processSymbols(nt.getFileHeader());

		return true;
	}

	private void processSymbols(FileHeader fileHeader) throws Exception {
		if (fileHeader.getPointerToSymbolTable() == 0) {
			return;
		}
		Address address = toAddr(fileHeader.getPointerToSymbolTable());
		List<DebugCOFFSymbol> symbols = fileHeader.getSymbols();
		for (DebugCOFFSymbol symbol : symbols) {
			if (symbol == null) {
				continue;
			}
			String comment = "Name: " + symbol.getName() + '\n' + "Storage Class: " +
				symbol.getStorageClassAsString() + '\n' + "Type: " + symbol.getTypeAsString();
			setPlateComment(address, comment);
			DataType symbolDT = symbol.toDataType();
			Data data = createData(address, symbolDT);
			createFragment("COFF_Symbols", data.getMinAddress(), data.getLength());
			address = address.add(data.getLength());
		}
		processStringTable(address);
	}

	private void processStringTable(Address address) throws Exception {
		Data dwordData = createDWord(address);

		createFragment("StringTable", dwordData.getMinAddress(), dwordData.getLength());

		int usedBytes = dwordData.getLength();
		int totalBytes = getInt(address);

		Address stringAddress = address.add(4);

		while (usedBytes < totalBytes) {
			if (monitor.isCancelled()) {
				break;
			}

			Data stringData = createAsciiString(stringAddress);
			setEOLComment(stringAddress, "");
			createFragment("StringTable", stringData.getMinAddress(), stringData.getLength());

			usedBytes += stringData.getLength();

			stringAddress = stringAddress.add(stringData.getLength());
		}
	}

	private void processDOSHeader(DOSHeader dos) throws DuplicateNameException, Exception {
		DataType dosDT = dos.toDataType();
		Address dosStartAddr = toAddr(0);
		createData(dosStartAddr, dosDT);
		createFragment(dosDT.getName(), dosStartAddr, dosDT.getLength());
	}

	private void processNTHeader(DOSHeader dos, NTHeader nt)
			throws DuplicateNameException, IOException, Exception {
		DataType ntDT = nt.toDataType();
		Address ntStartAddr = toAddr(dos.e_lfanew());
		Address ntEndAddr = ntStartAddr.add(ntDT.getLength());
		clearListing(ntStartAddr, ntEndAddr);//sometimes overlaps DOS header to packing
		createData(ntStartAddr, ntDT);
		createFragment(ntDT.getName(), ntStartAddr, ntDT.getLength());
	}

	private void processDataDirectories(NTHeader nt) throws Exception {
		MessageLog log = new MessageLog();
		OptionalHeader oh = nt.getOptionalHeader();
		DataDirectory[] datadirs = oh.getDataDirectories();
		for (DataDirectory datadir : datadirs) {
			if (datadir == null || datadir.getSize() == 0) {
				continue;
			}

			if (datadir.hasParsedCorrectly()) {
				datadir.markup(currentProgram, true, monitor, log, nt);

				Address startAddr = PeUtils.getMarkupAddress(currentProgram, true, nt,
						datadir.getVirtualAddress());
				createFragment(datadir.getDirectoryName(), startAddr, datadir.getSize());
			}
		}
		messages.appendMsg(log.toString());
	}

	private void processSections(NTHeader nt)
			throws Exception, DuplicateNameException, InvalidInputException {
		FileHeader fh = nt.getFileHeader();
		SectionHeader[] sections = fh.getSectionHeaders();
		int index = fh.getPointerToSections();
		for (SectionHeader section : sections) {
			DataType sectionDT = section.toDataType();
			Address sectionStartAddr = toAddr(index);
			createData(sectionStartAddr, sectionDT);
			createFragment(sectionDT.getName(), sectionStartAddr, sectionDT.getLength());

			setPlateComment(sectionStartAddr, section.toString());

			index += SectionHeader.IMAGE_SIZEOF_SECTION_HEADER;

			if (section.getPointerToRawData() == 0 || section.getSizeOfRawData() == 0) {
				continue;
			}

			Address dataStartAddr = toAddr(section.getPointerToRawData());
			currentProgram.getSymbolTable().createLabel(dataStartAddr, section.getName(),
				SourceType.IMPORTED);
			createFragment(section.getName() + "_DATA", dataStartAddr,
				section.getSizeOfRawData());
		}
	}
}
