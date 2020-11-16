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

import java.util.Arrays;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.bin.format.elf.ElfDynamicType.ElfDynamicValueType;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.framework.cmd.BinaryAnalysisCommand;
import ghidra.framework.options.Options;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

public class ElfBinaryAnalysisCommand extends FlatProgramAPI
		implements BinaryAnalysisCommand, AnalysisWorker {
	private MessageLog messages = new MessageLog();

	public ElfBinaryAnalysisCommand() {
		super();
	}

	@Override
	public boolean canApply(Program program) {
		try {
			Options options = program.getOptions("Program Information");
			String format = options.getString("Executable Format", null);
			if (!BinaryLoader.BINARY_NAME.equals(format)) {
				return false;
			}
			Memory memory = program.getMemory();
			byte[] magicBytes = new byte[ElfConstants.MAGIC_BYTES.length];
			memory.getBytes(program.getAddressFactory().getDefaultAddressSpace().getAddress(0),
				magicBytes);
			return Arrays.equals(magicBytes, ElfConstants.MAGIC_BYTES);
		}
		catch (Exception e) {
			return false;
		}
	}

	@Override
	public boolean analysisWorkerCallback(Program program, Object workerContext,
			TaskMonitor analysisMonitor) throws Exception, CancelledException {

		set(program, analysisMonitor);

		Listing listing = currentProgram.getListing();
		SymbolTable symbolTable = currentProgram.getSymbolTable();

		ByteProvider provider = new MemoryByteProvider(currentProgram.getMemory(),
			currentProgram.getAddressFactory().getDefaultAddressSpace());
		try {
			ElfHeader elf = ElfHeader.createElfHeader(RethrowContinuesFactory.INSTANCE, provider);
			elf.parse();

			processElfHeader(elf, listing);
			processProgramHeaders(elf, listing);
			processSectionHeaders(elf, listing);
			processInterpretor(elf, provider, program);
			processDynamic(elf, provider, program);
			processSymbolTables(elf, listing, symbolTable);
			processStrings(elf);
			processRelocationTables(elf, listing);

			return true;
		}
		catch (ElfException e) {
			messages.appendMsg("Not a binary ELF program: ELF header not found.");
			return false;
		}
	}

	@Override
	public String getWorkerName() {
		return getName();
	}

	@Override
	public boolean applyTo(Program program, TaskMonitor analysisMonitor) throws Exception {

		set(program, analysisMonitor);

		// Modify program and prevent events from triggering follow-on analysis
		AutoAnalysisManager aam = AutoAnalysisManager.getAnalysisManager(currentProgram);
		return aam.scheduleWorker(this, null, false, analysisMonitor);
	}

	@Override
	public String getName() {
		return "ELF Header Annotation";
	}

	@Override
	public MessageLog getMessages() {
		return messages;
	}

	private void processElfHeader(ElfHeader elf, Listing listing)
			throws DuplicateNameException, CodeUnitInsertionException, Exception {
		DataType elfDT = elf.toDataType();
		Address elfStart = addr(0);
		createData(elfStart, elfDT);
		createFragment(elfDT.getName(), elfStart, elfDT.getLength());
	}

	private void processStrings(ElfHeader elf) throws CancelledException {

		Memory memory = currentProgram.getMemory();

		ElfSectionHeader[] stringSections = elf.getSections(ElfSectionHeaderConstants.SHT_STRTAB);
		for (ElfSectionHeader stringSection : stringSections) {
			monitor.checkCanceled();
			try {
				Address addr = addr(stringSection.getOffset());
				Address maxAddr = addr.addNoWrap(stringSection.getSize() - 1);

				MemoryBlock block = memory.getBlock(addr);
				if (block == null) {
					messages.appendMsg(
						"Unable to markup string table at " + addr + " - block not found");
					continue;
				}
				if (maxAddr.compareTo(block.getEnd()) > 0) {
					messages.appendMsg(
						"Truncated string table markup at " + addr + " - block too short");
					maxAddr = block.getEnd();
				}

				addr = addr.addNoWrap(1);
				while (addr.compareTo(maxAddr) < 0) {
					Data d = createAsciiString(addr);
					addr = addr.addNoWrap(d.getLength());
				}
			}
			catch (AddressOverflowException | CodeUnitInsertionException e) {
				messages.appendMsg("Failed to markup string table: " + e.getMessage());
			}
			catch (Exception e) {
				messages.appendException(e);
			}
		}
	}

	private void processSectionHeaders(ElfHeader elf, Listing listing) throws Exception {
		ElfSectionHeader[] sections = elf.getSections();
		for (int i = 0; i < sections.length; i++) {
			monitor.checkCanceled();
			String name = sections[i].getNameAsString();

			DataType sectionDT = sections[i].toDataType();
			long offset = elf.e_shoff() + (i * elf.e_shentsize());
			Address sectionStart = addr(offset);

			createData(sectionStart, sectionDT);
			createFragment(sectionDT.getName(), sectionStart, sectionDT.getLength());

			CodeUnit cu = listing.getCodeUnitAt(addr(offset));
			cu.setComment(CodeUnit.PLATE_COMMENT,
				"#" + i + ") " + name + " at 0x" + Long.toHexString(sections[i].getAddress()));

			if (sections[i].getSize() == 0) {
				continue;
			}
			if (sections[i].getType() == ElfSectionHeaderConstants.SHT_NOBITS) {
				continue;
			}

			Address dataStart = addr(sections[i].getOffset());
			createFragment(name + "_DATA", dataStart, sections[i].getSize());

			try {
				createLabel(dataStart, name, true, SourceType.ANALYSIS);
			}
			catch (Exception e) {
				// ignore
			}

			cu = listing.getCodeUnitAt(dataStart);
			cu.setComment(CodeUnit.PRE_COMMENT, sections[i].getNameAsString() + " Size: 0x" +
				Long.toHexString(sections[i].getSize()));
		}
	}

	private void processProgramHeaders(ElfHeader elf, Listing listing) throws Exception {

		int headerCount = elf.e_phnum();
		int size = elf.e_phentsize() * headerCount;
		if (size == 0) {
			return;
		}

		Structure phStructDt = (Structure) elf.getProgramHeaders()[0].toDataType();
		phStructDt = (Structure) phStructDt.clone(listing.getDataTypeManager());
		Array arrayDt = new ArrayDataType(phStructDt, headerCount, size);

		Data array = createData(addr(elf.e_phoff()), arrayDt);

		createFragment(phStructDt.getName(), array.getMinAddress(), array.getLength());

		ElfProgramHeader[] programHeaders = elf.getProgramHeaders();
		for (int i = 0; i < programHeaders.length; i++) {
			monitor.checkCanceled();
			Data d = array.getComponent(i);
			d.setComment(CodeUnit.EOL_COMMENT, programHeaders[i].getComment());

			Address addr = addr(programHeaders[i].getOffset());

			createLabel(addr, programHeaders[i].getTypeAsString(), true, SourceType.ANALYSIS);
		}
	}

	private void processInterpretor(ElfHeader elf, ByteProvider provider, Program program)
			throws CancelledException {
		for (ElfProgramHeader programHeader : elf.getProgramHeaders(
			ElfProgramHeaderConstants.PT_INTERP)) {
			monitor.checkCanceled();
			long offset = programHeader.getOffset();
			if (offset == 0) {
				Msg.warn(this, " Dynamic table appears to have been stripped from binary");
				return;
			}
			try {
				createAsciiString(addr(offset));
			}
			catch (AddressOverflowException | CodeUnitInsertionException e) {
				messages.appendMsg("Failed to markup PT_INTERP string: " + e.getMessage());
			}
			catch (Exception e) {
				messages.appendException(e);
			}
		}
	}

	private void processDynamic(ElfHeader elf, ByteProvider provider, Program program)
			throws CancelledException {

		ElfDynamicTable dynamicTable = elf.getDynamicTable();
		if (dynamicTable == null) {
			return;
		}

		try {
			Address addr = addr(dynamicTable.getFileOffset());

			program.getSymbolTable().createLabel(addr, "_DYNAMIC", SourceType.ANALYSIS);

			ElfDynamic[] dynamics = dynamicTable.getDynamics();
			DataType structArray = dynamicTable.toDataType();
			Data dynamicTableData = createData(addr, structArray);

			BinaryReader reader = new BinaryReader(provider, !program.getMemory().isBigEndian());

			for (int i = 0; i < dynamics.length; i++) {
				monitor.checkCanceled();

				Data dynamicData = dynamicTableData.getComponent(i);
				if (dynamicData == null) {
					return;
				}

				int tagType = dynamics[i].getTag();

				ElfDynamicType dynamicType = elf.getDynamicType(tagType);
				String comment =
					dynamicType != null ? (dynamicType.name + " - " + dynamicType.description)
							: ("DT_0x" + StringUtilities.pad(Integer.toHexString(tagType), '0', 8));

				dynamicData.setComment(CodeUnit.EOL_COMMENT, comment);

				Data valueData = dynamicData.getComponent(1);

				if (dynamicType != null) {
					if (dynamicType.valueType == ElfDynamicValueType.ADDRESS) {
						addDynamicReference(elf, dynamics[i], valueData.getAddress(), program);
					}
					else if (dynamicType.valueType == ElfDynamicValueType.STRING) {
						addDynamicStringComment(elf, dynamics[i], valueData, reader, program);
					}
				}
				else {
					addDynamicReference(elf, dynamics[i], valueData.getAddress(), program);
				}
			}
		}
		catch (CancelledException e) {
			throw e;
		}
		catch (Exception e) {
			messages.appendMsg("Could not markup dynamic section: " + e);
		}
	}

	private void addDynamicStringComment(ElfHeader elf, ElfDynamic dynamic, Data data,
			BinaryReader reader, Program program) {
		ElfStringTable dynamicStringTable = elf.getDynamicStringTable();
		if (dynamicStringTable != null) {
			String str = dynamicStringTable.readString(reader, dynamic.getValue());
			if (str != null) {
				data.setComment(CodeUnit.EOL_COMMENT, str);
			}
		}
	}

	private void addDynamicReference(ElfHeader elf, ElfDynamic dynamic, Address fromAddr,
			Program program) {

		long dynamicRefAddr = dynamic.getValue();

		ElfProgramHeader programLoadHeader = elf.getProgramLoadHeaderContaining(dynamicRefAddr);
		if (programLoadHeader == null) {
			return; // unable to find loaded
		}

		Address refAddr = addr(programLoadHeader.getOffset(dynamicRefAddr));
		program.getReferenceManager().addMemoryReference(fromAddr, refAddr, RefType.DATA,
			SourceType.ANALYSIS, 0);

		try {
			createLabel(refAddr, "_" + dynamic.getTagAsString(), true, SourceType.ANALYSIS);
		}
		catch (Exception e1) {
			// ignore
		}

	}

	private void processSymbolTables(ElfHeader elf, Listing listing, SymbolTable symbolTable)
			throws CancelledException {
		monitor.setMessage("Processing symbol tables...");

		ElfSymbolTable[] symbolTables = elf.getSymbolTables();
		for (ElfSymbolTable symbolTable2 : symbolTables) {
			monitor.checkCanceled();

			Address symbolTableAddr = addr(symbolTable2.getFileOffset());

			try {
				DataType symbolTableDT = symbolTable2.toDataType();
				createData(symbolTableAddr, symbolTableDT);
			}
			catch (Exception e) {
				messages.appendMsg("Could not markup symbol table: " + e);
				return;
			}

			ElfSymbol[] symbols = symbolTable2.getSymbols();

			for (int j = 0; j < symbols.length; j++) {
				if (monitor.isCancelled()) {
					return;
				}

				String name = symbols[j].getNameAsString();
				long value = symbols[j].getValue() & Conv.INT_MASK;

				try {
					Address currAddr = symbolTableAddr.add(j * symbolTable2.getEntrySize());
					listing.setComment(currAddr, CodeUnit.EOL_COMMENT,
						name + " at 0x" + Long.toHexString(value));
				}
				catch (Exception e) {
					messages.appendMsg("Could not markup symbol table: " + e);
				}
			}
		}
	}

	private Address addr(long offset) {
		// FIXME! Will not work for space with wordsize != 1
		return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	private void processRelocationTables(ElfHeader elf, Listing listing) throws CancelledException {
		monitor.setMessage("Processing relocation tables...");
		ElfRelocationTable[] relocationTables = elf.getRelocationTables();
		for (ElfRelocationTable relocationTable : relocationTables) {
			monitor.checkCanceled();
			ElfSectionHeader relocationSection = relocationTable.getTableSectionHeader();
			String relocSectionName = "<section-not-found>";
			if (relocationSection != null) {
				relocSectionName = relocationSection.getNameAsString();
			}

			//		elf.getSection(relocationTable.getFileOffset()); // may be null
			Address relocationTableAddress = addr(relocationTable.getFileOffset());
			try {
				DataType dataType = relocationTable.toDataType();
				if (dataType != null) {
					createData(relocationTableAddress, dataType);
				}
				else {
					listing.setComment(relocationTableAddress, CodeUnit.PRE_COMMENT,
						"ELF Relocation Table (markup not yet supported)");
				}
			}
			catch (Exception e) {
				messages.appendMsg(
					"Could not markup relocation table for " + relocSectionName + " - " + e);
			}
		}
	}
}
