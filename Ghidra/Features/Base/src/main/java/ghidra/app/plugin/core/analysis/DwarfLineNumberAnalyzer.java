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
package ghidra.app.plugin.core.analysis;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.services.*;
import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.dwarf.DwarfSectionNames;
import ghidra.app.util.bin.format.dwarf.line.*;
import ghidra.app.util.bin.format.macho.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.MachoLoader;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.IOException;
import java.util.List;

public class DwarfLineNumberAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "DWARF Line Number";
	private static final String DESCRIPTION = "Extracts DWARF debug line number information.";

	public DwarfLineNumberAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after().after().after());
		setPrototype();
		setSupportsOneTimeAnalysis();
	}

	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();

		DwarfSectionNames sectionNames = new DwarfSectionNames(program);
		try {
			ByteProvider provider = getByteProvider(program, sectionNames);
			if (provider == null) {
				return true;
			}

			BinaryReader reader = new BinaryReader(provider, !program.getLanguage().isBigEndian());

			while (!monitor.isCancelled() && reader.getPointerIndex() < provider.length()) {
				long startIndex = reader.getPointerIndex();

				StatementProgramPrologue prologue = new StatementProgramPrologue(reader);

				StateMachine machine = new StateMachine();
				machine.reset(prologue.isDefaultIsStatement());

				StatementProgramInstructions instructions =
					new StatementProgramInstructions(reader, machine, prologue);

				while (!monitor.isCancelled()) {
					instructions.execute();
					//machine.print();

					FileEntry entry = prologue.getFileNameByIndex(machine.file);
					String directory = prologue.getDirectoryByIndex(entry.getDirectoryIndex());

					Address address = space.getAddress(machine.address);
					CodeUnit cu = program.getListing().getCodeUnitContaining(address);
					if (cu != null) {
						cu.setProperty("Source Path",
							directory + File.separator + entry.getFileName());
						cu.setProperty("Source File", entry.getFileName());
						cu.setProperty("Source Line", machine.line);
					}

					if (reader.getPointerIndex() - startIndex >= prologue.getTotalLength() +
						StatementProgramPrologue.TOTAL_LENGTH_FIELD_LEN) {
						break;
					}
				}
			}
		}
		catch (Exception e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			return false;
		}
		return true;
	}

	private ByteProvider getByteProvider(Program program, DwarfSectionNames sectionNames)
			throws IOException {
		File exePath = new File(program.getExecutablePath());
		if (MachoLoader.MACH_O_NAME.equals(program.getExecutableFormat())) {
			File parent = exePath.getParentFile();
			File dSymFile =
				new File(parent, exePath.getName() + ".dSYM/Contents/Resources/DWARF/" +
					exePath.getName());
			if (!dSymFile.exists()) {
				return null;
			}
			RandomAccessByteProvider provider = new RandomAccessByteProvider(dSymFile);
			try {
				MachHeader header =
					MachHeader.createMachHeader(RethrowContinuesFactory.INSTANCE, provider);
				header.parse();
				List<Section> allSections = header.getAllSections();
				for (Section section : allSections) {
					if (section.getSectionName().equals(sectionNames.SECTION_NAME_LINE())) {
						return new InputStreamByteProvider(section.getDataStream(header),
							section.getSize());
					}
				}
				return null;
			}
			catch (MachException e) {
			}
			finally {
				provider.close();
			}
			return null;//no line number section existed!
		}
		else if (ElfLoader.ELF_NAME.equals(program.getExecutableFormat())) {
			// We now load the .debug section as an overlay block, no need for the
			// original file
			MemoryBlock block = null;
			block = program.getMemory().getBlock(sectionNames.SECTION_NAME_LINE());
			if (block != null) {
				return new MemoryByteProvider(program.getMemory(), block.getStart());
			}
			// TODO: this will not handle the case where the .debug section is
			// in a separate file.  Can the file in a separate location?
			return null;  // no line number section existed!
		}
		throw new IllegalArgumentException("Unrecognized program format: " +
			program.getExecutableFormat());
	}

	public boolean canAnalyze(Program program) {

		return isElfOrMacho(program);
	}

	private boolean hasDebugInfo(Program program) {
		DwarfSectionNames sectionNames = new DwarfSectionNames(program);

		MemoryBlock block = null;
		block = program.getMemory().getBlock(sectionNames.SECTION_NAME_LINE());

		return block != null;
	}

	private boolean isElfOrMacho(Program program) {
		String format = program.getExecutableFormat();
		if (ElfLoader.ELF_NAME.equals(format)) {
			return hasDebugInfo(program);
		}
		if (MachoLoader.MACH_O_NAME.equals(format)) {
			return true;
		}
		return false;
	}
}
