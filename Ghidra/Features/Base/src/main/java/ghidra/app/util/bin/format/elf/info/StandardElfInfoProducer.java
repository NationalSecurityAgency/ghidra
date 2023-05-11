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
package ghidra.app.util.bin.format.elf.info;

import java.util.Map;
import java.util.Map.Entry;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.bin.format.elf.info.ElfInfoItem.ReaderFunc;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.classfinder.ExtensionPointProperties;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Handles marking up and program info for basic ELF note (and note-like) sections.
 * <ul>
 * 	<li>NoteAbiTag
 * 	<li>NoteGnuBuildId
 * 	<li>NoteGnuProperty
 * 	<li>GnuDebugLink (not a note)
 *  <li>ElfComment (not a note)
 * </ul>
 * <p>
 * Runs after other ElfInfoProducers that have a normal priority.
 */
@ExtensionPointProperties(priority = -1000)
public class StandardElfInfoProducer implements ElfInfoProducer {

	public static final CategoryPath ELF_CATEGORYPATH = new CategoryPath("/ELF");

	private static final Map<String, ReaderFunc<ElfInfoItem>> STANDARD_READERS = Map.of(
		GnuDebugLink.SECTION_NAME, GnuDebugLink::read,
		NoteAbiTag.SECTION_NAME, (br, prg) -> NoteAbiTag.read(ElfNote.read(br), prg),
		NoteGnuBuildId.SECTION_NAME, (br, prg) -> NoteGnuBuildId.read(ElfNote.read(br), prg),
		NoteGnuProperty.SECTION_NAME, (br, prg) -> NoteGnuProperty.read(ElfNote.read(br), prg),
		ElfComment.SECTION_NAME, ElfComment::read);

	private ElfLoadHelper elfLoadHelper;

	@Override
	public void init(ElfLoadHelper elfLoadHelper) {
		this.elfLoadHelper = elfLoadHelper;
	}

	@Override
	public void markupElfInfo(TaskMonitor monitor) throws CancelledException {
		Program program = elfLoadHelper.getProgram();

		for (Entry<String, ReaderFunc<ElfInfoItem>> noteEntry : STANDARD_READERS.entrySet()) {
			monitor.checkCancelled();

			String sectionName = noteEntry.getKey();
			ReaderFunc<ElfInfoItem> readFunc = noteEntry.getValue();

			ElfInfoItem.markupElfInfoItemSection(program, sectionName, readFunc);
		}
		markupPTNOTESections(monitor);
	}

	private void markupPTNOTESections(TaskMonitor monitor) throws CancelledException {
		Program program = elfLoadHelper.getProgram();
		Memory memory = program.getMemory();
		for (ElfProgramHeader elfProgramHeader : elfLoadHelper.getElfHeader()
				.getProgramHeaders(ElfProgramHeaderConstants.PT_NOTE)) {
			monitor.checkCancelled();

			Address addr = elfLoadHelper.findLoadAddress(elfProgramHeader, 0);
			MemoryBlock memBlock = memory.getBlock(addr);
			if (memBlock == null) {
				continue;
			}
			try (ByteProvider bp =
				MemoryByteProvider.createMemoryBlockByteProvider(program.getMemory(), memBlock)) {
				BinaryReader br = new BinaryReader(bp, !program.getMemory().isBigEndian());
				while (br.hasNext()) {
					monitor.checkCancelled();

					long start = br.getPointerIndex();
					ElfNote note = br.readNext(ElfNote::read);
					br.align(4);	// fix any notes with non-aligned size payloads
					long noteLength = br.getPointerIndex() - start;

					try {
						StructureDataType struct = note.toStructure(program.getDataTypeManager());
						DataUtilities.createData(program, addr, struct, -1, false,
							ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
						String comment =
							"ELF Note \"%s\", %xh".formatted(note.getName(), note.getVendorType());
						program.getListing().setComment(addr, CodeUnit.EOL_COMMENT, comment);
					}
					catch (CodeUnitInsertionException e) {
						// ignore, continue to next note
					}

					addr = addr.addWrap(noteLength);
				}
			}
			catch (IOException e) {
				Msg.warn(this, "Failed to read ELF Note at %s".formatted(addr), e);
			}

		}
	}

}
