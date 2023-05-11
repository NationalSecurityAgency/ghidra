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
package ghidra.app.util.bin.format.golang;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.elf.info.ElfInfoItem;
import ghidra.app.util.bin.format.elf.info.ElfNote;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;

/**
 * An ELF note that specifies the golang build-id.
 */
public class NoteGoBuildId extends ElfNote {
	public static final String SECTION_NAME = ".note.go.buildid";

	/**
	 * Reads a NoteGoBuildId from the specified BinaryReader, matching the signature of 
	 * {@link ElfInfoItem.ReaderFunc}.
	 * 
	 * @param br BinaryReader
	 * @param unusedProgram context (unused but needed to match signature)
	 * @return new NoteGoBuildId instance, never null
	 * @throws IOException if data error
	 */
	public static NoteGoBuildId read(BinaryReader br, Program unusedProgram) throws IOException {
		ElfNote note = ElfNote.read(br);
		if (!"Go".equals(note.getName())) {
			throw new IOException("Invalid note name: %s".formatted(note.getName()));
		}
		return new NoteGoBuildId(note.getNameLen(), note.getName(), note.getVendorType(),
			note.getDescription());
	}

	public NoteGoBuildId(int nameLen, String name, int vendorType, byte[] description) {
		super(nameLen, name, vendorType, description);
	}

	/**
	 * Returns the go buildid value
	 * 
	 * @return go buildid value
	 */
	public String getBuildId() {
		return new String(getDescription(), StandardCharsets.UTF_8);
	}

	@Override
	public String getNoteTypeName() {
		return SECTION_NAME;
	}

	@Override
	public String getProgramInfoKey() {
		return "Golang BuildId";
	}

	@Override
	public String getNoteValueString() {
		return getBuildId();
	}

	@Override
	public StructureDataType toStructure(DataTypeManager dtm) {
		StructureDataType struct =
			ElfNote.createNoteStructure(GoConstants.GOLANG_CATEGORYPATH,
				"NoteGoBuildId_%d".formatted(description.length), false, nameLen, 0, dtm);
		struct.add(StringUTF8DataType.dataType, description.length, "BuildId", null);
		return struct;
	}

}
