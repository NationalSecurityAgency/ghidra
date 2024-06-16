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

import static ghidra.app.util.bin.StructConverter.BYTE;

import java.io.IOException;

import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;

/**
 * An ELF note that specifies the build-id (sha1/md5/etc hash or manually specified bytes that 
 * can be hex-ified) of the containing program.
 * <p>
 * The hex values of the build-id are useful to find an external debug file.
 */
public class NoteGnuBuildId extends ElfNote {
	public static final String SECTION_NAME = ".note.gnu.build-id";

	/**
	 * Deserializes a NoteGnuBuildId from an already read generic Note.
	 * 
	 * @param note generic Note
	 * @param program context
	 * @return new NoteGnuBuildId instance, never null
	 * @throws IOException if data error
	 */
	public static NoteGnuBuildId read(ElfNote note, Program program) throws IOException {
		if (!note.isGnu() || note.getDescription().length == 0) {
			throw new IOException("Invalid .note.gnu.build-id values: %s, %d"
					.formatted(note.getName(), note.getDescription().length));
		}
		return new NoteGnuBuildId(note.getNameLen(), note.getName(), note.getVendorType(),
			note.getDescription());
	}

	/**
	 * Reads a NoteGnuBuildId from the standard ".note.gnu.build-id" section in the 
	 * specified Program.
	 * 
	 * @param program Program to read from
	 * @return new instance, or null if not found or data error
	 */
	public static NoteGnuBuildId fromProgram(Program program) {
		return ElfNote.readFromProgramHelper(program, SECTION_NAME, NoteGnuBuildId::read);
	}

	protected NoteGnuBuildId(int nameLen, String name, int vendorType, byte[] description) {
		super(nameLen, name, vendorType, description);
	}

	@Override
	public String getNoteTypeName() {
		return "GNU BuildId";
	}

	@Override
	public StructureDataType toStructure(DataTypeManager dtm) {
		StructureDataType result =
			createNoteStructure(null, "GnuBuildId", false, getNameLen(), 0, dtm);
		result.add(new ArrayDataType(BYTE, getDescriptionLen(), -1, dtm), "hash", null);

		return result;
	}

}
