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

import static ghidra.app.util.bin.StructConverter.DWORD;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;

/**
 * An ELF note that specifies the minimum kernel ABI required by this binary
 */
public class NoteAbiTag extends ElfNote {
	private static final int MIN_ABI_TAB_LEN = 0x10;
	public static final String SECTION_NAME = ".note.ABI-tag";

	/**
	 * Deserializes a NoteAbiTag from an already read generic Note.
	 * 
	 * @param note generic Note
	 * @param program context
	 * @return new NoteAbiTag instance, never null
	 * @throws IOException if data error
	 */
	public static NoteAbiTag read(ElfNote note, Program program) throws IOException {
		byte[] desc = note.getDescription();
		if (!note.isGnu() || desc.length < MIN_ABI_TAB_LEN) {
			throw new IOException(
				"Invalid .note.ABI-tag values: %s, %d".formatted(note.getName(), desc.length));
		}

		BinaryReader descReader = note.getDescriptionReader(!program.getMemory().isBigEndian());
		int abiType = descReader.readNextInt();
		int[] requiredKernelVersion = descReader.readNextIntArray(3);

		return new NoteAbiTag(note.getNameLen(), note.getName(), note.getVendorType(), abiType,
			requiredKernelVersion);
	}

	/**
	 * Reads a NoteAbiTag from the standard ".note.ABI-tag" section in the specified Program.
	 * 
	 * @param program Program to read from
	 * @return new instance, or null if not found or data error
	 */
	public static NoteAbiTag fromProgram(Program program) {
		return ElfNote.readFromProgramHelper(program, SECTION_NAME, NoteAbiTag::read);
	}

	private final int abiType;	// 0 == linux
	private final int[] requiredKernelVersion;	// int[3] { A, B, C } == kernel ver A.B.C  

	public NoteAbiTag(int nameLen, String name, int vendorType, int abiType,
			int[] requiredKernelVersion) {
		super(nameLen, name, vendorType);

		this.abiType = abiType;
		this.requiredKernelVersion = requiredKernelVersion;
	}

	public int getAbiType() {
		return abiType;
	}

	public String getAbiTypeString() {
		return switch (abiType) {
			case 0 -> "Linux";
			default -> "Unknown(%d)".formatted(abiType);
		};
	}

	public String getRequiredKernelVersion() {
		return "%s %d.%d.%d".formatted(getAbiTypeString(), requiredKernelVersion[0],
			requiredKernelVersion[1], requiredKernelVersion[2]);
	}

	@Override
	public String getNoteValueString() {
		return getRequiredKernelVersion();
	}

	@Override
	public String getNoteTypeName() {
		return "required kernel ABI";
	}

	@Override
	public StructureDataType toStructure(DataTypeManager dtm) {
		StructureDataType result =
			createNoteStructure(null, "NoteAbiTag", false, getNameLen(), 0, dtm);
		result.add(DWORD, "abiType", "0 == Linux");
		result.add(new ArrayDataType(DWORD, 3, -1, dtm), "requiredKernelVersion",
			"Major.minor.patch");
		return result;
	}


}
