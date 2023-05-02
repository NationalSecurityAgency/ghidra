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
import static ghidra.app.util.bin.StructConverter.DWORD;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;

/**
 * ELF note sections have a well-defined format that combines identity information along with a 
 * binary blob that is specific to each type of note.
 * <p>
 * Notes are identified by the combination of a name string and vendorType number, and are usually
 * stored in a ELF section with a specific name.
 */
public class ElfNote implements ElfInfoItem {
	private static final int MAX_SANE_NAME_LEN = 1024;
	private static final int MAX_SANE_DESC_LEN = 1024 * 1024;

	@FunctionalInterface
	public interface NoteReaderFunc<T extends ElfNote> {
		/**
		 * Returns a more specific Note type, typically using the data found in the generic note's
		 * {@link ElfNote#getDescription()} and the supplied Program.
		 * 
		 * @param note generic note instance
		 * @param program Program containing the note
		 * @return new note instance
		 * @throws IOException if error reading
		 */
		T read(ElfNote note, Program program) throws IOException;
	}

	/**
	 * Reads a generic {@link ElfNote} instance from the supplied BinaryReader.
	 * 
	 * @param reader BinaryReader to read from
	 * @return new {@link ElfNote} instance, never null
	 * @throws IOException if bad data or error reading
	 */
	public static ElfNote read(BinaryReader reader) throws IOException {
		int nameLen = reader.readNextUnsignedIntExact();
		int descLen = reader.readNextUnsignedIntExact();
		int vendorType = reader.readNextInt();
		if (nameLen > MAX_SANE_NAME_LEN || descLen > MAX_SANE_DESC_LEN) {
			throw new IOException("Invalid Note lengths: %d, %d".formatted(nameLen, descLen));
		}
		String name = reader.readNextAsciiString(nameLen);
		nameLen += reader.align(4);

		byte[] desc = reader.readNextByteArray(descLen);

		return new ElfNote(nameLen, name, vendorType, desc);
	}

	/**
	 * A helper method for {@code read()} methods defined in specific Note classes to attempt to
	 * read a specific Note type from a Program.
	 * 
	 * @param <T> Note type
	 * @param program {@link Program}
	 * @param sectionName name of the note section
	 * @param readerFunc {@link NoteReaderFunc} that converts a generic note instance into a
	 * specialized note.
	 * @return new Note instance, or null if not present or error reading
	 */
	protected static <T extends ElfNote> T readFromProgramHelper(Program program,
			String sectionName, NoteReaderFunc<T> readerFunc) {

		ItemWithAddress<ElfNote> wrappedNote = ElfInfoItem.readItemFromSection(program, sectionName,
			(br, _unused) -> ElfNote.read(br));
		if (wrappedNote != null) {
			try {
				return readerFunc.read(wrappedNote.item(), program);
			}
			catch (IOException e) {
				// fall thru
			}
		}
		return null;
	}

	protected final int nameLen;
	protected final String name;
	protected final int vendorType;
	protected final byte[] description;

	protected ElfNote(int nameLen, String name, int vendorType, byte[] description) {
		this.nameLen = nameLen;
		this.name = name;
		this.vendorType = vendorType;
		this.description = description;
	}

	protected ElfNote(int nameLen, String name, int vendorType) {
		this(nameLen, name, vendorType, null);
	}

	/**
	 * Shortcut test of name == "GNU"
	 * 
	 * @return true if name is "GNU"
	 */
	public boolean isGnu() {
		return "GNU".equals(name);
	}

	/**
	 * Returns the name value of this note.
	 * 
	 * @return string name
	 */
	public String getName() {
		return name;
	}

	public int getNameLen() {
		return nameLen;
	}

	/**
	 * Returns the bytes in the description portion of the note.
	 * 
	 * @return byte array
	 */
	public byte[] getDescription() {
		return description;
	}

	public int getDescriptionLen() {
		return description != null ? description.length : 0;
	}

	/**
	 * Returns a hex string of the description bytes.
	 * 
	 * @return hex string
	 */
	public String getDescriptionAsHexString() {
		return NumericUtilities.convertBytesToString(description);
	}

	/**
	 * Returns a {@link BinaryReader} that reads from this note's description blob.
	 * 
	 * @param isLittleEndian flag, see {@link BinaryReader#BinaryReader(ByteProvider, boolean)}
	 * @return new BinaryReader
	 */
	public BinaryReader getDescriptionReader(boolean isLittleEndian) {
		ByteArrayProvider bap = new ByteArrayProvider(description);
		BinaryReader descReader = new BinaryReader(bap, isLittleEndian);
		return descReader;
	}

	/**
	 * Returns the vendor type 'enum' value of this note.
	 * 
	 * @return vendor type 'enum' value
	 */
	public int getVendorType() {
		return vendorType;
	}

	/**
	 * Returns a string that describes this note's type, used when creating the default
	 * {@link #getProgramInfoKey()} value.
	 * <p>
	 * Specific Note subclasses can override this to return a better string than this default
	 * implementation, or can override the {@link #getProgramInfoKey()} method.
	 * 
	 * @return descriptive string 
	 */
	public String getNoteTypeName() {
		return "%s, %d".formatted(name, vendorType);
	}

	/**
	 *  Returns a string representation of this note's 'value', used when creating the
	 *  PROGRAM_INFO entry.
	 *  <p>
	 *  Specific Note subclasses should override this to return a better string than this default
	 *  implementation.
	 *  
	 * @return string describing this note's value
	 */
	public String getNoteValueString() {
		return getDescriptionAsHexString();
	}

	/**
	 * Returns a string that is used to build a PROGRAM_INFO entry's key.
	 * <p>
	 * Specific Note subclasses can override this to return a better key string.
	 * 
	 * @return key string (avoid using '.' characters as they will be converted to '_'s) 
	 */
	public String getProgramInfoKey() {
		return "ELF Note[%s]".formatted(getNoteTypeName());
	}

	/**
	 * Adds a single entry to the Options, built from the {@link #getProgramInfoKey()} value and
	 * {@link #getNoteValueString()} value.
	 * 
	 * @param programInfoOptions {@link Options} to add entry to
	 */
	public void decorateProgramInfo(Options programInfoOptions) {
		programInfoOptions.setString(getProgramInfoKey().replaceAll("\\.", "_"),
			getNoteValueString());
	}

	@Override
	public void markupProgram(Program program, Address address) {
		decorateProgramInfo(program.getOptions(Program.PROGRAM_INFO));

		StructureDataType dt = toStructure(program.getDataTypeManager());
		if (dt != null) {
			try {
				DataUtilities.createData(program, address, dt, -1, false,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			}
			catch (CodeUnitInsertionException e) {
				Msg.error(this, "Failed to markup Elf Note at %s: %s".formatted(address, this), e);
			}
		}
	}

	/**
	 * Returns a Structure datatype that matches the format of this ElfNote, or null if this
	 * ElfNote shouldn't be represented/marked up.
	 * 
	 * @param dtm {@link DataTypeManager} that will receive the structure 
	 * @return StructureDataType that specifies the layout of the ElfNote, or null
	 */
	public StructureDataType toStructure(DataTypeManager dtm) {
		return createNoteStructure(StandardElfInfoProducer.ELF_CATEGORYPATH, "ElfNote", true,
			getNameLen(), getDescriptionLen(), dtm);
	}

	@Override
	public String toString() {
		return "ELF Note[%s]: %s".formatted(getNoteTypeName(), getNoteValueString());
	}

	protected static StructureDataType createNoteStructure(CategoryPath cp, String structName,
			boolean templatedName, int noteNameLen, int noteDescLen, DataTypeManager dtm) {
		if (templatedName) {
			structName = "%s_%d_%d".formatted(structName, noteNameLen, noteDescLen);
		}
		if (cp == null) {
			cp = StandardElfInfoProducer.ELF_CATEGORYPATH;
		}
		StructureDataType result = new StructureDataType(cp, structName, 0, dtm);
		result.add(DWORD, "namesz", "Length of name field");
		result.add(DWORD, "descsz", "Length of description field");
		result.add(DWORD, "type", "Vendor specific type");
		if (noteNameLen > 0) {
			result.add(StringDataType.dataType, noteNameLen, "name", "Vendor name");
		}
		if (noteDescLen > 0) {
			result.add(new ArrayDataType(BYTE, noteDescLen, BYTE.getLength(), dtm), "description",
				"Blob value");
		}

		return result;
	}

}
