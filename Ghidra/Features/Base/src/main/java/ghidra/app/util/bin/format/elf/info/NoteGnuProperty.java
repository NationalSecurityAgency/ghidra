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

import java.util.ArrayList;
import java.util.List;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;

/**
 * An ELF note that contains a list of enumerated "properties".
 * <p>
 * Currently known property types are stack_size and no_copy_on_protected (flag).
 * <p>
 * <pre>
 *  array of Elf_Prop {
 *    word pr_type;
 *    word pr_datasz;
 *    byte pr_data[pr_datasz];
 *    byte padding[]
 *  }
 * </pre>
 */
public class NoteGnuProperty extends ElfNote {
	public static final String SECTION_NAME = ".note.gnu.property";

	// Elf_Prop pr_types
	private static final int GNU_PROPERTY_STACK_SIZE = 1;
	private static final int GNU_PROPERTY_NO_COPY_ON_PROTECTED = 2;

	// properties specific to processor options
	private static final int GNU_PROPERTY_LOPROC = 0xc0000000;
	private static final int GNU_PROPERTY_HIPROC = 0xdfffffff;

	// properties specific to application / user defined
	private static final int GNU_PROPERTY_LOUSER = 0xe0000000;
	private static final int GNU_PROPERTY_HIUSER = 0xffffffff;

	/**
	 * Parses a NoteGnuProperty instance from the specified generic note.
	 * 
	 * @param note generic note that contains the data from a .note.gnu.property section
	 * @param program Program that contains the note section
	 * @return {@link NoteGnuProperty} instance
	 * @throws IOException if IO error parsing data
	 */
	public static NoteGnuProperty read(ElfNote note, Program program) throws IOException {
		List<NotePropertyElement> elements = new ArrayList<>();
		BinaryReader descReader = note.getDescriptionReader(!program.getMemory().isBigEndian());
		while (descReader.hasNext()) {
			NotePropertyElement element =
				readNextNotePropertyElement(descReader, program.getDefaultPointerSize());
			elements.add(element);
		}

		return new NoteGnuProperty(note.getNameLen(), note.getName(), note.getVendorType(),
			elements);
	}

	/**
	 * Contains the information of an individual note property. 
	 */
	public record NotePropertyElement(int type, String typeName, String value, int length) {}

	private static NotePropertyElement readNextNotePropertyElement(BinaryReader reader, int intSize)
			throws IOException {
		int prType = reader.readNextInt();
		int prDatasz = reader.readNextUnsignedIntExact();
		long dataStart = reader.getPointerIndex();

		String typeName;
		String value = "???";
		switch (prType) {
			case GNU_PROPERTY_STACK_SIZE: {
				typeName = "stack_size";
				long tmp = reader.readNextUnsignedValue(intSize);
				value = "%d (0x%08x)".formatted(tmp, tmp);
				break;
			}
			case GNU_PROPERTY_NO_COPY_ON_PROTECTED:
				typeName = "no_copy_on_protected";
				value = "set";
				break;
			default:
				if (GNU_PROPERTY_LOPROC <= prType && prType <= GNU_PROPERTY_HIPROC) {
					typeName = "processor opt 0x%08x".formatted(prType);
				}
				else if (GNU_PROPERTY_LOUSER <= prType && prType <= GNU_PROPERTY_HIUSER) {
					typeName = "app opt 0x%08x".formatted(prType);
				}
				else {
					typeName = "unknown opt 0x%08x".formatted(prType);
				}
				if (prDatasz > 0) {
					byte[] valueBytes = reader.readNextByteArray(prDatasz);
					value = NumericUtilities.convertBytesToString(valueBytes, " ");
				}
		}
		// TODO: the logic for getting to next element isn't well tested and the docs are not very
		// clear.
		reader.setPointerIndex(dataStart + prDatasz);
		reader.align(intSize);

		return new NotePropertyElement(prType, typeName, value, prDatasz);
	}

	/**
	 * Returns a NoteGnuProperty instance containing the information found in the program's
	 * ".note.gnu.property" section, or null if there is no section.
	 * 
	 * @param program {@link Program} to read from
	 * @return {@link NoteGnuProperty}
	 */
	public static NoteGnuProperty fromProgram(Program program) {
		return ElfNote.readFromProgramHelper(program, SECTION_NAME, NoteGnuProperty::read);
	}

	private final List<NotePropertyElement> elements;

	/**
	 * Creates a instance using the specified values.
	 * 
	 * @param name name of property
	 * @param vendorType vendor type of property
	 * @param elements list of NotePropertyElements
	 */
	public NoteGnuProperty(int nameLen, String name, int vendorType,
			List<NotePropertyElement> elements) {
		super(nameLen, name, vendorType);

		this.elements = elements;
	}

	@Override
	public String getNoteTypeName() {
		return SECTION_NAME;
	}

	@Override
	public void decorateProgramInfo(Options programInfoOptions) {
		for (NotePropertyElement element : elements) {
			// TODO: de-dup keys that collide?
			String key =
				"ELF GNU Program Prop[%s]".formatted(element.typeName).replaceAll("\\.", "_");
			programInfoOptions.setString(key, element.value);
		}
	}

	@Override
	public void markupProgram(Program program, Address address) {
		super.markupProgram(program, address);

		ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
		Listing listing = program.getListing();

		try {
			StructureDataType struct =
				createNoteStructure(null, "NoteGnuProperty_%d".formatted(getNameLen()), false,
					getNameLen(), 0, program.getDataTypeManager());
			Data propData = DataUtilities.createData(program, address, struct, -1, false,
				ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			address = propData.getMaxAddress().next();

			for (NotePropertyElement element : elements) {
				DataType elementDT = getElementDataType(dtm, element);
				Data elementData = DataUtilities.createData(program, address, elementDT, -1, false,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
				listing.setComment(address, CodeUnit.EOL_COMMENT,
					element.typeName() + "=" + element.value());
				address = elementData.getMaxAddress().next();
			}
		}
		catch (CodeUnitInsertionException e) {
			Msg.error(this, "Failed to markup NoteGnuProperty at %s, %s".formatted(address, this));
		}

	}

	private DataType getElementDataType(DataTypeManager dtm, NotePropertyElement element) {
		StructureDataType result =
			new StructureDataType("NoteGnuPropertyElement_%d".formatted(element.length()), 0, dtm);

		result.add(StructConverter.DWORD, "prType", null);
		result.add(StructConverter.DWORD, "prDatasz", null);
		result.add(new ArrayDataType(StructConverter.BYTE, element.length, -1, dtm), "data", null);

		return result;
	}

	@Override
	public StructureDataType toStructure(DataTypeManager dtm) {
		// defer creating data types until our custom markupProgram method so it can create
		// more than 1 element.
		return null;
	}

}
