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

import static ghidra.app.util.bin.StructConverter.*;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;

/**
 * An ELF section (almost like a {@link ElfNote}) that contains information about an external
 * DWARF debug file.
 * <p>
 * External DWARF debug files can also be specified with a {@link NoteGnuBuildId}.
 */
public class GnuDebugAltLink implements ElfInfoItem {
	public static final String SECTION_NAME = ".gnu_debugaltlink";

	/**
	 * Reads a GnuDebugAltLink from the standard ".gnu_debugaltlink" section in the specified Program.
	 * 
	 * @param program Program to read from
	 * @return new instance, or null if not found or data error
	 */
	public static GnuDebugAltLink fromProgram(Program program) {
		ItemWithAddress<GnuDebugAltLink> wrappedItem = ElfInfoItem.readItemFromSection(program,
			SECTION_NAME, GnuDebugAltLink::read);
		return wrappedItem != null ? wrappedItem.item() : null;
	}

	/**
	 * Reads a GnuDebugAltLink from the specified BinaryReader.
	 * 
	 * @param br BinaryReader to read from
	 * @param program unused, present to match the signature of {@link ElfInfoItem.ReaderFunc}
	 * @return new instance, or null if data error
	 */
	public static GnuDebugAltLink read(BinaryReader br, Program program) {
		try {
			long filenameStart = br.getPointerIndex();
			String filename = br.readNextAsciiString();
			int filenameLen = (int) (br.getPointerIndex() - filenameStart);
			long hashSize = br.length() - br.getPointerIndex();
			if (hashSize > 1024 /* wag for max sane */) {
				throw new IOException();
			}
			byte[] hashBytes = br.readNextByteArray((int) hashSize);
			return new GnuDebugAltLink(filenameLen, filename, hashBytes);
		}
		catch (IOException e) {
			// fall thru and return null
		}
		return null;
	}

	private final int filenameLen;
	private final String filename;
	private final byte[] hashBytes;

	public GnuDebugAltLink(int filenameLen, String filename, byte[] hashBytes) {
		this.filenameLen = filenameLen;
		this.filename = filename;
		this.hashBytes = hashBytes;
	}

	public String getFilename() {
		return filename;
	}

	public int getFilenameLen() {
		return filenameLen;
	}

	public byte[] getHashBytes() {
		return hashBytes;
	}

	public String getHash() {
		return NumericUtilities.convertBytesToString(hashBytes);
	}

	@Override
	public void markupProgram(Program program, Address address) {
		program.getOptions(Program.PROGRAM_INFO)
				.setString("GNU DebugAltLink Filename", getFilename());
		program.getOptions(Program.PROGRAM_INFO).setString("GNU DebugAltLink Hash", getHash());

		try {
			StructureDataType struct = toStructure(program.getDataTypeManager());
			if (struct != null) {
				DataUtilities.createData(program, address, struct, -1, false,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			}
		}
		catch (CodeUnitInsertionException e) {
			Msg.error(this, "Failed to markup GnuDebugAltLink at %s: %s".formatted(address, this));
		}

	}

	private StructureDataType toStructure(DataTypeManager dtm) {
		if (filenameLen <= 0) {
			return null;
		}

		StructureDataType result =
			new StructureDataType(StandardElfInfoProducer.ELF_CATEGORYPATH,
				"GnuDebugAltLink_%d".formatted(filenameLen), 0, dtm);
		result.add(StringDataType.dataType, filenameLen, "filename", null);
		result.add(new ArrayDataType(BYTE, hashBytes.length), "hash", null);

		return result;
	}

	@Override
	public String toString() {
		return String.format("GnuDebugAltLink [filename=%s, hash=%s]", filename, getHash());
	}

}
