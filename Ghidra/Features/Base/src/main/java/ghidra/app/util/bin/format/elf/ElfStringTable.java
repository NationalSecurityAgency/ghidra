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
package ghidra.app.util.bin.format.elf;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

public class ElfStringTable implements ElfFileSection {

	private ElfHeader header;

	private ElfSectionHeader stringTableSection; // may be null
	private long fileOffset;
	private long addrOffset;
	private long length;

	/**
	 * Construct and parse an Elf string table
	 * @param reader the binary reader containing the elf string table
	 * @param header elf header
	 * @param stringTableSection string table section header or null if associated with a dynamic table entry
	 * @param fileOffset symbol table file offset
	 * @param addrOffset memory address of symbol table (should already be adjusted for prelink)
	 * @param length length of symbol table in bytes of -1 if unknown
	 */
	public ElfStringTable(BinaryReader reader, ElfHeader header,
			ElfSectionHeader stringTableSection, long fileOffset, long addrOffset, long length) {
		this.header = header;
		this.stringTableSection = stringTableSection;
		this.fileOffset = fileOffset;
		this.addrOffset = addrOffset;
		this.length = length;
	}

	/**
	 * Read string from table at specified relative table offset
	 * @param reader byte reader
	 * @param stringOffset table relative string offset
	 * @return string or null on error
	 */
	public String readString(BinaryReader reader, long stringOffset) {
		if (fileOffset < 0) {
			return null;
		}
		try {
			if (stringOffset >= length) {
				throw new IOException("String read beyond table bounds");
			}
			return reader.readAsciiString(fileOffset + stringOffset);
		}
		catch (IOException e) {
			header.logError(
				"Failed to read Elf String at offset 0x" + Long.toHexString(stringOffset) +
					" within String Table at offset 0x" + Long.toHexString(fileOffset));
		}
		return null;
	}

	@Override
	public long getAddressOffset() {
		return header.adjustAddressForPrelink(addrOffset);
	}

	/**
	 * Get section header which corresponds to this table, or null
	 * if only associated with a dynamic table entry
	 * @return string table section header or null
	 */
	public ElfSectionHeader getTableSectionHeader() {
		return stringTableSection;
	}

	@Override
	public long getFileOffset() {
		return fileOffset;
	}

	@Override
	public long getLength() {
		return length;
	}

	@Override
	public int getEntrySize() {
		return -1;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		// no uniform structure to be applied
		return null;
	}

}
