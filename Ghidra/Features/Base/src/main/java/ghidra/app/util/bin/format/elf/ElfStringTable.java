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
import java.nio.charset.StandardCharsets;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MutableByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

public class ElfStringTable implements StructConverter {

	private ElfHeader header;

	private ElfFileSection fileSection;
	private BinaryReader reader;

	/**
	 * Construct and parse an Elf string table
	 * @param header elf header
	 * @param fileSection string table file section
	 */
	public ElfStringTable(ElfHeader header, ElfFileSection fileSection) {
		this.header = header;
		this.fileSection = fileSection;
		this.reader = fileSection.getReader();
	}

	/**
	 * Read string from table at specified relative table offset
	 * @param stringOffset table relative string offset
	 * @return string or null on error
	 */
	public String readString(long stringOffset) {
		try {
			if (stringOffset >= fileSection.getMemorySize()) {
				throw new IOException("String read beyond table bounds");
			}
			return reader.readUtf8String(stringOffset).trim();
		}
		catch (IOException e) {
			header.logError(
				"Failed to read Elf String at offset 0x" + Long.toHexString(stringOffset) +
					" within String Table at offset 0x" + Long.toHexString(fileSection.getFileOffset()));
		}
		return null;
	}

	/**
	 * Append a string at the end of the string table
	 * @param str String to append
	 * @return index of string
	 */
	public int add(String str) throws IOException {
		ByteProvider byteProvider = reader.getByteProvider();
		if (!(byteProvider instanceof MutableByteProvider)) {
			throw new IOException("Backing byte provider isn't mutable");
		}

		MutableByteProvider mutableByteProvider = (MutableByteProvider) byteProvider;
		int strIndex = (int) mutableByteProvider.length();
		mutableByteProvider.writeBytes(strIndex, StandardCharsets.UTF_8.encode(str + '\0').array());

		return strIndex;
	}

	/**
	 * Get file section which corresponds to this table
	 * @return string table section section
	 */
	public ElfFileSection getFileSection() {
		return fileSection;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		// no uniform structure to be applied
		return null;
	}

}
