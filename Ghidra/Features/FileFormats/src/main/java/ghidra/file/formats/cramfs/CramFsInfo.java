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
package ghidra.file.formats.cramfs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class CramFsInfo implements StructConverter {

	private int crc;
	private int edition;
	private int blocks;
	private int files;

	/**
	 * This constructor reads the cramfs info/attributes
	 * @param reader the binary reader for the cramfs info/attributes.
	 * @throws IOException if there is an error while reading the cramfs info/attributes.
	 */
	public CramFsInfo(BinaryReader reader) throws IOException {
		crc = reader.readNextInt();
		edition = reader.readNextInt();
		blocks = reader.readNextInt();
		files = reader.readNextInt();
	}

	/**
	 * Returns the crc value of the cramfs info.
	 * @return the crc value of the cramfs info.
	 */
	public int getCrc() {
		return crc;
	}

	/**
	 * Returns the edition of the cramfs info.
	 * @return the edition of the cramfs info.
	 */
	public int getEdition() {
		return edition;
	}

	/**
	 * Returns the blocks of the cramfs info.
	 * @return the blocks of the cramfs info.
	 */
	public int getBlocks() {
		return blocks;
	}

	/**
	 * Returns the files of the cramfs info.
	 * @return the files of the cramfs info.
	 */
	public int getFiles() {
		return files;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType("cramfs_info", 0);
		struct.add(DWORD, "crc", null);
		struct.add(DWORD, "edition", null);
		struct.add(DWORD, "blocks", null);
		struct.add(DWORD, "files", null);
		return struct;
	}

}
