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
package ghidra.app.util.bin.format.dwarf.line;

import java.io.IOException;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf.DWARFCompilationUnit;
import ghidra.app.util.bin.format.dwarf.attribs.*;
import ghidra.program.model.data.LEB128;

/**
 * DWARFFile is used to store file or directory entries in the DWARFLine.
 */
public class DWARFFile {
	/**
	 * Reads a DWARFFile entry.
	 * 
	 * @param reader BinaryReader
	 * @return new DWARFFile, or null if end-of-list was found
	 * @throws IOException if error reading
	 */
	public static DWARFFile readV4(BinaryReader reader) throws IOException {
		String name = reader.readNextAsciiString();
		if (name.length() == 0) {
			// empty name == end-of-list of files
			return null;
		}

		int directory_index = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
		long modification_time = reader.readNext(LEB128::unsigned);
		long length = reader.readNext(LEB128::unsigned);

		return new DWARFFile(name, directory_index, modification_time, length, null);
	}

	/**
	 * Reads a DWARFFile entry.
	 * 
	 * @param reader BinaryReader
	 * @param defs similar to a DIE's attributespec, a list of DWARFForms that define how values
	 * will be deserialized from the stream
	 * @param cu {@link DWARFCompilationUnit}
	 * @return new DWARFFile
	 * @throws IOException if error reading
	 */
	public static DWARFFile readV5(BinaryReader reader, List<DWARFLineContentType.Def> defs,
			DWARFCompilationUnit cu) throws IOException {

		String name = null;
		int directoryIndex = -1;
		long modTime = 0;
		long length = 0;
		byte[] md5 = null;
		for (DWARFLineContentType.Def def : defs) {
			DWARFFormContext context = new DWARFFormContext(reader, cu, def);
			DWARFAttributeValue val = def.getAttributeForm().readValue(context);

			switch (def.getAttributeId()) {
				case DW_LNCT_path:
					name =
						val instanceof DWARFStringAttribute strval ? strval.getValue(cu) : null;
					break;
				case DW_LNCT_directory_index:
					directoryIndex = val instanceof DWARFNumericAttribute numval
							? numval.getUnsignedIntExact()
							: -1;
					break;
				case DW_LNCT_timestamp:
					modTime =
						val instanceof DWARFNumericAttribute numval ? numval.getValue() : 0;
					break;
				case DW_LNCT_size:
					length = val instanceof DWARFNumericAttribute numval
							? numval.getUnsignedValue()
							: 0;
					break;
				case DW_LNCT_MD5:
					md5 = val instanceof DWARFBlobAttribute blobval ? blobval.getBytes() : null;
					break;
				default:
					// skip any DW_LNCT_??? values that we don't care about
					break;
			}
		}
		if (name == null) {
			throw new IOException("No name value for DWARFLine file");
		}
		return new DWARFFile(name, directoryIndex, modTime, length, md5);
	}

	private final String name;
	private final int directory_index;
	private final long modification_time;
	private final long length;
	private final byte[] md5;

	public DWARFFile(String name) {
		this(name, -1, 0, 0, null);
	}

	/**
	 * Create a new DWARF file entry with the given parameters.
	 * @param name name of the file
	 * @param directory_index index of the directory for this file
	 * @param modification_time modification time of the file
	 * @param length length of the file
	 */
	public DWARFFile(String name, int directory_index, long modification_time, long length,
			byte[] md5) {
		this.name = name;
		this.directory_index = directory_index;
		this.modification_time = modification_time;
		this.length = length;
		this.md5 = md5;
	}

	public String getName() {
		return this.name;
	}

	public DWARFFile withName(String newName) {
		return new DWARFFile(newName, directory_index, modification_time, length, md5);
	}

	public int getDirectoryIndex() {
		return this.directory_index;
	}

	public long getModificationTime() {
		return this.modification_time;
	}

	public byte[] getMD5() {
		return md5;
	}

	@Override
	public String toString() {
		return "Filename: %s, Length: 0x%x, Time: 0x%x, DirIndex: %d".formatted(name, length,
			modification_time, directory_index);
	}
}
