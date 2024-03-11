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
package ghidra.app.util.bin.format.dwarf;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.FilenameUtils;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf.DWARFLineContentType.Def;
import ghidra.app.util.bin.format.dwarf.attribs.*;
import ghidra.program.model.data.LEB128;

/**
 * Represents source file line number mapping info.
 */
public class DWARFLine {
	private long unit_length;
	private int version;
	private long header_length;
	private int minimum_instruction_length;
	private int maximum_operations_per_instruction;
	private int default_is_stmt;
	private int line_base;
	private int line_range;
	private int opcode_base;
	private int[] standard_opcode_length;
	private List<DWARFFile> include_directories = new ArrayList<>();
	private List<DWARFFile> file_names = new ArrayList<>();
	private int address_size;
	private int segment_selector_size;

	public static DWARFLine empty() {
		return new DWARFLine();
	}

	/**
	 * Read a v4 DWARFLine. 
	 * 
	 * @param dprog {@link DWARFProgram} 
	 * @param reader {@link BinaryReader} stream
	 * @param lengthInfo {@link DWARFLengthValue} 
	 * @param version DWARFLine version (from header)
	 * @return a new DWARFLine instance if DW_AT_stmt_list and stream are present, otherwise null
	 * @throws IOException if error reading data
	 * @throws DWARFException if bad DWARF values
	 */
	public static DWARFLine readV4(DWARFProgram dprog, BinaryReader reader,
			DWARFLengthValue lengthInfo, int version) throws IOException, DWARFException {

		// length : dwarf_length
		// version : 2 bytes
		// header_len : dwarf_intsize
		// min_instr_len : 1 byte
		// ....
		DWARFLine result = new DWARFLine();
		result.unit_length = lengthInfo.length();

		result.version = version;
		result.header_length = reader.readNextUnsignedValue(lengthInfo.intSize());
		result.minimum_instruction_length = reader.readNextUnsignedByte();

		if (result.version >= 4) {
			// Maximum operations per instruction only exists in DWARF version 4 or higher
			result.maximum_operations_per_instruction = reader.readNextUnsignedByte();
		}
		else {
			result.maximum_operations_per_instruction = 1;
		}
		result.default_is_stmt = reader.readNextUnsignedByte();
		result.line_base = reader.readNextByte();
		result.line_range = reader.readNextUnsignedByte();
		result.opcode_base = reader.readNextUnsignedByte();
		result.standard_opcode_length = new int[result.opcode_base];
		result.standard_opcode_length[0] = 1; /* Should never be used */
		for (int i = 1; i < result.opcode_base; i++) {
			result.standard_opcode_length[i] = reader.readNextUnsignedByte();
		}

		// Read all include directories
		String include = reader.readNextAsciiString();
		while (include.length() != 0) {
			result.include_directories.add(new DWARFFile(include));
			include = reader.readNextAsciiString();
		}

		// Read all files, ending when null (hit empty filename)
		DWARFFile file;
		while ((file = DWARFFile.readV4(reader)) != null) {
			result.file_names.add(file);
		}

		return result;
	}

	/**
	 * Read a v5 DWARFLine.
	 * 
	 * @param dprog {@link DWARFProgram} 
	 * @param reader {@link BinaryReader} stream
	 * @param lengthInfo {@link DWARFLengthValue} 
	 * @param version DWARFLine version (from header)
	 * @param cu {@link DWARFCompilationUnit}
	 * @return a new DWARFLine instance if DW_AT_stmt_list and stream are present, otherwise null
	 * @throws IOException if error reading data
	 * @throws DWARFException if bad DWARF values
	 */
	public static DWARFLine readV5(DWARFProgram dprog, BinaryReader reader,
			DWARFLengthValue lengthInfo, int version, DWARFCompilationUnit cu)
			throws IOException, DWARFException {

		// length : dwarf_length
		// version : 2 bytes
		// address_size : 1 byte
		// segment_selector_size : 1 byte
		// header_len : dwarf_intsize
		// min_instr_len : 1 byte
		// ...
		DWARFLine result = new DWARFLine();
		result.unit_length = lengthInfo.length();
		result.version = version;
		result.address_size = reader.readNextUnsignedByte();
		result.segment_selector_size = reader.readNextUnsignedByte();
		result.header_length = reader.readNextUnsignedValue(lengthInfo.intSize());
		result.minimum_instruction_length = reader.readNextUnsignedByte();
		result.maximum_operations_per_instruction = reader.readNextUnsignedByte();
		result.default_is_stmt = reader.readNextUnsignedByte();
		result.line_base = reader.readNextByte();
		result.line_range = reader.readNextUnsignedByte();
		result.opcode_base = reader.readNextUnsignedByte();
		result.standard_opcode_length = new int[result.opcode_base];
		result.standard_opcode_length[0] = 1; /* Should never be used */
		for (int i = 1; i < result.opcode_base; i++) {
			result.standard_opcode_length[i] = reader.readNextUnsignedByte();
		}
		int directory_entry_format_count = reader.readNextUnsignedByte();
		List<DWARFLineContentType.Def> dirFormatDefs = new ArrayList<>();
		for (int i = 0; i < directory_entry_format_count; i++) {
			Def lcntDef = DWARFLineContentType.Def.read(reader);
			dirFormatDefs.add(lcntDef);
		}

		int directories_count = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
		for (int i = 0; i < directories_count; i++) {
			DWARFFile dir = DWARFFile.readV5(reader, dirFormatDefs, cu);
			result.include_directories.add(dir);
		}

		int filename_entry_format_count = reader.readNextUnsignedByte();
		List<DWARFLineContentType.Def> fileFormatDefs = new ArrayList<>();
		for (int i = 0; i < filename_entry_format_count; i++) {
			Def lcntDef = DWARFLineContentType.Def.read(reader);
			fileFormatDefs.add(lcntDef);
		}

		int file_names_count = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
		for (int i = 0; i < file_names_count; i++) {
			DWARFFile dir = DWARFFile.readV5(reader, fileFormatDefs, cu);
			result.file_names.add(dir);
		}

		return result;
	}

	record DirectoryEntryFormat(int contentTypeCode, int formCode) {
		static DirectoryEntryFormat read(BinaryReader reader) throws IOException, IOException {
			int contentTypeCode = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
			int formCode = reader.readNextUnsignedVarIntExact(LEB128::unsigned);

			return new DirectoryEntryFormat(contentTypeCode, formCode);
		}
	}

	private DWARFLine() {
		// empty, use #read()
	}

	/**
	 * Get a file name with the full path included.
	 * @param index index of the file
	 * @param compileDirectory current compile unit directory
	 * @return file name with full path
	 */
	public String getFullFile(int index, String compileDirectory) {
		if (index == 0) {
			//TODO: Handle index = 0
			throw new UnsupportedOperationException(
				"Currently does not support retrieving the primary source file.");
		}
		else if (index > 0) {
			// Retrieve the file by index (index starts at 1)
			DWARFFile file = this.file_names.get(index - 1);

			File fileObj = new File(file.getName());

			// Check to see if the file is an absolute path and return if so
			if (fileObj.isAbsolute()) {
				return file.getName();
			}

			// Otherwise we need to retrieve the directory
			int diridx = (int) file.getDirectoryIndex();
			if (diridx == 0) {
				// Use the compile directory if a directory index of 0 is given
				if (compileDirectory != null) {
					return compileDirectory + file.getName();
				}
				throw new IllegalArgumentException(
					"No compile directory was given when one was expected.");
			}
			else if (diridx > 0) {
				// Retrieve and append the directory
				DWARFFile directory = this.include_directories.get(diridx - 1);
				return directory.getName() + file.getName();
			}
			throw new IndexOutOfBoundsException(
				"Negative directory index was found: " + Integer.toString(diridx));
		}
		throw new IllegalArgumentException(
			"Negative file index was given: " + Integer.toString(index));
	}

	/**
	 * Get a file name given a file index.
	 * @param index index of the file
	 * @param compileDirectory current compile unit directory
	 * @return file name
	 */
	public String getFile(int index, String compileDirectory) {
		if (version < 5) {
			if (index == 0) {
				//TODO: Handle index = 0
				throw new UnsupportedOperationException(
					"Currently does not support retrieving the primary source file.");
			}
			else if (index > 0) {
				// Retrieve the file by index (index starts at 1)
				DWARFFile file = this.file_names.get(index - 1);
				return FilenameUtils.getName(file.getName());
			}
			throw new IllegalArgumentException(
				"Negative file index was given: " + Integer.toString(index));
		}
		else if (version >= 5) {
			if (index < 0 || file_names.size() <= index) {
				throw new IllegalArgumentException("Bad file index: " + index);
			}
			DWARFFile file = this.file_names.get(index);
			return FilenameUtils.getName(file.getName());
		}
		return null;
	}

	/**
	 * Returns true if file exists.
	 * 
	 * @param index file number, excluding 0
	 * @return boolean true if file exists
	 */
	public boolean isValidFileIndex(int index) {
		index--;
		return 0 <= index && index < file_names.size();
	}

	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer();
		buffer.append("Line Entry");
		buffer.append(" Include Directories: [");
		for (DWARFFile dir : this.include_directories) {
			buffer.append(dir);
			buffer.append(", ");
		}
		buffer.append("] File Names: [");
		for (DWARFFile file : this.file_names) {
			buffer.append(file.toString());
			buffer.append(", ");
		}
		buffer.append("]");
		return buffer.toString();
	}

	/**
	 * DWARFFile is used to store file information for each entry in the line section header.
	 */
	public static class DWARFFile {
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

			long directory_index = reader.readNext(LEB128::unsigned);
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
			long directoryIndex = -1;
			long modTime = 0;
			long length = 0;
			byte[] md5 = null;
			for (DWARFLineContentType.Def def : defs) {
				DWARFFormContext context = new DWARFFormContext(reader, cu, def);
				DWARFAttributeValue val = def.getAttributeForm().readValue(context);

				switch (def.getAttributeId()) {
					case DW_LNCT_path:
						name = val instanceof DWARFStringAttribute strval
								? strval.getValue(cu)
								: null;
						break;
					case DW_LNCT_directory_index:
						directoryIndex =
							val instanceof DWARFNumericAttribute numval ? numval.getValue() : -1;
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

		private String name;
		private long directory_index;
		private long modification_time;
		private long length;
		private byte[] md5;

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
		public DWARFFile(String name, long directory_index, long modification_time, long length,
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

		public long getDirectoryIndex() {
			return this.directory_index;
		}

		public long getModificationTime() {
			return this.modification_time;
		}

		@Override
		public String toString() {
			return "Filename: %s, Length: 0x%x, Time: 0x%x, DirIndex: %d".formatted(name, length,
				modification_time, directory_index);
		}
	}

}
