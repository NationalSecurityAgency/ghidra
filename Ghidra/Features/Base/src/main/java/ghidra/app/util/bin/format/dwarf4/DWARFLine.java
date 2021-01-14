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
package ghidra.app.util.bin.format.dwarf4;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.FilenameUtils;

import ghidra.app.util.bin.BinaryReader;

public class DWARFLine {
	private long unit_length;
	private int format;
	private int version;
	private long header_length;
	private int minimum_instruction_length;
	private int maximum_operations_per_instruction;
	private int default_is_stmt;
	private int line_base;
	private int line_range;
	private int opcode_base;
	private int[] standard_opcode_length;
	private List<String> include_directories;
	private List<DWARFFile> file_names;

	// TODO: convert this to a static factory method and a simple setter ctor
	public DWARFLine(BinaryReader reader) throws IOException, DWARFException {
		this.unit_length = reader.readNextUnsignedInt();
		// Length of 0xffffffff implies 64-bit DWARF format
		if (this.unit_length == 0xffffffffL) {
			this.unit_length = reader.readNextLong();
			this.format = DWARFCompilationUnit.DWARF_64;
		}
		// Length of 0xfffffff0 or greater is reserved for DWARF
		else if (this.unit_length >= 0xfffffff0L) {
			throw new DWARFException("Reserved DWARF length value: " +
				Long.toHexString(this.unit_length) + ". Unknown extension.");
		}
		else {
			this.format = DWARFCompilationUnit.DWARF_32;
		}

		// A version number for this line number information section
		this.version = reader.readNextUnsignedShort();

		// Get the header length based on the current format
		this.header_length = DWARFUtil.readOffsetByDWARFformat(reader, this.format);

		this.minimum_instruction_length = reader.readNextUnsignedByte();

		// Maximum operations per instruction only exists in DWARF version 4 or higher
		if (this.version >= 4) {
			this.maximum_operations_per_instruction = reader.readNextUnsignedByte();
		}
		else {
			this.maximum_operations_per_instruction = 1;
		}
		this.default_is_stmt = reader.readNextUnsignedByte();
		this.line_base = reader.readNextByte();
		this.line_range = reader.readNextUnsignedByte();
		this.opcode_base = reader.readNextUnsignedByte();
		this.standard_opcode_length = new int[this.opcode_base];
		this.standard_opcode_length[0] = 1; /* Should never be used */
		for (int i = 1; i < this.opcode_base; i++) {
			this.standard_opcode_length[i] = reader.readNextUnsignedByte();
		}

		// Read all include directories
		this.include_directories = new ArrayList<>();
		String include = reader.readNextAsciiString();
		while (include.length() != 0) {
			this.include_directories.add(include);
			include = reader.readNextAsciiString();
		}

		// Read all files
		this.file_names = new ArrayList<>();
		DWARFFile file = new DWARFFile(reader);
		while (file.getName().length() != 0) {
			this.file_names.add(file);
			file = new DWARFFile(reader);
		}
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
				String directory = this.include_directories.get(diridx - 1);
				return directory + file.getName();
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

	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer();
		buffer.append("Line Entry");
		buffer.append(" Include Directories: [");
		for (String dir : this.include_directories) {
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
		private String name;
		private long directory_index;
		private long modification_time;
		private long length;

		/**
		 * Read in a new file entry and store into this object.
		 * @param reader binary reader to read the file entry
		 * @throws IOException if an I/O error occurs
		 */
		public DWARFFile(BinaryReader reader) throws IOException {
			this.name = reader.readNextAsciiString();

			// This entry exists only if the length of the string is more than 0
			if (this.name.length() > 0) {
				this.directory_index = LEB128.readAsLong(reader, false);
				this.modification_time = LEB128.readAsLong(reader, false);
				this.length = LEB128.readAsLong(reader, false);
			}
		}

		/**
		 * Create a new DWARF file entry with the given parameters.
		 * @param name name of the file
		 * @param directory_index index of the directory for this file
		 * @param modification_time modification time of the file
		 * @param length length of the file
		 */
		public DWARFFile(String name, long directory_index, long modification_time, long length) {
			this.name = name;
			this.directory_index = directory_index;
			this.modification_time = modification_time;
			this.length = length;
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
			StringBuffer buffer = new StringBuffer();
			buffer.append("Filename: ");
			buffer.append(this.name);
			buffer.append(" Length: ");
			buffer.append(Long.toHexString(this.length));
			return buffer.toString();
		}
	}

}
