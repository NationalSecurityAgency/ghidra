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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf.*;
import ghidra.app.util.bin.format.dwarf.line.DWARFLineContentType.Def;
import ghidra.formats.gfilesystem.FSUtilities;
import ghidra.program.model.data.LEB128;

/**
 * A structure read from .debug_line, contains indexed source filenames as well as a mapping between
 * addresses and source filename and linenumbers.
 * <p>
 * TODO: refactor this and other similar classes to derive from DWARFUnitHeader and simplify
 */
public class DWARFLine {
	/**
	 * Returns a dummy DWARFLine instance that contains no information.
	 * 
	 * @return {@link DWARFLine} instance with no info
	 */
	public static DWARFLine empty() {
		return new DWARFLine();
	}

	public static DWARFLine read(BinaryReader reader, int defaultIntSize, DWARFCompilationUnit cu)
			throws IOException {
		// probe for the DWARFLine version number
		// length : dwarf_length
		// version : 2 bytes
		DWARFLine result = new DWARFLine();
		result.dprog = cu.getProgram();
		result.startOffset = reader.getPointerIndex();
		DWARFLengthValue lengthInfo = DWARFLengthValue.read(reader, defaultIntSize);
		if (lengthInfo == null) {
			throw new DWARFException(
				"Invalid DWARFLine length at 0x%x".formatted(result.startOffset));
		}

		result.length = lengthInfo.length();
		result.intSize = lengthInfo.intSize();
		result.endOffset = reader.getPointerIndex() + lengthInfo.length();

		result.dwarfVersion = reader.readNextUnsignedShort();
		if (result.dwarfVersion < 5) {
			DWARFLine.readV4(result, reader, cu);
		}
		else {
			DWARFLine.readV5(result, reader, cu);
		}
		return result;
	}

	private static void readV4(DWARFLine result, BinaryReader reader, DWARFCompilationUnit cu)
			throws IOException, DWARFException {

		// length : dwarf_length (already)
		// version : 2 bytes (already)
		// header_len : dwarf_intsize
		// min_instr_len : 1 byte
		// ....
		long header_length = reader.readNextUnsignedValue(result.intSize);
		result.opcodes_start = reader.getPointerIndex() + header_length;

		result.minimum_instruction_length = reader.readNextUnsignedByte();

		if (result.dwarfVersion >= 4) {
			// Maximum operations per instruction only exists in DWARF version 4 or higher
			result.maximum_operations_per_instruction = reader.readNextUnsignedByte();
		}
		else {
			result.maximum_operations_per_instruction = 1;
		}
		result.default_is_stmt = reader.readNextUnsignedByte() != 0;
		result.line_base = reader.readNextByte();
		result.line_range = reader.readNextUnsignedByte();
		result.opcode_base = reader.readNextUnsignedByte();
		result.standard_opcode_length = new int[result.opcode_base];
		result.standard_opcode_length[0] = 1; /* Should never be used */
		for (int i = 1; i < result.opcode_base; i++) {
			result.standard_opcode_length[i] = reader.readNextUnsignedByte();
		}

		// Add the cu's compDir as element 0 of the dir table
		String defaultCompDir = cu.getCompileDirectory();
		if (defaultCompDir == null || defaultCompDir.isBlank()) {
			defaultCompDir = "";
		}
		result.directories.add(new DWARFFile(defaultCompDir));

		// Read all include directories, which are only a list of names in v4
		String dirName = reader.readNextAsciiString();
		while (dirName.length() != 0) {
			DWARFFile dir = new DWARFFile(dirName);
			dir = fixupDir(dir, defaultCompDir);

			result.directories.add(dir);
			dirName = reader.readNextAsciiString();
		}

		// Read all files, ending when null (hit empty filename)
		DWARFFile file;
		while ((file = DWARFFile.readV4(reader)) != null) {
			result.files.add(file);
		}
	}

	private static void readV5(DWARFLine result, BinaryReader reader, DWARFCompilationUnit cu)
			throws IOException, DWARFException {

		// length : dwarf_length (already)
		// version : 2 bytes (already)
		// address_size : 1 byte
		// segment_selector_size : 1 byte
		// header_len : dwarf_intsize
		// min_instr_len : 1 byte
		// ...
		result.address_size = reader.readNextUnsignedByte();
		result.segment_selector_size = reader.readNextUnsignedByte();

		long header_length = reader.readNextUnsignedValue(result.intSize);
		result.opcodes_start = reader.getPointerIndex() + header_length;

		result.minimum_instruction_length = reader.readNextUnsignedByte();
		result.maximum_operations_per_instruction = reader.readNextUnsignedByte();
		result.default_is_stmt = reader.readNextUnsignedByte() != 0;
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

		String defaultCompDir = cu.getCompileDirectory();
		if (defaultCompDir == null || defaultCompDir.isBlank()) {
			defaultCompDir = "";
		}

		// read the directories, which are defined the same way files are
		int directories_count = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
		for (int i = 0; i < directories_count; i++) {
			DWARFFile dir = DWARFFile.readV5(reader, dirFormatDefs, cu);
			dir = fixupDir(dir, defaultCompDir);
			result.directories.add(dir);
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
			result.files.add(dir);
		}
	}

	private static DWARFFile fixupDir(DWARFFile dir, String defaultCompDir) {
		// fix relative dir names using the compiledir string from the CU
		if (!defaultCompDir.isEmpty()) {
			if (dir.getName().equals(".")) {
				return dir.withName(defaultCompDir);
			}
			else if (!isAbsolutePath(dir.getName())) {
				return dir.withName(FSUtilities.appendPath(defaultCompDir, dir.getName()));
			}
		}
		return dir;
	}

	private static boolean isAbsolutePath(String s) {
		return s.startsWith("/") || s.startsWith("\\") ||
			(s.length() > 3 && s.charAt(1) == ':' && (s.charAt(2) == '/' || s.charAt(2) == '\\'));
	}

	record DirectoryEntryFormat(int contentTypeCode, int formCode) {
		static DirectoryEntryFormat read(BinaryReader reader) throws IOException, IOException {
			int contentTypeCode = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
			int formCode = reader.readNextUnsignedVarIntExact(LEB128::unsigned);

			return new DirectoryEntryFormat(contentTypeCode, formCode);
		}
	}

	private DWARFProgram dprog;

	private long startOffset;

	/**
	 * Offset in the section of the end of this header. (exclusive)
	 */
	private long endOffset;

	/**
	 * Length in bytes of this header.
	 */
	private long length;

	/**
	 * size of integers, 4=int32 or 8=int64
	 */
	private int intSize;

	/**
	 * Version number, as read from the header.
	 */
	private int dwarfVersion;

	private int minimum_instruction_length;
	private int maximum_operations_per_instruction;
	private boolean default_is_stmt;
	private int line_base;
	private int line_range;
	private int opcode_base;
	private int[] standard_opcode_length;
	private List<DWARFFile> directories = new ArrayList<>();
	private List<DWARFFile> files = new ArrayList<>();
	private int address_size;
	private int segment_selector_size;

	private long opcodes_start = -1; // offset where line number program opcodes start

	private DWARFLine() {
		// empty, use #read()
	}

	public long getStartOffset() {
		return startOffset;
	}

	public long getEndOffset() {
		return endOffset;
	}

	public DWARFLineProgramExecutor getLineProgramexecutor(DWARFCompilationUnit cu,
			BinaryReader reader) {
		DWARFLineProgramExecutor lpe = new DWARFLineProgramExecutor(reader.clone(opcodes_start),
			endOffset, cu.getPointerSize(), opcode_base, line_base, line_range,
			minimum_instruction_length, default_is_stmt);

		return lpe;
	}

	public record SourceFileAddr(long address, String fileName, int lineNum) {}

	public List<SourceFileAddr> getAllSourceFileAddrInfo(DWARFCompilationUnit cu,
			BinaryReader reader) throws IOException {
		try (DWARFLineProgramExecutor lpe = getLineProgramexecutor(cu, reader)) {
			List<SourceFileAddr> results = new ArrayList<>();
			for (DWARFLineProgramState row : lpe.allRows()) {
				results.add(new SourceFileAddr(row.address, getFilePath(row.file, true), row.line));
			}

			return results;
		}
	}

	public DWARFFile getDir(int index) throws IOException {
		if (0 <= index && index < directories.size()) {
			return directories.get(index);
		}
		throw new IOException(
			"Invalid dir index %d for line table at 0x%x: ".formatted(index, startOffset));
	}

	/**
	 * Get a file name given a file index.
	 * 
	 * @param index index of the file
	 * @return file {@link DWARFFile}
	 * @throws IOException if invalid index
	 */
	public DWARFFile getFile(int index) throws IOException {
		if (dwarfVersion < 5) {
			if (0 < index && index <= files.size()) {
				// Retrieve the file by index (index starts at 1)
				return files.get(index - 1);
			}
		}
		else if (dwarfVersion >= 5) {
			if (0 <= index && index < files.size()) {
				return files.get(index);
			}
		}
		throw new IOException(
			"Invalid file index %d for line table at 0x%x: ".formatted(index, startOffset));
	}

	public String getFilePath(int index, boolean includePath) {
		try {
			DWARFFile f = getFile(index);
			if (!includePath) {
				return f.getName();
			}

			String dir = f.getDirectoryIndex() >= 0
					? getDir(f.getDirectoryIndex()).getName()
					: "";

			return FSUtilities.appendPath(dir, f.getName());
		}
		catch (IOException e) {
			return null;
		}
	}

	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer();
		buffer.append("Line Entry");
		buffer.append(" Include Directories: [");
		for (DWARFFile dir : this.directories) {
			buffer.append(dir);
			buffer.append(", ");
		}
		buffer.append("] File Names: [");
		for (DWARFFile file : this.files) {
			buffer.append(file.toString());
			buffer.append(", ");
		}
		buffer.append("]");
		return buffer.toString();
	}

}
