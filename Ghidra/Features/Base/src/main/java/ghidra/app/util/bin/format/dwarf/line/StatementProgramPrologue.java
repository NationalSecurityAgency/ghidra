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

import ghidra.app.util.bin.BinaryReader;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class StatementProgramPrologue {
	public final static int TOTAL_LENGTH_FIELD_LEN = 4;
	public final static int PRE_PROLOGUE_LEN = 4 + 2 + 4;

	private int        totalLength;
	private short      version;
	private int        prologueLength;
	private byte       minimumInstructionLength;
	private boolean    defaultIsStatement;
	private byte       lineBase;
	private byte       lineRange;
	private byte       opcodeBase;
	private byte []    standardOpcodeLengths;

	private List<String>     includeDirectories = new ArrayList<String>();
	private List<FileEntry>  fileNames          = new ArrayList<FileEntry>();

	public StatementProgramPrologue(BinaryReader reader) throws IOException {
		totalLength                = reader.readNextInt();
		version                    = reader.readNextShort();

		if (version != 2) {
			throw new IllegalStateException("Only DWARF v2 is supported.");
		}

		prologueLength             = reader.readNextInt();
		minimumInstructionLength   = reader.readNextByte();
		defaultIsStatement         = reader.readNextByte() != 0;
		lineBase                   = reader.readNextByte();
		lineRange                  = reader.readNextByte();
		opcodeBase                 = reader.readNextByte();
		standardOpcodeLengths      = reader.readNextByteArray(opcodeBase - 1);

		while (true) {
			String dir = reader.readNextAsciiString();
			if (dir.length() == 0) {
				break;
			}
			includeDirectories.add(dir);
		}

		while (true) {
			FileEntry entry = new FileEntry(reader);
			if (entry.getFileName().length() == 0) {
				break;
			}
			fileNames.add(entry);
		}
	}

	/**
	 * Returns the size in bytes of the statement information for this 
	 * compilation unit (not including the total_length field itself).
	 * @return size in bytes of the statement information
	 */
	public int getTotalLength() {
		return totalLength;
	}
	/**
	 * Returns the version identifier for the statement information format.
	 * @return the version identifier for the statement information format
	 */
	public int getVersion() {
		return version & 0xffff;
	}
	/**
	 * Returns the number of bytes following the prologue_length field to the 
	 * beginning of the first byte of the statement program itself.
	 * @return the number of bytes following the prologue_length
	 */
	public int getPrologueLength() {
		return prologueLength;
	}
	/**
	 * Returns the size in bytes of the smallest target machine instruction. 
	 * Statement program opcodes that alter the address register first 
	 * multiply their operands by this value.
	 * @return the size in bytes of the smallest target machine instruction
	 */
	public int getMinimumInstructionLength() {
		return minimumInstructionLength & 0xff;
	}
	/**
	 * Returns the initial value of the is_stmt register.
	 * @return the initial value of the is_stmt register
	 */
	public boolean isDefaultIsStatement() {
		return defaultIsStatement;
	}
	/**
	 * Returns the line base value.
	 * This parameter affects the meaning of the special opcodes. See below.
	 * @return the line base value
	 */
	public int getLineBase() {
		return lineBase & 0xff;
	}
	/**
	 * Returns the line range value.
	 * This parameter affects the meaning of the special opcodes. See below.
	 * @return the line range value
	 */
	public int getLineRange() {
		return lineRange & 0xff;
	}
	/**
	 * Returns the number assigned to the first special opcode.
	 * @return the number assigned to the first special opcode
	 */
	public int getOpcodeBase() {
		return opcodeBase & 0xff;
	}
	/**
	 * return the array for each of the standard opcodes
	 * @return the array for each of the standard opcodes
	 */
	public byte [] getStandardOpcodeLengths() {
		return standardOpcodeLengths;
	}
	/**
	 * @return each path that was searched for included source files
	 */
	public List<String> getIncludeDirectories() {
		return includeDirectories;
	}
	/**
	 * @return an entry for each source file that contributed to the statement
	 */
	public List<FileEntry> getFileNames() {
		return fileNames;
	}
	/**
	 * Returns the file entry at the given index.
	 * @param fileIndex the file index
	 * @return the file entry at the given index
	 */
	public FileEntry getFileNameByIndex(int fileIndex) {
		return fileNames.get(fileIndex - 1);
	}
	/**
	 * The directory index represents an entry in the 
	 * include directories section. If the directoryIndex
	 * is LEB128(0), then the file was found in the current
	 * directory.
	 * @param directoryIndex the directory index
	 * @return the directory or current directory
	 */
	public String getDirectoryByIndex(long directoryIndex) {
		if (directoryIndex == 0) {
			return ".";
		}
		return includeDirectories.get((int)directoryIndex - 1);
	}
}
