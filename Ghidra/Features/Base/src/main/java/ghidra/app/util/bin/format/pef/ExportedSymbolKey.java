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
package ghidra.app.util.bin.format.pef;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * See Apple's -- PEFBinaryFormat.h * Exported Symbol Hash Key
 * <pre>
 * struct PEFExportedSymbolKey {
 *     union {
 *         UInt32            fullHashWord;
 *         PEFSplitHashWord  splitHashWord;
 *     } u;
 * };
 * </pre>
 * <pre>
 * struct PEFSplitHashWord {
 *     UInt16  nameLength;
 *     UInt16  hashValue;
 * };
 * </pre>
 */
public class ExportedSymbolKey implements StructConverter {
	private int   fullHashWord;
	private short nameLength;
	private short hashValue;

	ExportedSymbolKey(BinaryReader reader) throws IOException {
		int value = reader.readNextInt();
	
		fullHashWord = value;

		nameLength = (short)(value >> 16);
		hashValue  = (short)(value & 0xffff);
	}

	public int getFullHashWord() {
		return fullHashWord;
	}
	public short getNameLength() {
		return nameLength;
	}
	public short getHashValue() {
		return hashValue;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return new TypedefDataType("ExportedSymbolKey", DWORD);
	}
}
