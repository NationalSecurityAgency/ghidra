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
 * See Apple's -- PEFBinaryFormat.h
 * <pre>
 * struct PEFExportedSymbolHashSlot {
 *     UInt32              countAndStart;
 * };
 * </pre>
 */
public class ExportedSymbolHashSlot implements StructConverter {
	private int symbolCount;
	private int indexOfFirstExportKey;

	ExportedSymbolHashSlot(BinaryReader reader) throws IOException {
		int countAndStart = reader.readNextInt();

		symbolCount = countAndStart >> 18;
		indexOfFirstExportKey = countAndStart & 0x12;
	}

	public int getSymbolCount() {
		return symbolCount;
	}

	public int getIndexOfFirstExportKey() {
		return indexOfFirstExportKey;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return new TypedefDataType("ExportedSymbolHashSlot", DWORD);
	}
}
