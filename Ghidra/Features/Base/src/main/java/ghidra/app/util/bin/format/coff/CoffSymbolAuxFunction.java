/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.bin.format.coff;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class CoffSymbolAuxFunction implements CoffSymbolAux {

	private int     tagIndex;
	private int     size;
	private int     filePointerToLineNumber;
	private int     nextEntryIndex;
	private byte [] unused;

	CoffSymbolAuxFunction(BinaryReader reader) throws IOException {
		tagIndex                = reader.readNextInt();
		size                    = reader.readNextInt();
		filePointerToLineNumber = reader.readNextInt();
		nextEntryIndex          = reader.readNextInt();
		unused                  = reader.readNextByteArray(2);
	}

	public int getTagIndex() {
		return tagIndex;
	}

	public int getSize() {
		return size;
	}

	public int getFilePointerToLineNumber() {
		return filePointerToLineNumber;
	}

	public int getNextEntryIndex() {
		return nextEntryIndex;
	}

	public byte[] getUnused() {
		return unused;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(this);
	}
}
