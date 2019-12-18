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

public class CoffSymbolAuxBeginningOfBlock implements CoffSymbolAux {

	private byte [] unused1;
	private short   sourceLineNumber;
	private byte [] unused2;
	private int     nextEntryIndex;
	private byte [] unused3;

	CoffSymbolAuxBeginningOfBlock(BinaryReader reader) throws IOException {
		unused1          = reader.readNextByteArray(4);
		sourceLineNumber = reader.readNextShort();
		unused2          = reader.readNextByteArray(5);
		nextEntryIndex   = reader.readNextInt();
		unused3          = reader.readNextByteArray(2);
	}

	public byte[] getUnused1() {
		return unused1;
	}

	public short getSourceLineNumber() {
		return sourceLineNumber;
	}

	public byte[] getUnused2() {
		return unused2;
	}

	public int getNextEntryIndex() {
		return nextEntryIndex;
	}

	public byte[] getUnused3() {
		return unused3;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(this);
	}
}
