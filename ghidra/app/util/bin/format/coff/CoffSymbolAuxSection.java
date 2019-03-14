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

public class CoffSymbolAuxSection implements CoffSymbolAux {

	private int      sectionLength;
	private short    relocationCount;
	private short    lineNumberCount;
	private byte []  unused;

	CoffSymbolAuxSection(BinaryReader reader) throws IOException {
		sectionLength     = reader.readNextInt();
		relocationCount   = reader.readNextShort();
		lineNumberCount   = reader.readNextShort();
		unused            = reader.readNextByteArray(10);
	}

	public int getSectionLength() {
		return sectionLength;
	}

	public short getRelocationCount() {
		return relocationCount;
	}

	public short getLineNumberCount() {
		return lineNumberCount;
	}

	public byte [] getUnused() {
		return unused;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(this);
	}

}
