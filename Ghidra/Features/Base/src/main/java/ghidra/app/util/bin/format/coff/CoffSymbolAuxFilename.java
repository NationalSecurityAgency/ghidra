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

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

public class CoffSymbolAuxFilename implements CoffSymbolAux {

	private byte [] filename;
	private byte [] unused;

	CoffSymbolAuxFilename(BinaryReader reader, short magic) throws IOException {
		filename = reader.readNextByteArray(CoffConstants.FILE_NAME_LENGTH);
		if (magic == CoffMachineType.IMAGE_FILE_MACHINE_I960ROMAGIC ||
				magic == CoffMachineType.IMAGE_FILE_MACHINE_I960RWMAGIC) {
			unused   = reader.readNextByteArray(10);
		} else {
			unused   = reader.readNextByteArray(4);
		}
	}

	public String getFilename() {
		return new String(filename);
	}

	public byte [] getUnused() {
		return unused;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(this);
	}
}
