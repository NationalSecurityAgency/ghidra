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
package wasm.format;

import java.io.IOException;
import java.util.Arrays;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

public class WasmHeader implements StructConverter {

	private byte[] magic;
	private int version;

	public WasmHeader(BinaryReader reader) throws IOException {
		magic = reader.readNextByteArray(WasmConstants.WASM_MAGIC.length);
		version = reader.readNextInt();
		if (!Arrays.equals(WasmConstants.WASM_MAGIC, magic)) {
			throw new IOException("not a wasm file.");
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder("header");
		builder.add(STRING, 4, "magic");
		builder.add(DWORD, 4, "version");
		return builder.toStructure();
	}

	public byte[] getMagic() {
		return magic;
	}

	public int getVersion() {
		return version;
	}
}
