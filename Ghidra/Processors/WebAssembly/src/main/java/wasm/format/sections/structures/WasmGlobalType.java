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
package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;
import wasm.format.WasmEnums.ValType;

public class WasmGlobalType implements StructConverter {

	private ValType type;
	private int mutability;

	public WasmGlobalType(BinaryReader reader) throws IOException {
		type = ValType.fromByte(reader.readNextUnsignedByte());
		mutability = reader.readNextUnsignedByte();
	}

	public ValType getType() {
		return type;
	}

	public int getMutability() {
		return mutability;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder("global_type");
		builder.add(BYTE, "type");
		builder.add(BYTE, "mutability");
		return builder.toStructure();
	}
}
