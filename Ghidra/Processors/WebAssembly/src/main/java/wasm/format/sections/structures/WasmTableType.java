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

public class WasmTableType implements StructConverter {

	private ValType elemType;
	private WasmResizableLimits limits;

	public WasmTableType(BinaryReader reader) throws IOException {
		elemType = ValType.fromByte(reader.readNextUnsignedByte());
		limits = new WasmResizableLimits(reader);
	}

	public ValType getElementType() {
		return elemType;
	}

	public DataType getElementDataType() {
		return elemType.asDataType();
	}

	public WasmResizableLimits getLimits() {
		return limits;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder("table_type");
		builder.add(BYTE, "element_type");
		builder.add(limits, "limits");
		return builder.toStructure();
	}
}
