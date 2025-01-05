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
import ghidra.app.util.bin.LEB128Info;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;
import wasm.format.WasmEnums.WasmExternalKind;

public class WasmExportEntry implements StructConverter {

	private WasmName name;
	private WasmExternalKind kind;
	private LEB128Info index;

	public WasmExportEntry(BinaryReader reader) throws IOException {
		name = new WasmName(reader);
		kind = WasmExternalKind.values()[reader.readNextByte()];
		index = reader.readNext(LEB128Info::unsigned);
	}

	public String getName() {
		return name.getValue();
	}

	public int getIndex() {
		return (int) index.asLong();
	}

	public WasmExternalKind getKind() {
		return kind;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder("export_" + getIndex());
		builder.add(name, "name");
		builder.add(BYTE, "kind");
		builder.addUnsignedLeb128(index, "index");
		return builder.toStructure();
	}
}
