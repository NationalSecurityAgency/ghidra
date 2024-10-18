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
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;
import wasm.format.WasmModule;

public class WasmGlobalEntry implements StructConverter {

	private WasmGlobalType type;
	private ConstantExpression expr;

	public WasmGlobalEntry(BinaryReader reader) throws IOException {
		type = new WasmGlobalType(reader);
		expr = new ConstantExpression(reader);
	}

	public WasmGlobalType getGlobalType() {
		return type;
	}

	public byte[] asBytes(WasmModule module) {
		return expr.asBytes(module);
	}

	public Address asAddress(AddressFactory addressFactory, WasmModule module) {
		return expr.asAddress(addressFactory, module);
	}

	public Long asGlobalGet() {
		return expr.asGlobalGet();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder("global_entry");
		builder.add(type, "type");
		builder.add(expr, "expr");
		return builder.toStructure();
	}
}
