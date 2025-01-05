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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.LEB128Info;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;

public class WasmNameMap implements StructConverter {
	// this is used to avoid structure name conflict
	private String structureName;
	private LEB128Info count;
	private List<WasmAssoc> entries = new ArrayList<>();
	private Map<Long, WasmName> map = new HashMap<>();

	private static class WasmAssoc {
		LEB128Info idx;
		WasmName name;
	}

	public WasmNameMap(String structureName, BinaryReader reader) throws IOException {
		this.structureName = structureName;
		count = reader.readNext(LEB128Info::unsigned);
		for (int i = 0; i < count.asLong(); i++) {
			WasmAssoc assoc = new WasmAssoc();
			assoc.idx = reader.readNext(LEB128Info::unsigned);
			assoc.name = new WasmName(reader);
			entries.add(assoc);
			map.put(assoc.idx.asLong(), assoc.name);
		}
	}

	public String getEntry(long idx) {
		WasmName result = map.get(idx);
		if (result == null)
			return null;
		return result.getValue();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder(structureName);
		builder.addUnsignedLeb128(count, "count");
		for (int i = 0; i < entries.size(); i++) {
			WasmAssoc assoc = entries.get(i);
			builder.addUnsignedLeb128(assoc.idx, "idx" + i);
			builder.add(assoc.name, "name" + i);
		}
		return builder.toStructure();
	}
}
