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

public class WasmNameIndirectMap implements StructConverter {
	private LEB128Info count;
	private List<WasmIndirectAssoc> entries = new ArrayList<>();
	private Map<Long, WasmNameMap> map = new HashMap<>();

	private static class WasmIndirectAssoc {
		LEB128Info idx;
		WasmNameMap nameMap;
	}

	public WasmNameIndirectMap(BinaryReader reader) throws IOException {
		count = reader.readNext(LEB128Info::unsigned);
		for (int i = 0; i < count.asLong(); i++) {
			WasmIndirectAssoc assoc = new WasmIndirectAssoc();
			assoc.idx = reader.readNext(LEB128Info::unsigned);
			assoc.nameMap = new WasmNameMap("namemap_func_" + i + "_locals", reader);
			entries.add(assoc);
			map.put(assoc.idx.asLong(), assoc.nameMap);
		}
	}

	public String getEntry(long idx1, long idx2) {
		WasmNameMap subMap = map.get(idx1);
		if (subMap == null)
			return null;

		return subMap.getEntry(idx2);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder("indirectnamemap");
		builder.addUnsignedLeb128(count, "count");
		for (int i = 0; i < entries.size(); i++) {
			WasmIndirectAssoc assoc = entries.get(i);
			builder.addUnsignedLeb128(assoc.idx, "idx" + i);
			builder.add(assoc.nameMap, "namemap" + i);
		}
		return builder.toStructure();
	}
}
