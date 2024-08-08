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
package wasm.format.sections;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.LEB128Info;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;
import wasm.format.WasmEnums.WasmExternalKind;
import wasm.format.sections.structures.WasmImportEntry;

public class WasmImportSection extends WasmSection {

	private LEB128Info count;
	private List<WasmImportEntry> importList = new ArrayList<>();
	private Map<WasmExternalKind, List<WasmImportEntry>> imports = new EnumMap<>(WasmExternalKind.class);

	public WasmImportSection(BinaryReader reader) throws IOException {
		super(reader);
		count = reader.readNext(LEB128Info::unsigned);
		for (int i = 0; i < count.asLong(); ++i) {
			WasmImportEntry entry = new WasmImportEntry(reader);
			WasmExternalKind kind = entry.getKind();
			if (!imports.containsKey(kind)) {
				imports.put(kind, new ArrayList<WasmImportEntry>());
			}
			imports.get(kind).add(entry);
			importList.add(entry);
		}
	}

	public List<WasmImportEntry> getImports(WasmExternalKind kind) {
		return imports.getOrDefault(kind, Collections.emptyList());
	}

	@Override
	protected void addToStructure(StructureBuilder builder) throws DuplicateNameException, IOException {
		builder.addUnsignedLeb128(count, "count");
		for (int i = 0; i < importList.size(); i++) {
			builder.add(importList.get(i), "import_" + i);
		}
	}

	@Override
	public String getName() {
		return ".import";
	}
}
