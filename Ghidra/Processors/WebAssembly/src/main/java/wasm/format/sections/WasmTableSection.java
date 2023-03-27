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
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.LEB128Info;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;
import wasm.format.sections.structures.WasmTableType;

public class WasmTableSection extends WasmSection {

	private LEB128Info count;
	private List<WasmTableType> tables = new ArrayList<WasmTableType>();

	public WasmTableSection(BinaryReader reader) throws IOException {
		super(reader);
		count = reader.readNext(LEB128Info::unsigned);
		for (int i = 0; i < count.asLong(); ++i) {
			tables.add(new WasmTableType(reader));
		}
	}

	public List<WasmTableType> getTables() {
		return Collections.unmodifiableList(tables);
	}

	@Override
	protected void addToStructure(StructureBuilder builder) throws DuplicateNameException, IOException {
		builder.addUnsignedLeb128(count, "count");
		for (int i = 0; i < tables.size(); i++) {
			builder.add(tables.get(i), "table_" + i);
		}
	}

	@Override
	public String getName() {
		return ".table";
	}
}
