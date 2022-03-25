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
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;

public class WasmFunctionSection extends WasmSection {

	private LEB128 count;
	private List<LEB128> types = new ArrayList<LEB128>();

	public WasmFunctionSection(BinaryReader reader) throws IOException {
		super(reader);
		count = LEB128.readUnsignedValue(reader);
		for (int i = 0; i < count.asLong(); ++i) {
			types.add(LEB128.readUnsignedValue(reader));
		}
	}

	public int getTypeIdx(int funcidx) {
		return (int) types.get(funcidx).asLong();
	}

	public int getTypeCount() {
		return types.size();
	}

	@Override
	protected void addToStructure(StructureBuilder builder) throws DuplicateNameException, IOException {
		builder.add(count, "count");
		for (int i = 0; i < types.size(); i++) {
			builder.add(types.get(i), "function_" + i);
		}
	}

	@Override
	public String getName() {
		return ".function";
	}
}
