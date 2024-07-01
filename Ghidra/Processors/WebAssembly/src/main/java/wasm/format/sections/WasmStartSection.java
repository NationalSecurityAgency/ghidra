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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.LEB128Info;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;

public class WasmStartSection extends WasmSection {

	private LEB128Info funcIdx;

	public WasmStartSection(BinaryReader reader) throws IOException {
		super(reader);
		funcIdx = reader.readNext(LEB128Info::unsigned);
	}

	public long getStartFunctionIndex() {
		return funcIdx.asLong();
	}

	@Override
	public void addToStructure(StructureBuilder builder) throws DuplicateNameException, IOException {
		builder.addUnsignedLeb128(funcIdx, "func");
	}

	@Override
	public String getName() {
		return ".start";
	}
}
