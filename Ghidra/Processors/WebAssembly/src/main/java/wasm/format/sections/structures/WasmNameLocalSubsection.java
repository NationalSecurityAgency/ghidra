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
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;

public class WasmNameLocalSubsection extends WasmNameSubsection {

	private WasmNameIndirectMap localNameMap;

	public WasmNameLocalSubsection(BinaryReader reader) throws IOException {
		super(reader);
		localNameMap = new WasmNameIndirectMap(reader);
	}

	public String getLocalName(int funcidx, int localidx) {
		return localNameMap.getEntry(funcidx, localidx);
	}

	@Override
	public void addToStructure(StructureBuilder builder) throws DuplicateNameException, IOException {
		builder.add(localNameMap, "local_names");
	}

	@Override
	public String getName() {
		return ".name.local";
	}
}
