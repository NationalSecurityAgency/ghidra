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
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;
import wasm.format.sections.structures.WasmNameLocalSubsection;
import wasm.format.sections.structures.WasmNameMapSubsection;
import wasm.format.sections.structures.WasmNameModuleSubsection;
import wasm.format.sections.structures.WasmNameSubsection;
import wasm.format.sections.structures.WasmNameSubsection.WasmNameSubsectionId;;

public class WasmNameSection extends WasmCustomSection {
	private List<WasmNameSubsection> subsections = new ArrayList<>();
	private Map<WasmNameSubsectionId, WasmNameSubsection> subsectionMap = new EnumMap<>(WasmNameSubsectionId.class);

	public WasmNameSection(BinaryReader reader) throws IOException {
		super(reader);
		long sectionEnd = getSectionOffset() + getSectionSize();
		while (reader.getPointerIndex() < sectionEnd) {
			WasmNameSubsection subsection = WasmNameSubsection.createSubsection(reader);
			if (subsection == null)
				continue;
			subsections.add(subsection);
			if (subsection.getId() != null)
				subsectionMap.put(subsection.getId(), subsection);
		}
	}

	@Override
	protected void addToStructure(StructureBuilder builder) throws DuplicateNameException, IOException {
		super.addToStructure(builder);
		for (int i = 0; i < subsections.size(); i++) {
			builder.add(subsections.get(i), subsections.get(i).getName());
		}
	}

	public String getModuleName() {
		WasmNameSubsection subsection = subsectionMap.get(WasmNameSubsectionId.NAME_MODULE);
		if (subsection == null)
			return null;
		return ((WasmNameModuleSubsection) subsection).getModuleName();
	}

	public String getFunctionName(int idx) {
		WasmNameSubsection subsection = subsectionMap.get(WasmNameSubsectionId.NAME_FUNCTION);
		if (subsection == null)
			return null;
		return ((WasmNameMapSubsection) subsection).getName(idx);
	}

	public String getLocalName(int funcidx, int localidx) {
		WasmNameSubsection subsection = subsectionMap.get(WasmNameSubsectionId.NAME_LOCAL);
		if (subsection == null)
			return null;
		return ((WasmNameLocalSubsection) subsection).getLocalName(funcidx, localidx);
	}

	public String getGlobalName(int idx) {
		WasmNameSubsection subsection = subsectionMap.get(WasmNameSubsectionId.NAME_GLOBAL);
		if (subsection == null)
			return null;
		return ((WasmNameMapSubsection) subsection).getName(idx);
	}

	public String getDataName(int idx) {
		WasmNameSubsection subsection = subsectionMap.get(WasmNameSubsectionId.NAME_DATA);
		if (subsection == null)
			return null;
		return ((WasmNameMapSubsection) subsection).getName(idx);
	}

	@Override
	public String getName() {
		return ".name";
	}
}
