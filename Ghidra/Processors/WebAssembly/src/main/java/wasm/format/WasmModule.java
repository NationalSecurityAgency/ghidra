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
package wasm.format;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import wasm.format.WasmEnums.WasmExternalKind;
import wasm.format.sections.WasmCodeSection;
import wasm.format.sections.WasmCustomSection;
import wasm.format.sections.WasmDataSection;
import wasm.format.sections.WasmElementSection;
import wasm.format.sections.WasmExportSection;
import wasm.format.sections.WasmFunctionSection;
import wasm.format.sections.WasmGlobalSection;
import wasm.format.sections.WasmImportSection;
import wasm.format.sections.WasmLinearMemorySection;
import wasm.format.sections.WasmNameSection;
import wasm.format.sections.WasmSection;
import wasm.format.sections.WasmSection.WasmSectionId;
import wasm.format.sections.WasmStartSection;
import wasm.format.sections.WasmTableSection;
import wasm.format.sections.WasmTypeSection;
import wasm.format.sections.structures.WasmCodeEntry;
import wasm.format.sections.structures.WasmDataSegment;
import wasm.format.sections.structures.WasmElementSegment;
import wasm.format.sections.structures.WasmExportEntry;
import wasm.format.sections.structures.WasmFuncType;
import wasm.format.sections.structures.WasmGlobalEntry;
import wasm.format.sections.structures.WasmGlobalType;
import wasm.format.sections.structures.WasmImportEntry;
import wasm.format.sections.structures.WasmResizableLimits;
import wasm.format.sections.structures.WasmTableType;

public class WasmModule {

	private WasmHeader header;
	private List<WasmSection> sections = new ArrayList<>();
	private List<WasmCustomSection> customSections = new ArrayList<>();
	private Map<WasmSectionId, WasmSection> sectionMap = new EnumMap<>(WasmSectionId.class);

	public WasmModule(BinaryReader reader) throws IOException {
		header = new WasmHeader(reader);
		while (reader.getPointerIndex() < reader.length()) {
			WasmSection section = WasmSection.createSection(reader);
			if (section == null)
				continue;
			sections.add(section);

			/* Except for custom sections, all other sections may appear at most once. */
			if (section.getId() == WasmSectionId.SEC_CUSTOM) {
				customSections.add((WasmCustomSection) section);
			} else {
				sectionMap.put(section.getId(), section);
			}
		}
	}

	public WasmHeader getHeader() {
		return header;
	}

	public List<WasmSection> getSections() {
		return sections;
	}

	public WasmSection getSection(WasmSectionId sectionId) {
		return sectionMap.get(sectionId);
	}

	// #region Sections which do not represent vectors of entries
	public List<WasmCustomSection> getCustomSections() {
		return Collections.unmodifiableList(customSections);
	}

	public WasmNameSection getNameSection() {
		for (WasmCustomSection section : customSections) {
			if (section instanceof WasmNameSection) {
				return (WasmNameSection) section;
			}
		}
		return null;
	}

	public WasmStartSection getStartSection() {
		return (WasmStartSection) sectionMap.get(WasmSectionId.SEC_START);
	}
	// #endregion

	// #region Sections which represent vectors of entries
	private WasmTypeSection getTypeSection() {
		return (WasmTypeSection) sectionMap.get(WasmSectionId.SEC_TYPE);
	}

	private WasmImportSection getImportSection() {
		return (WasmImportSection) sectionMap.get(WasmSectionId.SEC_IMPORT);
	}

	private WasmFunctionSection getFunctionSection() {
		return (WasmFunctionSection) sectionMap.get(WasmSectionId.SEC_FUNCTION);
	}

	private WasmTableSection getTableSection() {
		return (WasmTableSection) sectionMap.get(WasmSectionId.SEC_TABLE);
	}

	private WasmLinearMemorySection getLinearMemorySection() {
		return (WasmLinearMemorySection) sectionMap.get(WasmSectionId.SEC_LINEARMEMORY);
	}

	private WasmGlobalSection getGlobalSection() {
		return (WasmGlobalSection) sectionMap.get(WasmSectionId.SEC_GLOBAL);
	}

	private WasmExportSection getExportSection() {
		return (WasmExportSection) sectionMap.get(WasmSectionId.SEC_EXPORT);
	}

	private WasmElementSection getElementSection() {
		return (WasmElementSection) sectionMap.get(WasmSectionId.SEC_ELEMENT);
	}

	private WasmCodeSection getCodeSection() {
		return (WasmCodeSection) sectionMap.get(WasmSectionId.SEC_CODE);
	}

	private WasmDataSection getDataSection() {
		return (WasmDataSection) sectionMap.get(WasmSectionId.SEC_DATA);
	}

	public WasmFuncType getType(int typeidx) {
		WasmTypeSection typeSection = getTypeSection();
		if (typeSection == null) {
			throw new IndexOutOfBoundsException(typeidx);
		}
		return typeSection.getType(typeidx);
	}

	public List<WasmImportEntry> getImports(WasmExternalKind kind) {
		WasmImportSection importSection = getImportSection();
		if (importSection == null) {
			return Collections.emptyList();
		}
		return importSection.getImports(kind);
	}

	public List<WasmTableType> getNonImportedTables() {
		WasmTableSection tableSection = getTableSection();
		if (tableSection == null) {
			return Collections.emptyList();
		}
		return tableSection.getTables();
	}

	public List<WasmResizableLimits> getNonImportedMemories() {
		WasmLinearMemorySection memorySection = getLinearMemorySection();
		if (memorySection == null) {
			return Collections.emptyList();
		}
		return memorySection.getMemories();
	}

	public List<WasmGlobalEntry> getNonImportedGlobals() {
		WasmGlobalSection globalSection = getGlobalSection();
		if (globalSection == null) {
			return Collections.emptyList();
		}
		return globalSection.getEntries();
	}

	public List<WasmExportEntry> getExports(WasmExternalKind kind) {
		WasmExportSection exportSection = getExportSection();
		if (exportSection == null) {
			return Collections.emptyList();
		}
		return exportSection.getExports(kind);
	}

	public List<WasmElementSegment> getElementSegments() {
		WasmElementSection elementSection = getElementSection();
		if (elementSection == null) {
			return Collections.emptyList();
		}
		return elementSection.getSegments();
	}

	public List<WasmCodeEntry> getNonImportedFunctions() {
		WasmCodeSection codeSection = getCodeSection();
		if (codeSection == null) {
			return Collections.emptyList();
		}
		return codeSection.getFunctions();
	}

	public List<WasmDataSegment> getDataSegments() {
		WasmDataSection dataSection = getDataSection();
		if (dataSection == null) {
			return Collections.emptyList();
		}
		return dataSection.getSegments();
	}
	// #endregion

	// #region Convenience functions
	public int getFunctionCount() {
		int numFunctions = getImports(WasmExternalKind.EXT_FUNCTION).size();
		WasmFunctionSection functionSection = getFunctionSection();
		if (functionSection != null) {
			numFunctions += functionSection.getTypeCount();
		}
		return numFunctions;
	}

	public WasmFuncType getFunctionType(int funcidx) {
		List<WasmImportEntry> imports = getImports(WasmExternalKind.EXT_FUNCTION);
		if (funcidx < imports.size()) {
			return getType(imports.get(funcidx).getFunctionType());
		}
		return getType(getFunctionSection().getTypeIdx(funcidx - imports.size()));
	}

	public WasmCodeEntry getFunctionCode(int funcidx) {
		List<WasmImportEntry> imports = getImports(WasmExternalKind.EXT_FUNCTION);
		if (funcidx < imports.size()) {
			return null;
		} else {
			return getNonImportedFunctions().get(funcidx - imports.size());
		}
	}

	public WasmGlobalType getGlobalType(int globalidx) {
		List<WasmImportEntry> imports = getImports(WasmExternalKind.EXT_GLOBAL);
		if (globalidx < imports.size()) {
			return imports.get(globalidx).getGlobalType();
		}
		return getNonImportedGlobals().get(globalidx - imports.size()).getGlobalType();
	}

	public WasmTableType getTableType(int tableidx) {
		List<WasmImportEntry> imports = getImports(WasmExternalKind.EXT_TABLE);
		if (tableidx < imports.size()) {
			return imports.get(tableidx).getTableType();
		}
		return getNonImportedTables().get(tableidx - imports.size());
	}

	public WasmExportEntry findExport(WasmExternalKind kind, int idx) {
		WasmExportSection exportSection = getExportSection();
		if (exportSection == null) {
			return null;
		}
		return exportSection.findEntry(kind, idx);
	}
	// #endregion
}
