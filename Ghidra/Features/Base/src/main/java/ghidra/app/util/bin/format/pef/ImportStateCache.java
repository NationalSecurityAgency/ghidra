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
package ghidra.app.util.bin.format.pef;

import java.util.*;

import ghidra.app.cmd.label.AddUniqueLabelCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.AssertException;

public class ImportStateCache {
	private Program program;
	private SymbolTable symbolTable;
	private Namespace importNamespace;
	private Namespace tVectNamespace;
	private Map<ImportedLibrary, Namespace> libraryNamespaceMap =
		new HashMap<ImportedLibrary, Namespace>();
	private Map<ImportedLibrary, Map<String, Symbol>> librarySymbolsMap =
		new HashMap<ImportedLibrary, Map<String, Symbol>>();
	private Map<SectionHeader, MemoryBlock> sectionMap = new HashMap<SectionHeader, MemoryBlock>();
	private Address tocAddress;

	public ImportStateCache(Program program, ContainerHeader header) {
		this.program = program;
		this.symbolTable = program.getSymbolTable();
		this.importNamespace = createNamespace(null, PefConstants.IMPORT);
		this.tVectNamespace = createNamespace(null, PefConstants.TVECT);

		LoaderInfoHeader loader = header.getLoader();
		List<ImportedLibrary> libraries = loader.getImportedLibraries();
		for (ImportedLibrary library : libraries) {
			String libraryName = SymbolUtilities.replaceInvalidChars(library.getName(), true);
			Namespace libraryNamespace = createNamespace(importNamespace, libraryName);
			libraryNamespaceMap.put(library, libraryNamespace);
			librarySymbolsMap.put(library, new HashMap<String, Symbol>());
		}
	}

	public void dispose() {
		libraryNamespaceMap.clear();
		librarySymbolsMap.clear();
	}

	public Namespace getTVectNamespace() {
		return tVectNamespace;
	}

	/**
	 * Returns a namespace for the given imported library.
	 * @param library the imported library
	 * @return a namespace for the given imported library
	 */
	public Namespace getNamespace(ImportedLibrary library) {
		return libraryNamespaceMap.get(library);
	}

	/**
	 * Returns the memory block for the given section.
	 * Generally sections do not specify a preferred address
	 * and are not named. This map provides a way to lookup
	 * the block that was created for the given section.
	 * @param section the PEF section header
	 * @return the memory block for the given section
	 */
	public MemoryBlock getMemoryBlockForSection(SectionHeader section) {
		return sectionMap.get(section);
	}

	public void setMemoryBlockForSection(SectionHeader section, MemoryBlock block) {
		if (sectionMap.containsKey(section)) {
			throw new AssertException();
		}
		sectionMap.put(section, block);
	}

	/**
	 * Returns the symbol object with the given name in the specified library.
	 * @param symbolName the desired symbol's name
	 * @param library the desired library
	 * @return the symbol object with the given name in the specified library
	 */
	public Symbol getSymbol(String symbolName, ImportedLibrary library) {
		Map<String, Symbol> map = librarySymbolsMap.get(library);
		return map.get(symbolName);
	}

	public boolean createLibrarySymbol(ImportedLibrary library, String symbolName,
			Address address) {
		Namespace libraryNamespace = getNamespace(library);
		AddUniqueLabelCmd cmd =
			new AddUniqueLabelCmd(address, symbolName, libraryNamespace, SourceType.IMPORTED);
		boolean success = cmd.applyTo(program);
		Symbol symbol = cmd.getNewSymbol();
		Map<String, Symbol> map = librarySymbolsMap.get(library);
		map.put(symbolName, symbol);
		return success;
	}

	private Namespace createNamespace(Namespace parent, String name) {
		Namespace namespace = symbolTable.getNamespace(name, parent);
		if (namespace != null) {
			return namespace;
		}
		try {
			return program.getSymbolTable().createNameSpace(parent, name, SourceType.IMPORTED);
		}
		catch (Exception e) {
			return program.getGlobalNamespace();
		}
	}

	public Address getTocAddress() {
		return tocAddress;
	}

	public void setTocAddress(Address tocAddress) {
		this.tocAddress = tocAddress;
	}
}
