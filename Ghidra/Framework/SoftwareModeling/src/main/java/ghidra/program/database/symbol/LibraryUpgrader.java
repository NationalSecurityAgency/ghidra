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
package ghidra.program.database.symbol;

import java.io.IOException;
import java.util.*;

import db.DBRecord;
import db.RecordIterator;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Helper class for upgrading the records in the SymbolDatabaseAdapter when upgrading
 * to version 6. This version is where libraries are no longer considered namespaces. This
 * upgrade re-parents all symbols and namespaces that have a library as their parent namespace to
 * instead be parented to the global namespace. When promoting a namespace symbol, it may conflict
 * with an existing namespace already at the promoted level. In this case it will use the existing
 * namespace, possibly upgrading a generic namespace to a class namespace.
 * <P>
 * Also, sets a new library field in the symbol record for all external symbols.
 */
public class LibraryUpgrader {

	private SymbolDatabaseAdapter adapter;
	private TaskMonitor monitor;
	private Map<Long, SymbolInfo> symbolMap = new HashMap<>();
	private Set<Long> libraryIds = new HashSet<>();
	private Set<Long> externalNamespaces = new HashSet<>();
	private Map<String, SymbolInfo> nonExternalNamespaceMap = new HashMap<>();
	private Map<Long, Long> resolvedNamespaces = new HashMap<>();
	private List<Long> forRemoval = new ArrayList<>();

	public LibraryUpgrader(SymbolDatabaseAdapter adapter, TaskMonitor monitor) {
		this.adapter = adapter;
		this.monitor = monitor;
	}

	public void update() throws IOException, CancelledException {
		createSymbolMapping();		// create in memory mapping
		prepareNamespaces();		// create namespace name mapping and find external namespaces
		fixupExternalNamespaces();	// resolve external namespaces to non external namespaces
		reparentExternalSymbols();	// reparent all external symbols based on namespace re-mapping
		updateFunctionAndLabelSymbolsWithLibraryId(); // sets the library field for external symbols
		removeMergedNamespaces();	// removes any namespaces that are no longer used because they
									// were merged into another existing namespace.

	}

	private void removeMergedNamespaces() throws IOException {
		for (Long key : forRemoval) {
			adapter.removeSymbol(key);
		}
	}

	private void reparentExternalSymbols() throws IOException, CancelledException {
		for (SymbolInfo symbol : symbolMap.values()) {
			monitor.checkCancelled();
			if (resolvedNamespaces.containsKey(symbol.parentId)) {
				updateParentNamespace(symbol);
			}
		}
	}

	private void updateParentNamespace(SymbolInfo symbol) throws IOException {
		long newParentId = resolvedNamespaces.get(symbol.parentId);
		DBRecord record = adapter.getSymbolRecord(symbol.id);
		record.setLongValue(SymbolDatabaseAdapter.SYMBOL_PARENT_ID_COL, newParentId);
		adapter.updateSymbolRecord(record);
	}

	private void fixupExternalNamespaces() throws IOException, CancelledException {

		// first all library namespaces will resolve to the global namespace
		for (Long id : libraryIds) {
			resolvedNamespaces.put(id, Namespace.GLOBAL_NAMESPACE_ID);
		}

		for (Long id : externalNamespaces) {
			monitor.checkCancelled();
			resolveNamespace(id);
		}

	}

	private long resolveNamespace(Long id) throws IOException {

		if (resolvedNamespaces.containsKey(id)) {
			return resolvedNamespaces.get(id); // already resolved
		}

		SymbolInfo symbol = symbolMap.get(id);
		long resolvedParentId = resolveNamespace(symbol.parentId);
		String myPath = getNamespacePath(symbol.name, resolvedParentId);
		SymbolInfo conflict = nonExternalNamespaceMap.get(myPath);
		if (conflict == null) {
			// we can keep this namespace as it is, just mark it resolved
			resolvedNamespaces.put(id, id);
			return id;
		}
		if (conflict.type == SymbolType.NAMESPACE && symbol.type == SymbolType.CLASS) {
			upgradeType(conflict, SymbolType.CLASS);
		}
		resolvedNamespaces.put(id, conflict.id);
		forRemoval.add(id);
		return conflict.id;
	}

	private String getNamespacePath(String name, long parentId) {
		if (parentId == Namespace.GLOBAL_NAMESPACE_ID) {
			return name;
		}
		SymbolInfo parent = symbolMap.get(parentId);
		String parentPath = getNamespacePath(parent);
		return parentPath + "::" + name;
	}

	private String getNamespacePath(SymbolInfo symbol) {
		if (symbol.parentId == Namespace.GLOBAL_NAMESPACE_ID) {
			return symbol.name;
		}
		SymbolInfo parent = symbolMap.get(symbol.parentId);
		return getNamespacePath(parent) + "::" + symbol.name;
	}

	private void upgradeType(SymbolInfo symbol, SymbolType type) throws IOException {
		DBRecord record = adapter.getSymbolRecord(symbol.id);
		record.setByteValue(SymbolDatabaseAdapter.SYMBOL_TYPE_COL, type.getID());
		adapter.updateSymbolRecord(record);
	}

	private void updateFunctionAndLabelSymbolsWithLibraryId()
			throws IOException, CancelledException {

		for (SymbolInfo symbol : symbolMap.values()) {
			monitor.checkCancelled();
			if (symbol.type == SymbolType.FUNCTION || symbol.type == SymbolType.LABEL) {
				// these are the only two types than need to have the new library field set in
				// their database records
				SymbolInfo library = getLibrarySymbolContaining(symbol);
				if (library != null) {
					updateSymbolWithLibraryInfo(symbol, library);
				}
			}
			// all other symbols types should not be affected by this upgrade
		}
	}

	private void prepareNamespaces() throws CancelledException {
		for (SymbolInfo symbol : symbolMap.values()) {
			monitor.checkCancelled();
			if (symbol.type == SymbolType.NAMESPACE || symbol.type == SymbolType.CLASS) {
				if (isExternal(symbol)) {
					// track namespaces that we need to fixup
					externalNamespaces.add(symbol.id);
				}
				else {
					// otherwise create a mapping to use for resolving external namespaces
					nonExternalNamespaceMap.put(getNamespacePath(symbol), symbol);
				}
			}
		}
	}

	private void updateSymbolWithLibraryInfo(SymbolInfo symbol, SymbolInfo library)
			throws IOException {
		DBRecord record = adapter.getSymbolRecord(symbol.id);
		record.setLongValue(SymbolDatabaseAdapter.SYMBOL_LIBRARY_ID_COL, library.id);
		adapter.updateSymbolRecord(record);
	}

	private boolean isExternal(SymbolInfo symbol) {
		return getLibrarySymbolContaining(symbol) != null;
	}

	private SymbolInfo getLibrarySymbolContaining(SymbolInfo symbol) {
		long id = symbol.parentId;
		while (id != Namespace.GLOBAL_NAMESPACE_ID) {
			if (libraryIds.contains(id)) {
				return symbolMap.get(id);
			}
			SymbolInfo parentInfo = symbolMap.get(id);
			id = parentInfo.parentId;
		}
		return null;
	}

	private void createSymbolMapping() throws IOException, CancelledException {
		RecordIterator symbols = adapter.getSymbols();
		while (symbols.hasNext()) {
			monitor.checkCancelled();
			DBRecord record = symbols.next();
			long key = record.getKey();
			String name = record.getString(SymbolDatabaseAdapter.SYMBOL_NAME_COL);
			byte typeID = record.getByteValue(SymbolDatabaseAdapter.SYMBOL_TYPE_COL);
			SymbolType type = SymbolType.getSymbolType(typeID);
			long parentId = record.getLongValue(SymbolDatabaseAdapter.SYMBOL_PARENT_ID_COL);
			symbolMap.put(key, new SymbolInfo(key, name, parentId, type));
			if (type == SymbolType.LIBRARY) {
				libraryIds.add(key);
			}
		}
	}

	record SymbolInfo(long id, String name, long parentId, SymbolType type) {}
}
