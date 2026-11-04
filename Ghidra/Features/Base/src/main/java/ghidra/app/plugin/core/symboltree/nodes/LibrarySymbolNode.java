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
package ghidra.app.plugin.core.symboltree.nodes;

import java.awt.datatransfer.DataFlavor;
import java.util.*;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import generic.theme.GIcon;
import ghidra.app.plugin.core.symboltree.SymbolTreeFilterState;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class LibrarySymbolNode extends SymbolNode {

	private static final Icon LIBRARY_ICON = new GIcon("icon.plugin.symboltree.node.library");

	private String tooltip;

	LibrarySymbolNode(Program program, Symbol symbol) {
		super(program, symbol);

		String name = symbol.getName();
		String externalLibraryPath = program.getExternalManager().getExternalLibraryPath(name);
		tooltip = "External Library Symbol - " + name;
		if (externalLibraryPath != null) {
			tooltip = tooltip + " - " + externalLibraryPath;
		}
	}

	/**
	 * {@return the Library represented by this node}
	 */
	public Library getLibrary() {
		return getSymbol().getLibrary();
	}

	@Override
	public List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException {
		List<GTreeNode> list = new ArrayList<>();
		if (program.isClosed()) {
			return list;
		}

		Set<Symbol> symbolsInLibrary = getSymbolsForLibrary(monitor);
		Namespace global = getGlobalNamespace();
		Map<Namespace, Set<Symbol>> map =
			ImportsNamespaceNode.organizeByNamespace(symbolsInLibrary, global);
		Set<Symbol> globalSymbols = map.computeIfAbsent(global, k -> new HashSet<>());
		for (Symbol s : globalSymbols) {
			list.add(createNode(s, program));
		}
		map.remove(global);
		for (Namespace namespace : map.keySet()) {
			list.add(new ImportsNamespaceNode(namespace, map.get(namespace), program));
		}

		sort(list);
		return list;
	}

	private Set<Symbol> getSymbolsForLibrary(TaskMonitor monitor) throws CancelledException {
		Set<Symbol> set = new HashSet<>();
		SymbolTreeFilterState filterState = getFilterState();
		Library library = (Library) symbol.getObject();
		SymbolTable symbolTable = program.getSymbolTable();
		SymbolIterator iter = symbolTable.getSymbols(library);
		for (Symbol s : iter) {
			monitor.checkCancelled();
			if (filterState.passesFilter(s)) {
				set.add(s);
			}
		}
		return set;
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return LIBRARY_ICON;
	}

	@Override
	public String getToolTip() {
		return tooltip;
	}

	@Override
	public void setNodeCut(boolean isCut) {
		throw new UnsupportedOperationException("Cannot cut a library node");
	}

	@Override
	public boolean supportsDataFlavors(DataFlavor[] dataFlavors) {
		for (DataFlavor flavor : dataFlavors) {
			if (flavor instanceof SymbolTreeDataFlavor) {
				return true;
			}
		}
		return false;
	}

	SymbolNode symbolAdded(Symbol s) {
		if (!isLoaded()) {
			return null;
		}

		Namespace topLevelNamespace =
			ImportsNamespaceNode.getTopLevelNamespace(s, getGlobalNamespace());
		// we already know that this namespace is not global, so we either have a node for it
		// or we need to add one.
		GTreeNode child = getChild(topLevelNamespace.getName());
		if (child instanceof ImportsNamespaceNode namespaceNode) {
			return namespaceNode.symbolAdded(s);
		}

		doInsertNode(new ImportsNamespaceNode(topLevelNamespace, s, program));

		// The direct parent namespace node of the symbol is not in the tree. We did add one of
		// its ancestors above, but did not add the symbol itself.
		return null;
	}

	private Namespace getGlobalNamespace() {
		// the symbol is a library which is always global
		return symbol.getParentNamespace();
	}
}
