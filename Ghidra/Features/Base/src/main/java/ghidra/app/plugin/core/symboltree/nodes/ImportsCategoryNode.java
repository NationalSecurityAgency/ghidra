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
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import generic.theme.GIcon;
import ghidra.app.plugin.core.symboltree.SymbolCategory;
import ghidra.app.plugin.core.symboltree.SymbolTreeFilterState;
import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;
import util.CollectionUtils;

/**
 * Symbol Tree category node for showing  (external) symbols. This node displays library
 * nodes as its immediate children. Within each library node, the symbols within that library are
 * show, organized by namespace.
 */
public class ImportsCategoryNode extends SymbolCategoryNode {

	private static Icon CLOSED_FOLDER_EXTERNALS_ICON =
		new GIcon("icon.plugin.symboltree.node.category.imports.closed");
	private static Icon OPEN_FOLDER_EXTERNALS_ICON =
		new GIcon("icon.plugin.symboltree.node.category.imports.open");

	public ImportsCategoryNode(Program program, SymbolTreeFilterState filterState) {
		super(SymbolCategory.IMPORTS, program, filterState);
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return expanded ? OPEN_FOLDER_EXTERNALS_ICON : CLOSED_FOLDER_EXTERNALS_ICON;
	}

	@Override
	public String getToolTip() {
		return "Symbols for External libraries";
	}

	@Override
	protected boolean supportsSymbol(Symbol symbol, Namespace ns) {
		if (symbol.isExternal()) {
			return true;
		}

		return isInExternalFunction(symbol, ns);
	}

	@Override
	protected SymbolIterator getPotentialSymbols() {
		List<Library> libraries = program.getExternalManager().getLibraries();
		List<Symbol> symbols =
			libraries.stream().map(l -> l.getSymbol()).collect(Collectors.toList());
		return new SymbolIteratorAdapter(symbols.iterator());
	}

	@Override
	protected boolean supportsSymbolAtCatogryRoot(Symbol symbol) {
		return symbol.getSymbolType() == SymbolType.LIBRARY;
	}

	private boolean isInExternalFunction(Symbol symbol, Namespace ns) {
		if (ns instanceof Function function) {
			return function.isExternal();
		}
		return false;
	}

	@Override
	protected final SymbolNode symbolAdded(Symbol symbol, TaskMonitor monitor) {
		if (!isLoaded()) {
			return null;
		}

		if (!supportsSymbol(symbol, symbol.getParentNamespace())) {
			return null;
		}

		// global externals will work using the generic symbolAdded
		if (symbol.getParentNamespace().isGlobal()) {
			return super.symbolAdded(symbol, monitor);
		}

		// if this symbol is in a function, then normal added will work
		if (isInExternalFunction(symbol, symbol.getParentNamespace())) {
			return super.symbolAdded(symbol, monitor);
		}

		// only special case is for a new symbol in a namespace
		String libraryName = symbol.getLibrary().getName();
		LibrarySymbolNode child = (LibrarySymbolNode) getChild(libraryName);
		if (child != null) {
			return child.symbolAdded(symbol);
		}

		return null;
	}

	@Override
	protected final void symbolRemoved(Symbol symbol, Namespace oldNamespace, String oldName,
			TaskMonitor monitor) {

		if (!isLoaded()) {
			return;
		}
		if (!filterState.passesFilter(symbol)) {
			return;
		}
		if (!supportsSymbol(symbol, oldNamespace)) {
			return;
		}
		super.symbolRemoved(symbol, oldNamespace, oldName, monitor);

		// we still have to remove the symbol from any intermediate namespace nodes
		Namespace parent = symbol.getParentNamespace();
		if (parent.isGlobal()) {
			return;
		}
		List<SymbolNode> keys = createSearchKeys(symbol, oldName, oldNamespace);
		keys.removeLast();
		// key[0] is the library, all the others are intermediate namespace nodes
		while (keys.size() > 1) {
			GTreeNode foundNode = getNodeByPath(keys, false, monitor);
			if (foundNode instanceof ImportsNamespaceNode namespaceNode) {
				namespaceNode.removeSymbol(symbol);
			}
			keys.removeLast();
		}
	}

	@Override
	protected List<SymbolNode> createSearchKeys(Symbol symbol, String name, Namespace ns) {
		SymbolType type = symbol.getSymbolType();
		if (type == SymbolType.LIBRARY) {
			return CollectionUtils.asList(SearchNode.create(symbol, name));
		}

		/*
		 	The layout of the Imports category node:
		 	
		 		Imports
		 			LibraryName
		 				Function
		 					Variable
		 				Label
		 				Namespace
		 					Function
		 					Label
		 */
		List<SymbolNode> keys = new ArrayList<>();
		Library library = getLibrary(symbol, ns);
		SearchNode libraryKey = SearchNode.create(library.getSymbol(), library.getName());
		keys.add(libraryKey);

		if (isLabelOrFunction(symbol)) {
			addNamespaceKeys(ns, keys);
			keys.add(SearchNode.create(symbol, name));
			return keys;
		}

		// otherwise we have a function variable
		Symbol functionSymbol = symbol.getParentSymbol();
		addNamespaceKeys(functionSymbol.getParentNamespace(), keys);

		SearchNode functionKey = SearchNode.create(functionSymbol, functionSymbol.getName());
		keys.add(functionKey);

		SearchNode variableKey = SearchNode.create(symbol, name);
		keys.add(variableKey);
		return keys;
	}

	private void addNamespaceKeys(Namespace ns, List<SymbolNode> keys) {
		List<Namespace> parents = NamespaceUtils.getNamespaceParts(ns);
		for (Namespace parent : parents) {
			keys.add(SearchNode.create(parent));
		}

	}

	private boolean isLabelOrFunction(Symbol symbol) {
		SymbolType type = symbol.getSymbolType();
		return type == SymbolType.FUNCTION || type == SymbolType.LABEL;
	}

	private Library getLibrary(Symbol symbol, Namespace ns) {
		SymbolType type = symbol.getSymbolType();
		if (type == SymbolType.LIBRARY) {
			return (Library) symbol.getObject();
		}
		if (type == SymbolType.FUNCTION || type == SymbolType.LABEL) {
			return symbol.getLibrary();
		}
		// assume symbol is a function variable and its parent is an external function
		return ns.getSymbol().getLibrary();
	}

	@Override
	protected SymbolNode doAddSymbol(Symbol symbol, GTreeNode parentNode) {
		if (!parentNode.isLoaded()) {
			return null; // the node's not open, we don't care
		}
		SymbolNode newNode = SymbolNode.createNode(symbol, program);
		doAddNode(parentNode, newNode);
		return newNode;
	}

	@Override
	public boolean supportsDataFlavors(DataFlavor[] dataFlavors) {
		return false;
	}

}
