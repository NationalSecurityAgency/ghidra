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

import static ghidra.app.plugin.core.symboltree.SymbolCategory.*;
import static ghidra.program.model.symbol.SymbolType.*;

import java.util.*;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import generic.theme.GIcon;
import ghidra.app.plugin.core.symboltree.SymbolCategory;
import ghidra.app.plugin.core.symboltree.SymbolTreeFilterState;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

public class SymbolTreeRootNode extends GTreeNode {
	private static Icon GLOBAL_ICON = new GIcon("icon.plugin.symboltree.node.root");
	private final String name;

	protected Program program;
	private int groupThreshold;
	private SymbolTreeFilterState filterState;

	public SymbolTreeRootNode(Program program, int groupThreshold,
			SymbolTreeFilterState filterState) {
		this.groupThreshold = groupThreshold;
		this.program = program;
		this.filterState = filterState;

		if (program == null) {
			name = "No Symbol Tree";
		}
		else {
			name = "Root";
		}
	}

	public int getNodeGroupThreshold() {
		return groupThreshold;
	}

	public int getReorganizeLimit() {
		// Arbitrary number to prevent bulk updates from triggering repeated node organization.
		// The higher the value, the longer the delay between the tree collapsing nodes to signal
		// that a re-organzation is needed.
		return groupThreshold * 2;
	}

	public Program getProgram() {
		return program;
	}

	@Override
	public List<GTreeNode> generateChildren() {
		if (program == null) {
			return Collections.emptyList();
		}

		List<GTreeNode> list = new ArrayList<>();

		if (filterState.showImports()) {
			list.add(new ImportsCategoryNode(program, filterState));
		}
		if (filterState.showExports()) {
			list.add(new ExportsCategoryNode(program, filterState));
		}
		if (filterState.showGlobals()) {
			list.add(new GlobalsCategoryNode(program, filterState));
		}
		if (filterState.showNamespaces()) {
			list.add(new NamespaceCategoryNode(program, filterState));
		}

		return list;
	}

	/**
	 * Finds the given symbol in the tree.
	 * @param symbol the symbol to search for
	 * @param loadChildren if true, then lazy nodes will be loaded before searching. Otherwise,
	 * unloaded nodes will not be searched.
	 * @param monitor a TaskMonitor that can be used to cancel the search
	 * @return the GTreeNode corresponding to the given symbol or null if the symbol is not found in
	 * the tree.
	 */
	public GTreeNode findSymbolNode(Symbol symbol, boolean loadChildren, TaskMonitor monitor) {

		//
		// The finding of nodes starts here, at the root.  Optimize searching by using the 
		// implicit knowledge of how the tree builds/stores symbols by their type:
		// -Function - search only the function nodes, no recursive searching		
		// -External function - search only the imports node, no recursive searching
		// -Params/Locals - find the function node, then search that node
		// -Classes - search the classes node, need recursive searching
		// -Namespaces - search the namespaces node, need recursive searching
		//

		SymbolType type = symbol.getSymbolType();
		if (type == FUNCTION) {
			return findFunctionRelatedSymbol(symbol, loadChildren, monitor);
		}
		else if (type == PARAMETER || type == LOCAL_VAR) {
			return findFunctionRelatedSymbol(symbol, loadChildren, monitor);
		}
		else if (type == CLASS) {
			return findClassSymbol(symbol, loadChildren, monitor);
		}
		else if (type == NAMESPACE) {
			return findNamespaceSymbol(symbol, loadChildren, monitor);
		}
		else if (type == LIBRARY) {
			return findLibrarySymbol(symbol, loadChildren, monitor);
		}
		else if (type == LABEL) {
			return findCodeSymbol(symbol, loadChildren, monitor);
		}
		//else { GLOBAL, GLOBAL_VAR } // not sure where these end up

		return null;
	}

	private GTreeNode findCodeSymbol(Symbol symbol, boolean loadChildren, TaskMonitor monitor) {

		GTreeNode node =
			searchCategories(symbol, loadChildren, monitor, IMPORTS, GLOBALS, NAMESPACES);
		return node;
	}

	private GTreeNode findNamespaceSymbol(Symbol symbol, boolean loadChildren,
			TaskMonitor monitor) {
		GTreeNode node = searchCategories(symbol, loadChildren, monitor, NAMESPACES);
		return node;
	}

	private GTreeNode findLibrarySymbol(Symbol symbol, boolean loadChildren, TaskMonitor monitor) {
		GTreeNode node = searchCategories(symbol, loadChildren, monitor, IMPORTS);
		return node;
	}

	private GTreeNode findClassSymbol(Symbol symbol, boolean loadChildren, TaskMonitor monitor) {
		GTreeNode node = searchCategories(symbol, loadChildren, monitor, NAMESPACES);
		return node;
	}

	private GTreeNode findFunctionRelatedSymbol(Symbol symbol, boolean loadChildren,
			TaskMonitor monitor) {
		GTreeNode node =
			searchCategories(symbol, loadChildren, monitor, IMPORTS, GLOBALS, NAMESPACES);
		return node;
	}

	private GTreeNode searchCategories(Symbol symbol, boolean loadChildren, TaskMonitor monitor,
			SymbolCategory... categories) {
		for (SymbolCategory category : categories) {
			SymbolCategoryNode categoryNode = getCategoryNode(category);
			if (categoryNode == null) {
				continue;
			}
			GTreeNode node = categoryNode.findSymbolNode(symbol, loadChildren, monitor);
			if (node != null) {
				return node;
			}
		}

		return null;
	}

	private SymbolCategoryNode getCategoryNode(SymbolCategory category) {
		List<GTreeNode> children = getChildren();
		for (GTreeNode child : children) {
			if (child instanceof SymbolCategoryNode categoryNode) {
				if (categoryNode.getSymbolCategory() == category) {
					return categoryNode;
				}
			}
		}
		return null; // must be filtered out
	}

	public SymbolNode symbolAdded(Symbol symbol, TaskMonitor monitor) {
		SymbolNode returnNode = null;
		List<GTreeNode> allChildren = getChildren();
		for (GTreeNode gNode : allChildren) {
			SymbolCategoryNode symbolNode = (SymbolCategoryNode) gNode;
			SymbolNode newNode = symbolNode.symbolAdded(symbol, monitor);
			if (newNode != null) {
				returnNode = newNode;  // doesn't matter which one we return
			}
		}
		return returnNode;
	}

	public void symbolRemoved(Symbol symbol, String oldName, TaskMonitor monitor) {

		// we have to loop--the symbol may exist in more than one category
		List<GTreeNode> allChildren = getChildren();
		for (GTreeNode gNode : allChildren) {
			SymbolCategoryNode categoryNode = (SymbolCategoryNode) gNode;
			categoryNode.symbolRemoved(symbol, symbol.getParentNamespace(), oldName, monitor);
		}
	}

	public void symbolRemoved(Symbol symbol, Namespace oldNamespace, TaskMonitor monitor) {
		// we have to loop--the symbol may exist in more than one category
		List<GTreeNode> allChildren = getChildren();
		for (GTreeNode gNode : allChildren) {
			SymbolCategoryNode categoryNode = (SymbolCategoryNode) gNode;
			categoryNode.symbolRemoved(symbol, oldNamespace, symbol.getName(), monitor);
		}
	}

	public void rebuild() {
		setChildren(null);
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return GLOBAL_ICON;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getToolTip() {
		return null;
	}

	@Override
	public boolean isLeaf() {
		return program == null;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (!(o instanceof SymbolTreeRootNode)) {
			return false;
		}
		SymbolTreeRootNode node = (SymbolTreeRootNode) o;
		return getName().equals(node.getName());
	}

	public void setSymbolTreeFilterState(SymbolTreeFilterState filterState) {
		this.filterState = filterState;
		reloadChildren();
	}

	private void reloadChildren() {
		setChildren(null);  // this will trigger generateChildren next time someone asks.
	}

	public SymbolTreeFilterState getSymbolTreeFilterState() {
		return filterState;
	}
}
