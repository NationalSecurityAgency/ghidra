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

import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.tasks.GTreeCollapseAllTask;
import ghidra.app.plugin.core.symboltree.SymbolCategory;
import ghidra.app.plugin.core.symboltree.SymbolTreeFilterState;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class SymbolCategoryNode extends SymbolTreeNode {

	protected SymbolCategory symbolCategory;
	protected SymbolTable symbolTable;
	protected GlobalNamespace globalNamespace;
	protected Program program;
	protected SymbolTreeFilterState filterState;

	public SymbolCategoryNode(SymbolCategory category, Program p,
			SymbolTreeFilterState filterState) {
		this.symbolCategory = category;
		this.program = p;
		this.filterState = filterState;
		this.symbolTable = p == null ? null : p.getSymbolTable();
		this.globalNamespace = p == null ? null : (GlobalNamespace) p.getGlobalNamespace();
	}

	@Override
	public final List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException {

		SymbolTreeRootNode root = (SymbolTreeRootNode) getRoot();
		if (root == null) {
			// this can happen if the tree is reloaded while we are searching in a background task
			return List.of();
		}

		List<GTreeNode> list = getSymbolNodes(monitor);
		monitor.checkCancelled();
		int groupThreshold = root.getNodeGroupThreshold();
		return OrganizationNode.organize(list, groupThreshold, monitor);
	}

	private List<GTreeNode> getSymbolNodes(TaskMonitor monitor) {
		List<GTreeNode> list = new ArrayList<>();
		SymbolIterator symbols = getPotentialSymbols();
		for (Symbol symbol : symbols) {
			if (!filterState.passesFilter(symbol)) {
				continue;
			}
			if (supportsSymbolAtCatogryRoot(symbol)) {
				list.add(SymbolNode.createNode(symbol, program));
			}
		}

		Collections.sort(list, getChildrenComparator());
		return list;
	}

	/**
	 * Return an iterator over all symbols that could potentially be at the root of this
	 * category. Generally, the best we can do is iterate over all global symbols and then
	 * those will be further filtered by the supportsSymbol() method.
	 * @return an iterator over all possible symbols for this category.
	 */
	protected SymbolIterator getPotentialSymbols() {
		return symbolTable.getSymbols(globalNamespace);
	}

	public Program getProgram() {
		return program;
	}

	@Override
	public boolean canCut() {
		return false;
	}

	@Override
	public boolean isCut() {
		return false;
	}

	public boolean isModifiable() {
		return false;
	}

	@Override
	public void setNodeCut(boolean isCut) {
		throw new UnsupportedOperationException("Cannot cut a Category node");
	}

	public SymbolCategory getSymbolCategory() {
		return symbolCategory;
	}

	@Override
	public String getName() {
		return symbolCategory.getName();
	}

	@Override
	public String getToolTip() {
		return "SymbolCategory: " + getName();
	}

	@Override
	public boolean isLeaf() {
		return false;
	}

	@Override
	public DataFlavor getNodeDataFlavor() {
		return null;
	}

	/**
	 * Returns true if this symbol is applicable for this category. This is used when symbols
	 * are added, changed, or deleted.
	 * @param symbol the symbol to test
	 * @param parentNamespace this is the current namespace of the symbol for adds or
	 * renames, but will be the old namespace when the namespace was changed
	 * @return true if this symbol is applicable for this category
	 */
	protected abstract boolean supportsSymbol(Symbol symbol, Namespace parentNamespace);

	/**
	 * Returns true if this symbol is applicable for this categories root level. It is used when
	 * generating the children for the category node.
	 * @param symbol the symbol to test
	 * @return true if this symbol should be included in this categories root children.
	 */
	protected abstract boolean supportsSymbolAtCatogryRoot(Symbol symbol);

	/**
	 * Create a list of SymbolNodes to be used to find a specific symbol within the symbol tree.
	 * <P>
	 * Each category has specific knowledge on how symbols are organized within that category, so
	 * for any symbol, it knows what search nodes to generate that will match nodes at each level
	 * down in the tree that lead to that symbol.
	 * <P> 
	 * Generally, each search node will handle one level in the tree. However, Organization nodes
	 * are handled a bit differently since they add artificial layers, so they don't get a specific
	 * search key for any levels they generate. Instead, the organization node has overridden logic 
	 * that uses special comparators to recurse down through its own unique layering structure.
	 * @param symbol the symbol being searched for
	 * @param name the name of the symbol being searched for (can be different than the symbol's 
	 * current name in the case of a rename)
	 * @param namespace the parent namespace of the symbol being searched for (can be different
	 * that the symbol's parent namespace if it was changed) 
	 * @return a list of symbol search nodes that can be used to find the desired symbol.
	 */
	protected abstract List<SymbolNode> createSearchKeys(Symbol symbol, String name,
			Namespace namespace);

	protected SymbolNode symbolAdded(Symbol symbol, TaskMonitor monitor) {
		if (!isLoaded()) {
			return null;
		}
		if (!filterState.passesFilter(symbol)) {
			return null;
		}

		if (!supportsSymbol(symbol, symbol.getParentNamespace())) {
			return null;
		}

		List<SymbolNode> keys =
			createSearchKeys(symbol, symbol.getName(), symbol.getParentNamespace());
		// we want to find the parent, so remove the last key
		keys.removeLast();
		GTreeNode parentNode = getNodeByPath(keys, false, monitor);
		if (parentNode == null) {
			return null;
		}
		return doAddSymbol(symbol, parentNode);
	}

	protected void symbolRemoved(Symbol symbol, Namespace oldNamespace, String oldName,
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

		List<SymbolNode> keys = createSearchKeys(symbol, oldName, oldNamespace);
		GTreeNode foundNode = getNodeByPath(keys, false, monitor);
		if (foundNode == null) {
			foundNode = findNodeBruteForce(symbol, monitor);
		}
		if (foundNode != null) {
			GTreeNode foundParent = foundNode.getParent();
			foundParent.removeNode(foundNode);
		}
	}

	protected final GTreeNode getNodeByPath(List<SymbolNode> keys, boolean loadChildren,
			TaskMonitor monitor) {

		SymbolTreeNode parent = this;
		for (SymbolNode key : keys) {
			if (monitor.isCancelled()) {
				return null;
			}
			SymbolTreeNode foundMatch = parent.getMatchingChild(key, loadChildren);
			if (foundMatch == null) {
				return null;
			}
			parent = foundMatch;
		}
		return parent;
	}

	protected SymbolNode doAddSymbol(Symbol symbol, GTreeNode parentNode) {
		if (!parentNode.isLoaded()) {
			return null; // the node's not open, we don't care
		}

		SymbolNode newNode = SymbolNode.createNode(symbol, program);
		doAddNode(parentNode, newNode);
		return newNode;
	}

	protected void doAddNode(GTreeNode parentNode, GTreeNode newNode) {

		SymbolTreeNode symbolTreeNode = (SymbolTreeNode) parentNode;
		Comparator<GTreeNode> comparator = symbolTreeNode.getChildrenComparator();
		List<GTreeNode> children = parentNode.getChildren();
		int index = Collections.binarySearch(children, newNode, comparator);
		if (index >= 0) { // found a match			
			GTreeNode matchingNode = parentNode.getChild(index);

			// we must handle OrganizationNodes specially, since they may be recursively defined
			if (matchingNode instanceof OrganizationNode) {
				OrganizationNode orgNode = (OrganizationNode) matchingNode;
				orgNode.insertNode(newNode);
				return;
			}
		}
		else {
			index = -index - 1;
		}

		parentNode.addNode(index, newNode);

		SymbolTreeRootNode root = (SymbolTreeRootNode) getRoot();
		int reOrgLimit = root.getReorganizeLimit();
		if (parentNode.getChildCount() > reOrgLimit) {
			GTree tree = parentNode.getTree();
			// The tree needs to be reorganized, close this category node to clear its children
			// and force a reorganization next time it is opened. Also need to clear the selection 
			// so that it doesn't re-open the category.
			tree.clearSelectionPaths();
			tree.runTask(new GTreeCollapseAllTask(tree, parentNode));
		}
	}

	/**
	 * Searches for the given symbol within this symbol category node
	 * @param symbol the symbol to search for
	 * @param loadChildren if true, will load children nodes in the tree as it searches down
	 * @param monitor the TaskMonitor that can be used to cancel the operation
	 * @return The GTreeNode that contains the symbol or null if the symbol was not found in the 
	 * tree. Note: there is a special case where an {@link MoreNode} can be returned if there
	 * are many symbols with the same name and they were represented by the MoreNode. So in cases
	 * where it is important that the node actually contains the symbol, it should be checked for.
	 */
	public GTreeNode findSymbolNode(Symbol symbol, boolean loadChildren, TaskMonitor monitor) {
		if ((!isLoaded() && !loadChildren) || monitor.isCancelled()) {
			return null;
		}
		if (!filterState.passesFilter(symbol)) {
			return null;
		}
		Namespace namespace = symbol.getParentNamespace();
		if (!supportsSymbol(symbol, namespace)) {
			return null;
		}

		String name = symbol.getName();
		List<SymbolNode> keys = createSearchKeys(symbol, name, namespace);
		return getNodeByPath(keys, loadChildren, monitor);
	}

	@Override
	public Namespace getNamespace() {
		return program.getGlobalNamespace();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null) {
			return false;
		}
		if (getClass() != o.getClass()) {
			return false;
		}
		SymbolCategoryNode node = (SymbolCategoryNode) o;
		return getName().equals(node.getName());
	}
}
