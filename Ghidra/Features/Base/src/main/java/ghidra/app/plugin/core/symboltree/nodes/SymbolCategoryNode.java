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

	protected boolean isEnabled = true;

	public SymbolCategoryNode(SymbolCategory symbolCategory, Program p) {
		this.symbolCategory = symbolCategory;
		this.program = p;
		this.symbolTable = p == null ? null : p.getSymbolTable();
		this.globalNamespace = p == null ? null : (GlobalNamespace) p.getGlobalNamespace();
	}

	public void setEnabled(boolean enabled) {
		if (isEnabled == enabled) {
			return;
		}

		isEnabled = enabled;
		unloadChildren();

		GTree gTree = getTree();
		if (gTree != null) {
			SymbolCategoryNode modelNode = (SymbolCategoryNode) gTree.getModelNode(this);
			if (this != modelNode) {
				modelNode.setEnabled(enabled);
			}
		}
	}

	public boolean isEnabled() {
		return isEnabled;
	}

	@Override
	public List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException {
		if (!isEnabled) {
			return Collections.emptyList();
		}

		SymbolType symbolType = symbolCategory.getSymbolType();
		List<GTreeNode> list = getSymbols(symbolType, monitor);
		monitor.checkCancelled();
		SymbolTreeRootNode root = (SymbolTreeRootNode) getRoot();
		int groupThreshold = root.getNodeGroupThreshold();
		return OrganizationNode.organize(list, groupThreshold, monitor);
	}

	public Program getProgram() {
		return program;
	}

	protected List<GTreeNode> getSymbols(SymbolType type, TaskMonitor monitor)
			throws CancelledException {
		return getSymbols(type, true, monitor);
	}

	protected List<GTreeNode> getSymbols(SymbolType type, boolean globalOnly, TaskMonitor monitor)
			throws CancelledException {
		List<GTreeNode> list = new ArrayList<>();

		SymbolType symbolType = symbolCategory.getSymbolType();
		monitor.initialize(symbolTable.getNumSymbols());
		SymbolIterator it =
			globalOnly ? symbolTable.getSymbols(globalNamespace) : symbolTable.getSymbolIterator();
		while (it.hasNext()) {
			Symbol s = it.next();
			monitor.incrementProgress(1);
			monitor.checkCancelled();
			if (s != null && (s.getSymbolType() == symbolType)) {
				list.add(SymbolNode.createNode(s, program));
			}
		}
		Collections.sort(list, getChildrenComparator());
		return list;
	}

	@Override
	public boolean canCut() {
		return false;
	}

	@Override
	public boolean canPaste(List<GTreeNode> pastedNodes) {
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

	@Override
	public boolean supportsDataFlavors(DataFlavor[] dataFlavors) {
		for (DataFlavor flavor : dataFlavors) {
			if (isLocalDataFlavor(flavor)) {
				return true;
			}
		}
		return false;
	}

	protected boolean isLocalDataFlavor(DataFlavor dataFlavor) {
		return dataFlavor == CodeSymbolNode.LOCAL_DATA_FLAVOR ||
			dataFlavor == FunctionSymbolNode.LOCAL_DATA_FLAVOR ||
			dataFlavor == NamespaceSymbolNode.LOCAL_DATA_FLAVOR ||
			dataFlavor == ClassSymbolNode.LOCAL_DATA_FLAVOR;
	}

	protected abstract boolean supportsSymbol(Symbol symbol);

	public SymbolNode symbolAdded(Symbol symbol, TaskMonitor monitor) {

		if (!isLoaded()) {
			return null;
		}

		if (!supportsSymbol(symbol)) {
			return null;
		}

		GTreeNode parentNode = this;
		if (symbol.isGlobal()) {
			return doAddSymbol(symbol, parentNode);
		}

		Namespace parentNamespace = symbol.getParentNamespace();
		Symbol namespaceSymbol = parentNamespace.getSymbol();
		SymbolNode key = SymbolNode.createNode(namespaceSymbol, program);
		parentNode = findSymbolTreeNode(key, false, monitor);
		if (parentNode == null) {
			return null;
		}

		return doAddSymbol(symbol, parentNode);
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
		if (!parentNode.isLoaded()) {
			return;
		}

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

	public void symbolRemoved(Symbol symbol, TaskMonitor monitor) {
		symbolRemoved(symbol, symbol.getName(), monitor);
	}

	public void symbolRemoved(Symbol symbol, String oldName, TaskMonitor monitor) {
		if (!isLoaded()) {
			return;
		}

		if (!supportsSymbol(symbol)) {
			return;
		}

		SymbolNode key = SymbolNode.createKeyNode(symbol, oldName, program);
		GTreeNode foundNode = findSymbolTreeNode(key, false, monitor);
		if (foundNode == null) {
			return;
		}

		GTreeNode foundParent = foundNode.getParent();
		foundParent.removeNode(foundNode);
	}

	public void symbolRemoved(Symbol symbol, Namespace oldNamespace, TaskMonitor monitor) {
		// Most categories will treat a symbol moved as a remove; symbolAdded() will get called 
		// after this to restore the symbol.  Subclasses that depend on scope will override this 
		// method.
		symbolRemoved(symbol, monitor);
	}

	/**
	 * Returns the last Namespace tree node in the given path of namespaces.  Each Namespace in the
	 * list from 0 to n will be used to find the last tree node, starting at the given parent
	 * node. 
	 * 
	 * @param parentNode the node at which to start the search
	 * @param namespaces the list of namespaces to traverse.
	 * @param loadChildren true to load children if they have not been loaded
	 * @param monitor the task monitor
	 * @return the namespace node or null if it is not open in the tree
	 */
	protected GTreeNode getNamespaceNode(GTreeNode parentNode, List<Namespace> namespaces,
			boolean loadChildren, TaskMonitor monitor) {

		if (!loadChildren && !parentNode.isLoaded() || monitor.isCancelled()) {
			return null;
		}

		if (namespaces.isEmpty()) {
			return null;
		}

		Namespace namespace = namespaces.remove(0);
		Symbol nsSymbol = namespace.getSymbol();
		SymbolNode key = SymbolNode.createKeyNode(nsSymbol, nsSymbol.getName(), program);
		GTreeNode namespaceNode = findNode(parentNode, key, loadChildren, monitor);
		if (namespaceNode == null || namespaces.isEmpty()) {
			return namespaceNode; // we hit the last namespace
		}

		// move to the next namespace
		return getNamespaceNode(namespaceNode, namespaces, loadChildren, monitor);
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
		if (getClass() != o.getClass()) {
			return false;
		}
		SymbolCategoryNode node = (SymbolCategoryNode) o;
		return getName().equals(node.getName());
	}
}
