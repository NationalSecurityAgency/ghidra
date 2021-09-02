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
import ghidra.util.task.TaskMonitorAdapter;

public abstract class SymbolCategoryNode extends SymbolTreeNode {
	public static final int MAX_NODES_BEFORE_ORGANIZING = 40;
	public static final int MAX_NODES_BEFORE_CLOSING = 200;

	protected SymbolCategory symbolCategory;
	protected SymbolTable symbolTable;
	protected GlobalNamespace globalNamespace;
	protected Program program;

	// dummy constructor for no program
	protected SymbolCategoryNode() {
		symbolCategory = null;
		symbolTable = null;
		globalNamespace = null;
		program = null;
	}

	public SymbolCategoryNode(SymbolCategory symbolCategory, Program program) {
		this.symbolCategory = symbolCategory;
		this.program = program;
		this.symbolTable = program.getSymbolTable();
		this.globalNamespace = (GlobalNamespace) program.getGlobalNamespace();
	}

	@Override
	public List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException {
		SymbolType symbolType = symbolCategory.getSymbolType();
		List<GTreeNode> list = getSymbols(symbolType, monitor);
		monitor.checkCanceled();
		return OrganizationNode.organize(list, MAX_NODES_BEFORE_ORGANIZING, monitor);
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
			monitor.checkCanceled();
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

	public SymbolNode symbolAdded(Symbol symbol) {

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
		parentNode = findSymbolTreeNode(key, false, TaskMonitorAdapter.DUMMY_MONITOR);
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
			GTreeNode matchingNode = getChild(index);

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
		if (parentNode.isLoaded() && parentNode.getChildCount() > MAX_NODES_BEFORE_CLOSING) {
			GTree tree = parentNode.getTree();
			// tree needs to be reorganized, close this category node to clear its children
			// and force a reorganization next time it is opened
			// also need to clear the selection so that it doesn't re-open the category
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

		SymbolNode key = SymbolNode.createKeyNode(symbol, oldName, program);
		GTreeNode foundNode = findSymbolTreeNode(key, false, monitor);
		if (foundNode == null) {
			return;
		}

		GTreeNode foundParent = foundNode.getParent();
		foundParent.removeNode(foundNode);
	}

	protected boolean supportsSymbol(Symbol symbol) {
		if (!symbol.isGlobal() || symbol.isExternal()) {
			return false;
		}
		SymbolType symbolType = symbol.getSymbolType();
		return symbolType == symbolCategory.getSymbolType();
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
