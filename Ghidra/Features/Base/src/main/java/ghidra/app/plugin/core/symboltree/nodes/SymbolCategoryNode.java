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

import docking.widgets.tree.*;
import ghidra.app.plugin.core.symboltree.SymbolCategory;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public abstract class SymbolCategoryNode extends GTreeSlowLoadingNode implements SymbolTreeNode {
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
		if (list.size() > MAX_CHILD_NODES) {
			list = OrganizationNode.organize(list, MAX_CHILD_NODES, monitor);
		}
		return list;
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
		SymbolIterator it =
			globalOnly ? symbolTable.getSymbols(globalNamespace) : symbolTable.getSymbolIterator();
		while (it.hasNext()) {
			Symbol s = it.next();
			if (s != null && (s.getSymbolType() == symbolType)) {
				monitor.checkCanceled();
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

	public void symbolAdded(Symbol symbol) {

		if (!isChildrenLoadedOrInProgress()) {
			return;
		}

		if (!supportsSymbol(symbol)) {
			return;
		}

		GTreeNode parentNode = this;
		if (symbol.isGlobal()) {
			doAddSymbol(symbol, parentNode);
			return;
		}

		Namespace parentNamespace = symbol.getParentNamespace();
		Symbol namespaceSymbol = parentNamespace.getSymbol();
		SymbolNode key = SymbolNode.createNode(namespaceSymbol, program);
		parentNode = findSymbolTreeNode(key, false, TaskMonitorAdapter.DUMMY_MONITOR);
		if (parentNode == null) {
			return;
		}

		doAddSymbol(symbol, parentNode);
	}

	protected void doAddSymbol(Symbol symbol, GTreeNode parentNode) {
		if (!((AbstractGTreeNode) parentNode).isChildrenLoadedOrInProgress()) {
			return; // the node's not open, we don't care
		}

		SymbolNode newNode = SymbolNode.createNode(symbol, program);
		doAddNode(parentNode, newNode);
	}

	protected void doAddNode(GTreeNode parentNode, GTreeNode newNode) {

		SymbolTreeNode symbolTreeNode = (SymbolTreeNode) parentNode;
		Comparator<GTreeNode> comparator = symbolTreeNode.getChildrenComparator();
		List<GTreeNode> children = parentNode.getAllChildren();
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
	}

	public void symbolRemoved(Symbol symbol, TaskMonitor monitor) {
		symbolRemoved(symbol, symbol.getName(), monitor);
	}

	public void symbolRemoved(Symbol symbol, String oldName, TaskMonitor monitor) {
		if (!isChildrenLoadedOrInProgress()) {
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
