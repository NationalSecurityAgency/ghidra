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
import java.util.List;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import generic.theme.GIcon;
import ghidra.app.plugin.core.symboltree.SymbolCategory;
import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

public class NamespaceCategoryNode extends SymbolCategoryNode {

	public static final Icon OPEN_FOLDER_NAMESPACES_ICON =
		new GIcon("icon.plugin.symboltree.node.category.namespace.open");
	public static final Icon CLOSED_FOLDER_NAMESPACES_ICON =
		new GIcon("icon.plugin.symboltree.node.category.namespace.closed");

	public NamespaceCategoryNode(Program program) {
		super(SymbolCategory.NAMESPACE_CATEGORY, program);
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return expanded ? OPEN_FOLDER_NAMESPACES_ICON : CLOSED_FOLDER_NAMESPACES_ICON;
	}

	@Override
	protected boolean supportsSymbol(Symbol symbol) {

		if (symbol.isExternal()) {
			return false;
		}

		SymbolType symbolType = symbol.getSymbolType();
		if (symbolType == SymbolType.NAMESPACE) {
			return true;
		}

		// must be in a non-global namespace
		Namespace parentNamespace = symbol.getParentNamespace();
		return parentNamespace != null && parentNamespace != globalNamespace;
	}

	@Override
	public void symbolRemoved(Symbol symbol, Namespace oldNamespace, TaskMonitor monitor) {

		if (!isLoaded()) {
			return;
		}

		if (!supportsSymbol(symbol)) {
			return;
		}

		List<Namespace> parents = NamespaceUtils.getNamespaceParts(oldNamespace);
		GTreeNode namespaceNode = getNamespaceNode(this, parents, false, monitor);
		if (namespaceNode == null) {
			return;
		}

		SymbolNode key = SymbolNode.createKeyNode(symbol, symbol.getName(), program);
		GTreeNode foundNode = findNode(namespaceNode, key, false, monitor);
		if (foundNode == null) {
			return;
		}

		GTreeNode foundParent = foundNode.getParent();
		foundParent.removeNode(foundNode);
	}

	@Override
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
		List<Namespace> parents = NamespaceUtils.getNamespaceParts(parentNamespace);
		GTreeNode namespaceNode = getNamespaceNode(this, parents, false, monitor);
		if (namespaceNode == null) {
			return null;
		}

		return doAddSymbol(symbol, namespaceNode);
	}

	@Override
	public GTreeNode findSymbolTreeNode(SymbolNode key, boolean loadChildren, TaskMonitor monitor) {

		if ((!isLoaded() && !loadChildren) || monitor.isCancelled()) {
			return null;
		}

		Symbol symbol = key.getSymbol();
		Namespace parent = symbol.getParentNamespace();
		List<Namespace> parents = NamespaceUtils.getNamespaceParts(parent);
		GTreeNode namespaceNode = getNamespaceNode(this, parents, loadChildren, monitor);
		if (namespaceNode != null) {
			return findNode(namespaceNode, key, loadChildren, monitor);
		}

		// look in the namespace node for the given symbol
		return findNode(this, key, loadChildren, monitor);
	}

	@Override
	public boolean supportsDataFlavors(DataFlavor[] dataFlavors) {
		for (DataFlavor flavor : dataFlavors) {
			if (isSupportedLocalFlavor(flavor)) {
				return true;
			}
		}
		return false;
	}

	public boolean isSupportedLocalFlavor(DataFlavor flavor) {
		if (!isLocalDataFlavor(flavor)) {
			return false;
		}

		// we don't know how to add a class to the top-level category node
		return flavor != ClassSymbolNode.LOCAL_DATA_FLAVOR;
	}
}
