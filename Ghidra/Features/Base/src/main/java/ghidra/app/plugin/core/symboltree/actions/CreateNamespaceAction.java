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
package ghidra.app.plugin.core.symboltree.actions;

import javax.swing.tree.TreePath;

import docking.action.MenuData;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.symboltree.SymbolTreeActionContext;
import ghidra.app.plugin.core.symboltree.SymbolTreePlugin;
import ghidra.app.plugin.core.symboltree.nodes.NamespaceCategoryNode;
import ghidra.app.plugin.core.symboltree.nodes.SymbolNode;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class CreateNamespaceAction extends SymbolTreeContextAction {

	public CreateNamespaceAction(SymbolTreePlugin plugin, String group, String subGroup) {
		super("Create Namespace", plugin.getName());
		MenuData menuData = new MenuData(new String[] { "Create Namespace" }, group);
		menuData.setMenuSubGroup(subGroup);
		setPopupMenuData(menuData);
		setEnabled(false);
	}

	@Override
	public boolean isEnabledForContext(SymbolTreeActionContext context) {
		TreePath[] selectionPaths = context.getSelectedSymbolTreePaths();
		if (selectionPaths.length != 1) {
			return false;
		}

		Object object = selectionPaths[0].getLastPathComponent();
		if (object instanceof SymbolNode) {
			SymbolNode symbolNode = (SymbolNode) object;
			Symbol symbol = symbolNode.getSymbol();
			SymbolType symbolType = symbol.getSymbolType();
			if (symbolType == SymbolType.FUNCTION) {
				return !symbol.isExternal();
			}
			return (symbolType == SymbolType.NAMESPACE || symbolType == SymbolType.CLASS ||
				symbolType == SymbolType.LIBRARY);
		}
		else if (object instanceof NamespaceCategoryNode) {
			return true;
		}

		return false;
	}

	@Override
	public void actionPerformed(SymbolTreeActionContext context) {
		GTree tree = (GTree) context.getContextObject();
		if (tree.isFiltered()) {
			Msg.showWarn(getClass(), tree, "Create Namespace Not Allowed",
				"Cannot create namespace while the tree is filtered!");
			return;
		}
		createNamespace(context);
	}

	private void createNamespace(SymbolTreeActionContext context) {

		TreePath[] selectionPaths = context.getSelectedSymbolTreePaths();

		Program program = context.getProgram();
		Namespace parent = program.getGlobalNamespace();
		GTreeNode node = (GTreeNode) selectionPaths[0].getLastPathComponent();

		if (node instanceof SymbolNode) {
			Symbol symbol = ((SymbolNode) node).getSymbol();
			parent = (Namespace) symbol.getObject();
			if (parent == null) {
				return; // assume selected symbol has been deleted
			}
		}

		String newNamespaceName = createNamespace(program, parent);
		if (newNamespaceName == null) {
			// error occurred
			return;
		}

		program.flushEvents();
		context.getSymbolTree().startEditing(node, newNamespaceName);
	}

	private String createNamespace(Program program, Namespace parent) {

		String namespaceName = "NewNamespace";
		int transactionID = program.startTransaction("Create Namespace");
		try {
			SymbolTable symbolTable = program.getSymbolTable();
			int oneUp = 0;
			namespaceName = "NewNamespace";
			Namespace namespace = null;
			while (namespace == null) {
				try {
					namespace =
						symbolTable.createNameSpace(parent, namespaceName, SourceType.USER_DEFINED);
				}
				catch (DuplicateNameException e) {
					namespaceName = "NewNamespace(" + ++oneUp + ")";
				}
				catch (InvalidInputException e) {
					Msg.debug(this, "Failed to create namespace: " + e.getMessage());
					return null;
				}
			}
		}
		finally {
			program.endTransaction(transactionID, true);
		}

		return namespaceName;
	}
}
