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
import ghidra.app.plugin.core.symboltree.nodes.ClassCategoryNode;
import ghidra.app.plugin.core.symboltree.nodes.SymbolNode;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class CreateClassAction extends SymbolTreeContextAction {

	public CreateClassAction(SymbolTreePlugin plugin, String group, String subGroup) {
		super("Create Class", plugin.getName());
		MenuData menuData = new MenuData(new String[] { "Create Class" }, group);
		menuData.setMenuSubGroup(subGroup);
		setPopupMenuData(menuData);
		setEnabled(false);
	}

	@Override
	protected void actionPerformed(SymbolTreeActionContext context) {
		GTree tree = (GTree) context.getContextObject();
		if (tree.isFiltered()) {
			Msg.showWarn(getClass(), tree, "Create Class Not Allowed",
				"Cannot create class while the tree is filtered!");
			return;
		}
		createNewClass(context);
	}

	@Override
	protected boolean isEnabledForContext(SymbolTreeActionContext context) {

		TreePath[] selectionPaths = context.getSelectedSymbolTreePaths();
		if (selectionPaths.length != 1) {
			return false;
		}

		Object object = selectionPaths[0].getLastPathComponent();
		if (object instanceof ClassCategoryNode) {
			return true;
		}
		else if (object instanceof SymbolNode) {
			SymbolNode symbolNode = (SymbolNode) object;
			Symbol symbol = symbolNode.getSymbol();
			SymbolType symbolType = symbol.getSymbolType();
			if (symbolType == SymbolType.NAMESPACE) {
				// allow SymbolType to perform additional checks
				Namespace parentNamespace = (Namespace) symbol.getObject();
				return SymbolType.CLASS.isValidParent(context.getProgram(), parentNamespace,
					Address.NO_ADDRESS, parentNamespace.isExternal());
			}
			return (symbolType == SymbolType.CLASS || symbolType == SymbolType.LIBRARY);
		}
		return false;
	}

	private void createNewClass(SymbolTreeActionContext context) {

		TreePath[] selectionPaths = context.getSelectedSymbolTreePaths();
		Program program = context.getProgram();
		Namespace parent = program.getGlobalNamespace();
		GTreeNode node = (GTreeNode) selectionPaths[0].getLastPathComponent();

		if (node instanceof SymbolNode) {
			Symbol symbol = ((SymbolNode) node).getSymbol();
			parent = (Namespace) symbol.getObject();
			if (parent == null) {
				return; // assume selected node has been deleted
			}
		}

		final String newClassName = createClass(program, parent);
		if (newClassName == null) {
			// error occurred
			return;
		}
		program.flushEvents();
		context.getSymbolTree().startEditing(node, newClassName);
	}

	private String createClass(Program program, Namespace parent) {
		String newClassName = "NewClass";
		int transactionID = program.startTransaction("Create Class");
		try {
			SymbolTable symbolTable = program.getSymbolTable();
			int oneUp = 0;
			Namespace namespace = null;
			while (namespace == null) {
				try {
					namespace =
						symbolTable.createClass(parent, newClassName, SourceType.USER_DEFINED);
				}
				catch (DuplicateNameException e) {
					newClassName = "NewClass(" + ++oneUp + ")";
				}
				catch (InvalidInputException e) {
					Msg.debug(this, "Failed to create class: " + e.getMessage());
					return null;
				}
			}
		}
		finally {
			program.endTransaction(transactionID, true);
		}

		return newClassName;
	}
}
