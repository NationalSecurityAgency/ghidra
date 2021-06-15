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
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.symboltree.*;
import ghidra.app.plugin.core.symboltree.nodes.SymbolNode;
import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.InvalidInputException;

/**
 * Symbol tree action for converting a namespace to a class
 */
public class ConvertToClassAction extends SymbolTreeContextAction {

	private static final String NAME = "Convert to Class";

	public ConvertToClassAction(SymbolTreePlugin plugin, String group, String subGroup) {
		super(NAME, plugin.getName());
		MenuData menuData = new MenuData(new String[] { NAME }, group);
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
			return symbol.getSymbolType() == SymbolType.NAMESPACE;
		}
		return false;
	}

	@Override
	protected void actionPerformed(SymbolTreeActionContext context) {
		TreePath[] selectionPaths = context.getSelectedSymbolTreePaths();

		Program program = context.getProgram();
		GTreeNode node = (GTreeNode) selectionPaths[0].getLastPathComponent();

		SymbolGTree tree = context.getSymbolTree();
		GTreeNode root = tree.getViewRoot();
		GTreeNode classesNode = root.getChild(SymbolCategory.CLASS_CATEGORY.getName());

		Symbol symbol = ((SymbolNode) node).getSymbol();
		Namespace namespace = (Namespace) symbol.getObject();
		if (namespace != null) {
			String name = namespace.getName();
			convertToClass(program, namespace);
			program.flushEvents();
			context.getSymbolTree().startEditing(classesNode, name);
		}
	}

	private static void convertToClass(Program program, Namespace ns) {
		int id = program.startTransaction(NAME);
		boolean success = false;
		try {
			NamespaceUtils.convertNamespaceToClass(ns);
			success = true;
		}
		catch (InvalidInputException e) {
			// This is thrown when the provided namespace is a function
			// It was checked in isEnabledForContext and thus cannot occur
			throw new AssertException(e);
		}
		finally {
			program.endTransaction(id, success);
		}
	}

}
