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
import ghidra.app.plugin.core.symboltree.*;
import ghidra.app.plugin.core.symboltree.nodes.ImportsCategoryNode;
import ghidra.app.plugin.core.symboltree.nodes.SymbolTreeRootNode;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class CreateLibraryAction extends SymbolTreeContextAction {

	private SymbolTreePlugin plugin;

	public CreateLibraryAction(SymbolTreePlugin plugin) {
		super("Create Library", plugin.getName());
		this.plugin = plugin;
		setPopupMenuData(new MenuData(new String[] { "Create Library" }, "0External"));
		setEnabled(false);
	}

	@Override
	public void dispose() {
		this.plugin = null;
		super.dispose();
	}

	@Override
	public boolean isEnabledForContext(SymbolTreeActionContext context) {

		TreePath[] selectionPaths = context.getSelectedSymbolTreePaths();
		if (selectionPaths.length == 1) {
			Object object = selectionPaths[0].getLastPathComponent();
			if (object instanceof ImportsCategoryNode || object instanceof SymbolTreeRootNode) {
				return true;
			}
		}
		return false;
	}

	@Override
	public void actionPerformed(SymbolTreeActionContext context) {
		GTree tree = (GTree) context.getContextObject();
		if (tree.isFiltered()) {
			Msg.showWarn(getClass(), tree, "Create Library Not Allowed",
				"Cannot create library name while the tree is filtered!");
			return;
		}
		createExternalLibrary(context);
	}

	private void createExternalLibrary(SymbolTreeActionContext context) {

		TreePath[] selectionPaths = context.getSelectedSymbolTreePaths();

		Program program = context.getProgram();
		GTreeNode node = (GTreeNode) selectionPaths[0].getLastPathComponent();

		if (node instanceof SymbolTreeRootNode) {
			node = node.getChild("Imports");
		}

		String newExternalLibraryName = createExternalLibrary(program);
		if (newExternalLibraryName == null) {
			return;
		}

		SymbolTreeProvider provider = plugin.getProvider();
		provider.editNode(node, newExternalLibraryName);
	}

	private String createExternalLibrary(Program program) {

		return program.withTransaction("Create Library", () -> {
			SymbolTable symbolTable = program.getSymbolTable();
			int oneUp = 0;
			String importName = "NewLibrary";
			Library library = null;
			while (library == null) {
				try {
					library =
						symbolTable.createExternalLibrary(importName, SourceType.USER_DEFINED);
				}
				catch (DuplicateNameException e) {
					importName = "NewLibrary(" + ++oneUp + ")";
				}
				catch (InvalidInputException e) {
					Msg.debug(this, "Failed to create library name: " + e.getMessage());
					return null;
				}
			}
			return importName;
		});
	}
}
