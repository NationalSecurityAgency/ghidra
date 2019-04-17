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

import javax.swing.ImageIcon;
import javax.swing.tree.TreePath;

import docking.action.MenuData;
import ghidra.app.plugin.core.symboltree.*;
import ghidra.app.plugin.core.symboltree.nodes.ImportsCategoryNode;
import ghidra.app.plugin.core.symboltree.nodes.LibrarySymbolNode;
import ghidra.util.HelpLocation;

/**
 * An action in the symbol tree for creating an external location or external function.
 */
public class CreateExternalLocationAction extends SymbolTreeContextAction {
	private static ImageIcon EDIT_ICON = null;
	private final SymbolTreePlugin plugin;

	/**
	 * Creates the action for creating a new external location or external function in the 
	 * symbol tree.
	 * @param plugin the symbol tree plugin, which owns this action.
	 */
	public CreateExternalLocationAction(SymbolTreePlugin plugin) {
		super("Create External Location", plugin.getName());
		this.plugin = plugin;
		this.setPopupMenuData(
			new MenuData(new String[] { "Create External Location" }, EDIT_ICON, "0External"));

		setEnabled(true);
	}

	@Override
	public boolean isEnabledForContext(SymbolTreeActionContext context) {

		TreePath[] selectionPaths = context.getSelectedSymbolTreePaths();
		if (selectionPaths.length == 1) {
			Object object = selectionPaths[0].getLastPathComponent();
			if (object instanceof LibrarySymbolNode || object instanceof ImportsCategoryNode) {
				return true;
			}
		}
		return false;
	}

	@Override
	public void actionPerformed(SymbolTreeActionContext context) {
		TreePath[] selectionPaths = context.getSelectedSymbolTreePaths();
		if (selectionPaths.length != 1) {
			return;
		}
		Object object = selectionPaths[0].getLastPathComponent();
		if (!(object instanceof LibrarySymbolNode) && !(object instanceof ImportsCategoryNode)) {
			return;
		}

		String externalName = null;
		if (object instanceof LibrarySymbolNode) {
			LibrarySymbolNode libraryNode = (LibrarySymbolNode) object;
			externalName = libraryNode.getName();
		}

		final EditExternalLocationDialog dialog =
			new EditExternalLocationDialog(context.getProgram(), externalName);

		dialog.setHelpLocation(new HelpLocation("SymbolTreePlugin", "CreateExternalLocation"));
		plugin.getTool().showDialog(dialog);
	}
}
