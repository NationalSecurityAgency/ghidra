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

import java.awt.event.KeyEvent;

import javax.swing.Icon;
import javax.swing.tree.TreePath;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.plugin.core.symboltree.SymbolTreeActionContext;
import ghidra.app.plugin.core.symboltree.SymbolTreePlugin;
import ghidra.app.plugin.core.symboltree.nodes.SymbolNode;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import resources.ResourceManager;

public class DeleteAction extends SymbolTreeContextAction {

	private final static Icon DELETE_ICON = ResourceManager.loadImage("images/edit-delete.png");

	private final SymbolTreePlugin plugin;

	public DeleteAction(SymbolTreePlugin plugin) {
		super("Delete Symbols", plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(new MenuData(new String[] { "Delete" }, DELETE_ICON, "xxx",
			MenuData.NO_MNEMONIC, "2"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_DELETE, 0));
	}

	@Override
	public boolean isEnabledForContext(SymbolTreeActionContext context) {
		TreePath[] selectionPaths = context.getSelectedSymbolTreePaths();
		if (selectionPaths.length == 0) {
			return false;
		}

		for (TreePath treePath : selectionPaths) {
			Object object = treePath.getLastPathComponent();
			if (!(object instanceof SymbolNode)) {
				return false; // can only delete symbol nodes
			}
		}

		return true;
	}

	@Override
	public void actionPerformed(SymbolTreeActionContext context) {
		TreePath[] selectionPaths = context.getSelectedSymbolTreePaths();
		Program program = plugin.getProgram();
		int transactionID = program.startTransaction("Delete Symbol(s)");
		try {
			for (TreePath treePath : selectionPaths) {
				SymbolNode symbolNode = (SymbolNode) treePath.getLastPathComponent();
				Symbol symbol = symbolNode.getSymbol();
				symbol.delete();
				symbolNode.getParent().removeNode(symbolNode);
			}
		}
		finally {
			program.endTransaction(transactionID, true);
		}
	}
}
