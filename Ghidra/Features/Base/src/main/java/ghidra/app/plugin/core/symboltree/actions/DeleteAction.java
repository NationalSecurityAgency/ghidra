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
import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;
import javax.swing.tree.TreePath;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.symboltree.SymbolTreeActionContext;
import ghidra.app.plugin.core.symboltree.SymbolTreePlugin;
import ghidra.app.plugin.core.symboltree.nodes.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import resources.Icons;

public class DeleteAction extends SymbolTreeContextAction {

	private final static Icon DELETE_ICON = Icons.DELETE_ICON;

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
			if (!(object instanceof SymbolNode) &&
				!(object instanceof OrganizationNode)) {
				// can only delete symbol nodes or the fake organization nodes, as those are just 
				// small groups of symbols
				return false;
			}
		}

		return true;
	}

	@Override
	public void actionPerformed(SymbolTreeActionContext context) {
		TreePath[] selectionPaths = context.getSelectedSymbolTreePaths();
		List<SymbolTreeNode> nodes = getNodes(selectionPaths);
		Program program = plugin.getProgram();
		program.withTransaction("Delete Symbols(s)", () -> {
			for (SymbolTreeNode node : nodes) {
				Symbol symbol = node.getSymbol();
				symbol.delete();
				node.getParent().removeNode(node);
			}
		});
	}

	private List<SymbolTreeNode> getNodes(TreePath[] paths) {
		List<SymbolTreeNode> nodes = new ArrayList<>();
		for (TreePath treePath : paths) {
			Object object = treePath.getLastPathComponent();
			if (object instanceof SymbolNode symbolNode) {
				nodes.add(symbolNode);
			}
			else if (object instanceof OrganizationNode orgNode) {
				getNodes(orgNode, nodes);
			}
		}
		return nodes;
	}

	private void getNodes(OrganizationNode orgNode, List<SymbolTreeNode> nodes) {
		List<GTreeNode> children = orgNode.getChildren();
		for (GTreeNode node : children) {
			if (node instanceof SymbolNode symbolNode) {
				nodes.add(symbolNode);
			}
			else if (node instanceof OrganizationNode childOrgNode) {
				getNodes(childOrgNode, nodes);
			}

		}
	}
}
