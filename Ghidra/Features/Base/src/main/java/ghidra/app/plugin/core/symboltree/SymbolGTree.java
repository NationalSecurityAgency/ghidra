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
package ghidra.app.plugin.core.symboltree;

import java.awt.Color;
import java.awt.Component;

import javax.swing.*;
import javax.swing.tree.TreePath;

import docking.widgets.tree.*;
import docking.widgets.tree.support.GTreeRenderer;
import generic.theme.GIcon;
import ghidra.app.plugin.core.symboltree.nodes.SymbolCategoryNode;
import ghidra.app.plugin.core.symboltree.nodes.SymbolNode;
import ghidra.app.util.SymbolInspector;
import ghidra.program.model.symbol.Symbol;
import resources.ResourceManager;

public class SymbolGTree extends GTree {

	private GTreeNode armedNode;
	private SymbolInspector symbolInspector;

	public SymbolGTree(GTreeNode root, SymbolTreePlugin plugin) {
		super(root);
		symbolInspector = new SymbolInspector(plugin.getTool(), this);
		setShowsRootHandles(true);
		setCellRenderer(new SymbolTreeCellRenderer());

		setDragNDropHandler(new SymbolGTreeDragNDropHandler(plugin));

		setAccessibleNamePrefix("Symbol");

		setRootNodeAllowedToCollapse(false);
	}

	// open access
	@Override
	protected void setFilterRestoreState(GTreeState state) {
		super.setFilterRestoreState(state);
	}

	@Override
	public void setNodeEditable(GTreeNode node) {
		armedNode = node;
	}

	@Override
	public boolean isPathEditable(TreePath path) {
		boolean isArmed = path.getLastPathComponent() == armedNode;
		armedNode = null;
		if (isArmed) {
			return super.isPathEditable(path);
		}
		return false;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class SymbolTreeCellRenderer extends GTreeRenderer {
		public final Icon OPEN_FOLDER_GROUP_ICON =
			new GIcon("icon.plugin.symboltree.node.group.folder.open");
		public final Icon CLOSED_FOLDER_GROUP_ICON =
			new GIcon("icon.plugin.symboltree.node.group.folder.closed");

		public SymbolTreeCellRenderer() {
			setMinIconWidth(28);
		}

		@Override
		public Component getTreeCellRendererComponent(JTree tree, Object value, boolean isSelected,
				boolean expanded, boolean leaf, int row, boolean isFocused) {

			JLabel label = (JLabel) super.getTreeCellRendererComponent(tree, value, isSelected,
				expanded, leaf, row, isFocused);

			if (label.getIcon() == null) {
				label.setIcon(expanded ? OPEN_FOLDER_GROUP_ICON : CLOSED_FOLDER_GROUP_ICON);
			}

			if (!isSelected && (value instanceof SymbolNode)) {
				SymbolNode node = (SymbolNode) value;
				Symbol symbol = node.getSymbol();
				Color color = symbolInspector.getColor(symbol);
				label.setForeground(color);
			}

			return label;
		}

		@Override
		protected Icon getNodeIcon(GTreeNode node, boolean expanded) {

			Icon icon = super.getNodeIcon(node, expanded);

			if (node instanceof SymbolCategoryNode symbolNode) {
				if (!symbolNode.isEnabled()) {
					return ResourceManager.getDisabledIcon(icon);
				}
			}

			return icon;
		}
	}

	@Override
	public void dispose() {
		super.dispose();
		symbolInspector.dispose();
	}

}
