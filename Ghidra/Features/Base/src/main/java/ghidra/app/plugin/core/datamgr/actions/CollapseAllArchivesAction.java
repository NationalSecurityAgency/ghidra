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
package ghidra.app.plugin.core.datamgr.actions;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.List;

import javax.swing.ImageIcon;
import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.*;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.tree.ArchiveRootNode;
import ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree;
import resources.Icons;

/**
 * This action handles recursively collapsing nodes in the dataTypes tree.  If invoked from the
 * local toolbar icon, it collapses all nodes in the tree.  If invoked from the popup, it only
 * collapses the selected nodes.
 *
 */
public class CollapseAllArchivesAction extends DockingAction {

	private ImageIcon collapseIcon = Icons.COLLAPSE_ALL_ICON;
	private final DataTypeManagerPlugin plugin;

	public CollapseAllArchivesAction(DataTypeManagerPlugin plugin) {
		super("Collapse All", plugin.getName());
		this.plugin = plugin;

		updatePopupMenu(false);
		setToolBarData(new ToolBarData(collapseIcon, null));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_UP, InputEvent.ALT_DOWN_MASK));
		setEnabled(true);
		setDescription("Collapse All Data Types for Program and Archives");
	}

	private void updatePopupMenu(boolean isSingleNodeSelected) {
		if (isSingleNodeSelected) {
			setPopupMenuData(new MenuData(new String[] { "Collapse" }, collapseIcon, "Tree"));
		}
		else {
			setPopupMenuData(new MenuData(new String[] { "Collapse All" }, collapseIcon, "Tree"));
		}
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		Object contextObject = context.getContextObject();
		GTree gtree = (GTree) contextObject;
		TreePath[] selectionPaths = gtree.getSelectionPaths();

		boolean hasLeaf = isLeafNodeSelection(selectionPaths);
		if (hasLeaf) {
			// don't add to menu when the only item selected has no children
			return selectionPaths.length != 1;
		}

		return true;
	}

	@Override
	/**
	 * Only shows up if all selected nodes are collapsable.
	 */
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			updatePopupMenu(false);
			return false;
		}

		Object contextObject = context.getContextObject();
		GTree gtree = (GTree) contextObject;
		TreePath[] selectionPaths = gtree.getSelectionPaths();

		if (selectionPaths.length == 0) {
			updatePopupMenu(false); // Collapse All when nothing is selected
		}
		else if (selectionPaths.length == 1) {
			updatePopupMenu(true); // collapse single node with children
		}
		else {
			updatePopupMenu(false); // Collapse All when multiple nodes
		}

		return true;
	}

	private boolean isLeafNodeSelection(TreePath[] selectionPaths) {
		for (TreePath path : selectionPaths) {
			GTreeNode node = (GTreeNode) path.getLastPathComponent();
			if (node.isLeaf()) {
				return true;
			}
		}
		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		// This actions does double duty.  When invoked from the icon, it closes all nodes.
		// When invoked from the popup, it only closes selected nodes.

		if (!(context instanceof DataTypesActionContext)) {
			collapseAll(plugin.getProvider().getGTree()); // on the toolbar or filter field--collapse all
		}

		DataTypesActionContext dataTypeContext = (DataTypesActionContext) context;
		if (dataTypeContext.isToolbarAction()) {
			collapseAll(plugin.getProvider().getGTree()); // on the toolbar or filter field--collapse all
		}
		else {
			DataTypeArchiveGTree gtree = (DataTypeArchiveGTree) context.getContextObject();
			TreePath[] selectionPaths = gtree.getSelectionPaths();
			if (selectionPaths == null || selectionPaths.length != 1) {
				// no paths selected; close all paths
				collapseAll(plugin.getProvider().getGTree());
			}

			if (selectionPaths != null) {
				for (TreePath path : selectionPaths) {
					GTreeNode node = (GTreeNode) path.getLastPathComponent();
					if (node instanceof ArchiveRootNode) { // if the root is selected collapseAll
						collapseAll(gtree);
						return;
					}
					gtree.collapseAll(node);
				}
			}
		}
	}

	private void collapseAll(GTree archiveGTree) {
		GTreeNode rootNode = archiveGTree.getViewRoot();
		List<GTreeNode> children = rootNode.getChildren();
		for (GTreeNode childNode : children) {
			archiveGTree.collapseAll(childNode);
		}
	}
}
