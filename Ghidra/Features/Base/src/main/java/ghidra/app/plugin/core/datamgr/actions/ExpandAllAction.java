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

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.*;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import resources.Icons;

/**
 * This action handles recursively expanding the selected nodes in the dataTypes tree.
 *
 */
public class ExpandAllAction extends DockingAction {

	public ExpandAllAction(DataTypeManagerPlugin plugin) {
		super("Expand All", plugin.getName());

		setPopupMenuData(new MenuData(new String[] { "Expand" }, Icons.EXPAND_ALL_ICON, "Tree"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_DOWN, InputEvent.ALT_DOWN_MASK));

		setEnabled(true);
		setDescription("Recursively expand all selected nodes.");
	}

	@Override
	/**
	 * Only shows up if all selected nodes are expandable.
	 */
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		Object contextObject = context.getContextObject();
		GTree gtree = (GTree) contextObject;
		TreePath[] selectionPaths = gtree.getSelectionPaths();

		if (selectionPaths.length == 0) {
			return false;
		}

		for (TreePath path : selectionPaths) {
			GTreeNode node = (GTreeNode) path.getLastPathComponent();
			if (node.isLeaf()) {
				return false;
			}
		}
		return true;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		GTree gTree = (GTree) context.getContextObject();
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		for (TreePath path : selectionPaths) {
			GTreeNode node = (GTreeNode) path.getLastPathComponent();
			gTree.expandTree(node);
		}
	}
}
