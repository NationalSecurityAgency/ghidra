/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.program.model.data.DataType;
import ghidra.util.HelpLocation;

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.MenuData;
import docking.action.ToggleDockingAction;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;

public class SetFavoriteDataTypeAction extends ToggleDockingAction {

	public SetFavoriteDataTypeAction(DataTypeManagerPlugin plugin) {
		super("Set Favorite Data Type", plugin.getName());
		setSelected(false); // make this a checkbox
		setPopupMenuData(new MenuData(new String[] { "Favorite" }, null, "VeryLast"));
		setHelpLocation(new HelpLocation("DataPlugin", "Favorites"));
		setEnabled(true);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		Object contextObject = context.getContextObject();
		GTree gTree = (GTree) contextObject;
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		if (selectionPaths.length == 0) {
			return false;
		}

		for (TreePath path : selectionPaths) {
			GTreeNode node = (GTreeNode) path.getLastPathComponent();
			if (!(node instanceof DataTypeNode)) {
				return false;
			}
		}

		boolean isFavorite = ((DataTypeNode) selectionPaths[0].getLastPathComponent()).isFavorite();
		for (TreePath path : selectionPaths) {
			DataTypeNode dataTypeNode = (DataTypeNode) path.getLastPathComponent();
			if (isFavorite != dataTypeNode.isFavorite()) {
				return false;
			}
		}

		setSelected(isFavorite); // if not enabled, then turn off selection state

		return true;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		GTree gTree = (GTree) context.getContextObject();

		TreePath[] selectionPaths = gTree.getSelectionPaths();
		for (TreePath path : selectionPaths) {
			DataTypeNode node = (DataTypeNode) path.getLastPathComponent();
			toggleFavorite(node, isSelected());
		}
	}

	private void toggleFavorite(DataTypeNode node, boolean isFavorite) {

		DataType dataType = node.getDataType();
		dataType.getDataTypeManager().setFavorite(dataType, isFavorite);
	}
}
