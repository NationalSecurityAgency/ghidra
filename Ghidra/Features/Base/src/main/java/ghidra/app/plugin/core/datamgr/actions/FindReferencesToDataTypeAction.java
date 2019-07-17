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

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.MenuData;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.actions.AbstractFindReferencesDataTypeAction;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.program.model.data.DataType;

public class FindReferencesToDataTypeAction extends AbstractFindReferencesDataTypeAction {

	public FindReferencesToDataTypeAction(DataTypeManagerPlugin plugin) {
		super(plugin.getTool(), NAME, plugin.getName(), DEFAULT_KEY_STROKE);

		String menuGroup = "ZVeryLast"; // it's own group; on the bottom
		setPopupMenuData(new MenuData(new String[] { "Find Uses of" }, null, menuGroup));
	}

	@Override
	protected DataType getDataType(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return null;
		}

		Object contextObject = context.getContextObject();
		GTree gtree = (GTree) contextObject;
		TreePath[] selectionPaths = gtree.getSelectionPaths();
		if (selectionPaths.length != 1) {
			return null;
		}

		GTreeNode node = (GTreeNode) selectionPaths[0].getLastPathComponent();
		if (node instanceof DataTypeNode) {
			return ((DataTypeNode) node).getDataType();
		}
		return null;
	}
}
