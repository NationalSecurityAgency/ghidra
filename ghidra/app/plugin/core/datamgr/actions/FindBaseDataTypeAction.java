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

import javax.swing.SwingUtilities;
import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;

public class FindBaseDataTypeAction extends DockingAction {

	private DataTypeManagerPlugin plugin;

	public FindBaseDataTypeAction(DataTypeManagerPlugin plugin) {
		super("Show Base Data Type", plugin.getName());
		this.plugin = plugin;

		String menuGroup = "ZVeryLast"; // it's own group; on the bottom
		setPopupMenuData(new MenuData(new String[] { "Show Base Data Type" }, null, menuGroup));

		setEnabled(true);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		Object contextObject = context.getContextObject();
		GTree gtree = (GTree) contextObject;
		TreePath[] selectionPaths = gtree.getSelectionPaths();
		if (selectionPaths.length != 1) {
			return false;
		}

		GTreeNode node = (GTreeNode) selectionPaths[0].getLastPathComponent();
		if (!(node instanceof DataTypeNode)) {
			return false;
		}

		DataTypeNode dtNode = (DataTypeNode) node;
		DataType dt = dtNode.getDataType();
		return dt instanceof TypeDef || dt instanceof Array || dt instanceof Pointer;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		GTree gTree = (GTree) context.getContextObject();
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		DataTypeNode dataTypeNode = (DataTypeNode) selectionPaths[0].getLastPathComponent();
		final DataType baseDataType = DataTypeUtils.getBaseDataType(dataTypeNode.getDataType());

		PluginTool tool = plugin.getTool();
		final DataTypeManagerService service = tool.getService(DataTypeManagerService.class);

		SwingUtilities.invokeLater(() -> service.setDataTypeSelected(baseDataType));
	}
}
