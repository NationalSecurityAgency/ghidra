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

import java.util.ArrayList;
import java.util.List;

import javax.swing.SwingUtilities;
import javax.swing.tree.TreePath;

import org.apache.commons.lang3.StringUtils;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.app.plugin.core.navigation.FindAppliedDataTypesService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

public class FindReferencesToFieldAction extends DockingAction {

	private final DataTypeManagerPlugin plugin;

	public FindReferencesToFieldAction(DataTypeManagerPlugin plugin) {
		super("Find Uses of Field", plugin.getName());
		this.plugin = plugin;

		String menuGroup = "ZVeryLast"; // it's own group; on the bottom
		setPopupMenuData(new MenuData(new String[] { "Find Uses of Field..." }, null, menuGroup));

		setHelpLocation(new HelpLocation("LocationReferencesPlugin", "Data_Types"));
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
		DataType dataType = dtNode.getDataType();
		return dataType instanceof Composite;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		GTree gTree = (GTree) context.getContextObject();
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		final DataTypeNode dataTypeNode = (DataTypeNode) selectionPaths[0].getLastPathComponent();

		PluginTool tool = plugin.getTool();
		FindAppliedDataTypesService service = tool.getService(FindAppliedDataTypesService.class);

		if (service == null) {
			Msg.showError(this, null, "Missing Plugin",
				"The FindAppliedDataTypesService is not installed.\n" +
					"Please add the plugin implementing this service.");
			return;
		}

		Composite composite = (Composite) dataTypeNode.getDataType();
		DataTypeComponent[] components = composite.getDefinedComponents();
		List<String> names = new ArrayList<>();
		for (DataTypeComponent dataTypeComponent : components) {
			if (dataTypeComponent.isBitFieldComponent()) {
				continue;
			}
			String fieldName = dataTypeComponent.getFieldName();
			if (StringUtils.isBlank(fieldName)) {
				continue;
			}
			names.add(fieldName);
		}

		String[] array = names.toArray(new String[names.size()]);
		String userChoice = OptionDialog.showInputChoiceDialog(null, "Choose Field",
			"Find uses of '" + composite.getName() + "' field", array, null,
			OptionDialog.QUESTION_MESSAGE);

		if (userChoice == null) {
			return;
		}

		SwingUtilities.invokeLater(
			() -> service.findAndDisplayAppliedDataTypeAddresses(composite, userChoice));
	}

}
