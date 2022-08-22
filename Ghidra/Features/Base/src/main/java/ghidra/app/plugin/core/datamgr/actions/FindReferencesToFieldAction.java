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
import ghidra.app.services.FieldMatcher;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.util.*;

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
		return dataType instanceof Composite || dataType instanceof Enum;
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

		DataType dt = dataTypeNode.getDataType();
		String[] choices = null;
		if (dt instanceof Composite) {
			choices = getCompisiteFieldNames((Composite) dt);
		}
		else if (dt instanceof Enum) {
			choices = ((Enum) dt).getNames();
		}

		String message = "Find uses of '" + dt.getName() + "' field by name or offset";
		String userChoice = OptionDialog.showEditableInputChoiceDialog(null, "Choose Field",
			message, choices, null, OptionDialog.QUESTION_MESSAGE);
		if (userChoice == null) {
			return;
		}

		FieldMatcher fieldMatcher;
		Long longChoice = parseInt(userChoice);
		if (longChoice != null) {
			fieldMatcher = new FieldMatcher(dt, longChoice.intValue());
		}
		else {
			fieldMatcher = new FieldMatcher(dt, userChoice);
		}

		Swing.runLater(() -> service.findAndDisplayAppliedDataTypeAddresses(dt, fieldMatcher));
	}

	private Long parseInt(String s) {
		return NumericUtilities.parseNumber(s, null);
	}

	private String[] getCompisiteFieldNames(Composite composite) {
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

		return names.toArray(String[]::new);
	}

}
