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
package ghidra.app.plugin.core.function;

import java.awt.event.KeyEvent;

import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.action.*;
import ghidra.app.context.ListingActionContext;
import ghidra.app.util.datatype.DataTypeSelectionDialog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;

/**
 * An action that allows the user to change or select a data type.
 */
public class ChooseDataTypeAction extends DockingAction {
	private static final KeyStroke KEY_BINDING = KeyStroke.getKeyStroke(KeyEvent.VK_T, 0);
	private final static String ACTION_NAME = "Choose Data Type";

	private FunctionPlugin plugin;

	public ChooseDataTypeAction(FunctionPlugin plugin) {
		super(ACTION_NAME, plugin.getName(), KeyBindingType.SHARED);
		this.plugin = plugin;

		setPopupMenuData(new MenuData(
			new String[] { FunctionPlugin.SET_DATA_TYPE_PULLRIGHT, "Choose Data Type..." }, null,
			"Array"));
		setHelpLocation(new HelpLocation("DataTypeEditors", "DataTypeSelectionDialog"));

		initKeyStroke(KEY_BINDING);
	}

	private void initKeyStroke(KeyStroke keyStroke) {
		if (keyStroke == null) {
			return;
		}

		setKeyBindingData(new KeyBindingData(keyStroke));
	}

	@Override
	public void actionPerformed(ActionContext actionContext) {
		ListingActionContext context = (ListingActionContext) actionContext.getContextObject();
		createDataType(context);
	}

	@Override
	public boolean isEnabledForContext(ActionContext actionContext) {
		if (!(actionContext.getContextObject() instanceof ListingActionContext)) {
			return false;
		}

		ListingActionContext context = (ListingActionContext) actionContext.getContextObject();
		if (context.hasSelection()) {
			return false;
		}

		ProgramLocation location = context.getLocation();
		if (plugin.isValidDataLocation(location)) {
			return true;
		}
		if (location instanceof VariableLocation) {
			return true;
		}
		return false;
	}

	private void createDataType(ListingActionContext context) {
		int maxSize = getSelectedVariableStorageSize(context);

		DataType dataType = getUserSelectedDataType(context, maxSize);
		if (dataType != null) {
			plugin.createData(dataType, context, false, true);
		}
	}

	/**
	 * Returns the storage size of the variable at the current cursor location in the
	 * given listing/program.
	 * 
	 * @return -1 if the selected item in the listing is not a variable type
	 */
	private int getSelectedVariableStorageSize(ListingActionContext context) {
		ProgramLocation loc = context.getLocation();

		if (loc instanceof VariableTypeFieldLocation) {
			Variable var = ((VariableTypeFieldLocation) loc).getVariable();
			Function func = var.getFunction();
			if ((var instanceof Parameter) && !func.hasCustomVariableStorage()) {
				return -1; // do not constrain size
			}

			VariableStorage storage = var.getVariableStorage();
			if (storage.isValid() && !storage.isStackStorage()) {
				return storage.size();
			}
		}

		return -1;
	}

	private DataType getUserSelectedDataType(ListingActionContext context, int maxStorageSize) {
		PluginTool tool = plugin.getTool();
		DataTypeManager dataTypeManager = context.getProgram().getDataTypeManager();
		DataTypeSelectionDialog selectionDialog =
			showSelectionDialog(context, maxStorageSize, tool, dataTypeManager);
		return selectionDialog.getUserChosenDataType();
	}

	private DataTypeSelectionDialog showSelectionDialog(ListingActionContext context,
			int maxStorageSize, PluginTool tool, DataTypeManager dataTypeManager) {
		DataTypeSelectionDialog selectionDialog = new DataTypeSelectionDialog(tool, dataTypeManager,
			maxStorageSize, AllowedDataTypes.FIXED_LENGTH);
		DataType currentDataType = plugin.getCurrentDataType(context);
		selectionDialog.setInitialDataType(currentDataType);
		tool.showDialog(selectionDialog);
		return selectionDialog;
	}
}
