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
import ghidra.framework.options.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.ToolConstants;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;

/**
 * An action that allows the user to change or select a data type.
 */
public class ChooseDataTypeAction extends DockingAction implements OptionsChangeListener {
	private static final KeyStroke KEY_BINDING = KeyStroke.getKeyStroke(KeyEvent.VK_T, 0);
	private final static String ACTION_NAME = "Choose Data Type";

	private FunctionPlugin plugin;

	public ChooseDataTypeAction(FunctionPlugin plugin) {
		super(ACTION_NAME, plugin.getName(), false);

		this.plugin = plugin;

		// setup key binding management
		PluginTool tool = plugin.getTool();
		DockingAction action = new DummyKeyBindingsOptionsAction(ACTION_NAME, KEY_BINDING);
		tool.addAction(action);

		// setup options to know when the dummy key binding is changed
		ToolOptions options = tool.getOptions(ToolConstants.KEY_BINDINGS);
		KeyStroke keyStroke = options.getKeyStroke(action.getFullName(), KEY_BINDING);
		setPopupMenu(plugin.getDataActionMenuName(null), true);

		if (!KEY_BINDING.equals(keyStroke)) {
			// user-defined keystroke
			setUnvalidatedKeyBindingData(new KeyBindingData(keyStroke));
		}
		else {
			setKeyBindingData(new KeyBindingData(keyStroke));
		}

		options.addOptionsChangeListener(this);
		setHelpLocation(new HelpLocation("DataTypeEditors", "DataTypeSelectionDialog"));
	}

	@Override
	public void optionsChanged(ToolOptions options, String name, Object oldValue, Object newValue) {
		KeyStroke keyStroke = (KeyStroke) newValue;
		if (name.startsWith(ACTION_NAME)) {
			setUnvalidatedKeyBindingData(new KeyBindingData(keyStroke));
		}
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
			setPopupMenu(plugin.getDataActionMenuName(location), true);
			return true;
		}
		if (location instanceof VariableLocation) {
			setPopupMenu(plugin.getDataActionMenuName(location), false);
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
			if (storage.isValid()) {
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

	private void setPopupMenu(String name, boolean isSignatureAction) {
		setPopupMenuData(new MenuData(
			new String[] { FunctionPlugin.SET_DATA_TYPE_PULLRIGHT, "Choose Data Type..." }, null,
			"Array"));
	}
}
