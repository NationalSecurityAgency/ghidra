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
package ghidra.app.plugin.core.data;

import java.awt.event.KeyEvent;

import javax.swing.KeyStroke;

import docking.action.KeyBindingData;
import docking.action.KeyBindingType;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.util.datatype.DataTypeSelectionDialog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;

/**
 * An action that allows the user to change or select a data type.
 */
public class ChooseDataTypeAction extends ListingContextAction {

	private DataPlugin plugin;
	private static final KeyStroke KEY_BINDING = KeyStroke.getKeyStroke(KeyEvent.VK_T, 0);
	private final static String ACTION_NAME = "Choose Data Type";

	public ChooseDataTypeAction(DataPlugin plugin) {
		super(ACTION_NAME, plugin.getName(), KeyBindingType.SHARED);
		this.plugin = plugin;

		initKeyStroke(KEY_BINDING);
	}

	private void initKeyStroke(KeyStroke keyStroke) {
		if (keyStroke == null) {
			return;
		}

		setKeyBindingData(new KeyBindingData(keyStroke));
	}

	@Override
	protected void actionPerformed(ListingActionContext context) {
		DataType dataType = getDataType(context);
		if (dataType != null) {
			plugin.createData(dataType, context, false, true);
		}
	}

	private DataType getDataType(ListingActionContext context) {
		PluginTool tool = plugin.getTool();
		Data data = plugin.getDataUnit(context);
		int noSizeRestriction = -1;
		DataTypeSelectionDialog selectionDialog = new DataTypeSelectionDialog(tool,
			data.getProgram().getDataTypeManager(), noSizeRestriction, AllowedDataTypes.ALL);
		DataType initialType = data.getBaseDataType();
		selectionDialog.setInitialDataType(initialType);
		tool.showDialog(selectionDialog);
		return selectionDialog.getUserChosenDataType();
	}

	@Override
	protected boolean isEnabledForContext(ListingActionContext context) {
		return plugin.isCreateDataAllowed(context);
	}
}
