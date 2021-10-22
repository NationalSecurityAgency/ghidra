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

import java.awt.event.KeyEvent;

import docking.ActionContext;
import docking.DockingUtils;
import docking.action.*;
import docking.widgets.dialogs.InputDialog;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;

public class FindDataTypesByNameAction extends DockingAction {

	public static final String NAME = "Find Data Types by Name";

	private final DataTypeManagerPlugin plugin;

	public FindDataTypesByNameAction(DataTypeManagerPlugin plugin, String menuSubGroup) {
		super("Find Data Types by Name", plugin.getName());
		this.plugin = plugin;

		setMenuBarData(new MenuData(new String[] { NAME + "..." }, null,
			"VeryLast", -1, menuSubGroup));
		setKeyBindingData(
			new KeyBindingData(KeyEvent.VK_F, DockingUtils.CONTROL_KEY_MODIFIER_MASK));
		setHelpLocation(new HelpLocation("DataTypeManagerPlugin", "Find_Data_Types_By_Name"));
	}

	@Override
	public void actionPerformed(ActionContext context) {

		InputDialog inputDialog =
			new InputDialog(NAME, "Please enter the search string: ");
		PluginTool tool = plugin.getTool();
		tool.showDialog(inputDialog);
		if (inputDialog.isCanceled()) {
			return;
		}

		String searchString = inputDialog.getValue();
		DataTypesProvider newProvider = plugin.createProvider();
		newProvider.setIncludeDataTypeMembersInFilter(plugin.includeDataMembersInSearch());
		newProvider.setTitle(NAME);
		newProvider.setFilterText(searchString);
		newProvider.setVisible(true);
	}
}
