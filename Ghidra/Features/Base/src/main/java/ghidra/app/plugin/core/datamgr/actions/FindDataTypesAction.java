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
import ghidra.app.plugin.core.datamgr.DataTypesProvider;
import ghidra.framework.plugintool.PluginTool;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import docking.ActionContext;
import docking.action.*;
import docking.widgets.dialogs.InputDialog;

public class FindDataTypesAction extends DockingAction {

	private final DataTypeManagerPlugin plugin;

	public FindDataTypesAction(DataTypeManagerPlugin plugin) {
		super("Find Data Types", plugin.getName());
		this.plugin = plugin;

		setMenuBarData(new MenuData(new String[] { "Find Data Types by Name..." }, null,
			"VeryLast", -1, "1"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_F, InputEvent.CTRL_DOWN_MASK));

		setEnabled(true);
	}

	@Override
	public void actionPerformed(ActionContext context) {

		InputDialog inputDialog =
			new InputDialog("Find Data Types", "Please enter the search string: ");
		PluginTool tool = plugin.getTool();
		tool.showDialog(inputDialog);

		if (inputDialog.isCanceled()) {
			return;
		}

		final String searchString = inputDialog.getValue();
		String title = "Find Data Type";
		final DataTypesProvider newProvider = plugin.createProvider();
		newProvider.setIncludeDataTypeMembersInFilter(plugin.includeDataMembersInSearch());
		newProvider.setTitle(title);
		newProvider.setFilterText(searchString);
		newProvider.setVisible(true);
	}
}
