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
package ghidra.app.plugin.core.datamgr;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.util.HelpLocation;

public class ShowDataTypesTableAction extends DockingAction {

	public static final String NAME = "Show Data Types Table";

	private DataTypeManagerPlugin plugin;

	ShowDataTypesTableAction(DataTypeManagerPlugin plugin, String menuSubGroup) {
		super(NAME, plugin.getName());
		this.plugin = plugin;

		setMenuBarData(
			new MenuData(new String[] { NAME }, null, "VeryLast", -1, menuSubGroup));

		setHelpLocation(new HelpLocation("DataTypeManagerPlugin", "Data_Types_Table"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		plugin.showDataTypesTable();
	}
}
