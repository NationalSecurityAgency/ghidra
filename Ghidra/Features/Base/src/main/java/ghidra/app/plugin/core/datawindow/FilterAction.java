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
package ghidra.app.plugin.core.datawindow;

import docking.ActionContext;
import docking.action.ToggleDockingAction;
import docking.action.ToolBarData;
import resources.Icons;

class FilterAction extends ToggleDockingAction {

	private DataWindowPlugin plugin;

	FilterAction(DataWindowPlugin plugin) {
		super("Filter Data Types", plugin.getName());
		this.plugin = plugin;
		setDescription("Filters table so only specified types are displayed");
		setToolBarData(new ToolBarData(Icons.CONFIGURE_FILTER_ICON));

		setEnabled(false); // action is disabled until a program is open
		setSelected(false); // not selected; filter is off until the user turns on
	}

	@Override
	public void actionPerformed(ActionContext context) {
		DataWindowFilterDialog dialog = new DataWindowFilterDialog(plugin);
		plugin.getTool().showDialog(dialog);

		setSelected(dialog.isFilterEnabled());
	}
}
