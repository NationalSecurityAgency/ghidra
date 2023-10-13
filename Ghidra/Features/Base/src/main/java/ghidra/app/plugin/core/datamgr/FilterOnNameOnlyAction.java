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

import docking.action.MenuData;
import docking.action.ToggleDockingAction;
import docking.widgets.tree.GTreeNode;
import ghidra.util.HelpLocation;

/**
 * Allows user to filter on only the data type name.   When off, all information returned by
 * {@link GTreeNode#getDisplayText()} is used for filtering.
 */
public class FilterOnNameOnlyAction extends ToggleDockingAction {

	private final DataTypesProvider provider;

	public FilterOnNameOnlyAction(DataTypeManagerPlugin plugin, DataTypesProvider provider,
			String menuSubGroup) {
		super("Filter on Name Only", plugin.getName());
		this.provider = provider;

		setMenuBarData(new MenuData(new String[] { "Filter on Name Only" }, null, "VeryLast",
			MenuData.NO_MNEMONIC, menuSubGroup));
		setDescription("Selected indicates to use only the data type name when filtering.");

		setEnabled(true);
		setSelected(false); // default to off!

		setHelpLocation(new HelpLocation("DataTypeManagerPlugin", "Filter_Name_Only"));
	}

	@Override
	public void setSelected(boolean newValue) {
		if (isSelected() == newValue) {
			return;
		}
		super.setSelected(newValue);
		provider.setFilterOnNameOnlyCallback(newValue);
	}
}
