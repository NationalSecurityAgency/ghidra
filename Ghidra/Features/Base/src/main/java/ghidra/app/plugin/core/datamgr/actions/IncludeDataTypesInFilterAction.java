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
import ghidra.util.HelpLocation;
import docking.action.MenuData;
import docking.action.ToggleDockingAction;

public class IncludeDataTypesInFilterAction extends ToggleDockingAction {

	private final DataTypesProvider provider;

	public IncludeDataTypesInFilterAction(DataTypeManagerPlugin plugin, DataTypesProvider provider) {
		super("Include Data Members in Filter", plugin.getName());
		this.provider = provider;

		setMenuBarData(new MenuData(new String[] { "Include Data Members in Filter" }, null,
			"VeryLast", MenuData.NO_MNEMONIC, "3"));
		setDescription("Selected indicates to include member names and data types in filter operations.");

		setEnabled(true);
		setSelected(false); // default to off!

		setHelpLocation(new HelpLocation("DataTypeManagerPlugin", "Filter"));
	}

	@Override
	public void setSelected(boolean newValue) {
		super.setSelected(newValue);
		provider.setIncludeDataTypeMembersInFilterCallback(newValue);
	}
}
