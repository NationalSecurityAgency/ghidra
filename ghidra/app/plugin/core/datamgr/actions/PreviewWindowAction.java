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

public class PreviewWindowAction extends ToggleDockingAction {

	private final DataTypesProvider provider;

	public PreviewWindowAction(DataTypeManagerPlugin plugin, DataTypesProvider provider) {
		super("Show Preview Window", plugin.getName());
		this.provider = provider;

		setMenuBarData(new MenuData(new String[] { "Preview Window" }, null, "RefreshAfter")); // put after the refresh item

		setDescription("Toggled on shows a window containing a preview of the selected data type.");
		setEnabled(true);

		setHelpLocation(new HelpLocation("DataTypeManagerPlugin", "Preview_Window"));
	}

	@Override
	public void setSelected(boolean newValue) {
		super.setSelected(newValue);
		provider.setPreviewWindowVisible(newValue);
	}
}
