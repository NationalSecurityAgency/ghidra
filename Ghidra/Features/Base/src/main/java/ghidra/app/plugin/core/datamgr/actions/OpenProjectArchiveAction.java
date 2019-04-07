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
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

public class OpenProjectArchiveAction extends DockingAction {

	private final DataTypeManagerPlugin plugin;

	public OpenProjectArchiveAction(DataTypeManagerPlugin plugin) {
		super("Open Project Data Type Archive", plugin.getName());
		this.plugin = plugin;

// ACTIONS - auto generated
		setMenuBarData(new MenuData(new String[] { "Open Project Archive..." }, null, "Archive"));

		setDescription("Opens a project data type archive in this data type manager.");
		setEnabled(true);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		plugin.openProjectDataTypeArchive();
	}

}
