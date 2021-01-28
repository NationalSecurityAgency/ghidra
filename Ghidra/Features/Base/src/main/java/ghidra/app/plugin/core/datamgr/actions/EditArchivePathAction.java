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

import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.pathmanager.PathManager;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler;
import ghidra.framework.preferences.Preferences;
import ghidra.util.HelpLocation;

public class EditArchivePathAction extends DockingAction {

	private final DataTypeManagerPlugin plugin;

	public EditArchivePathAction(DataTypeManagerPlugin plugin) {
		super("Edit Archive Paths", plugin.getName());
		this.plugin = plugin;

// ACTIONS - auto generated
		setMenuBarData(new MenuData(new String[] { "Edit Archive Paths..." }, null, "R2"));

		setDescription("Opens the options editor for adding paths that will be searched when " +
			"attempting to locate archive files.");
		setEnabled(true);
		setHelpLocation(new HelpLocation(plugin.getName(), "Edit_Archive_Paths"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		PathManagerDialog pathManagerDialog = new PathManagerDialog();
		plugin.getTool().showDialog(pathManagerDialog);
	}

	class PathManagerDialog extends DialogComponentProvider {

		private PathManager pathManager;

		protected PathManagerDialog() {
			super("Edit Data Type Archive Paths");
			pathManager = new PathManager(false, true);
			pathManager.setFileChooserProperties("Select Archive Directory",
				Preferences.LAST_OPENED_ARCHIVE_DIRECTORY, GhidraFileChooserMode.DIRECTORIES_ONLY,
				false, null);
			setHelpLocation(new HelpLocation("DataTypeManagerPlugin", "Edit_Archive_Paths_Dialog"));

			pathManager.restoreFromPreferences(DataTypeManagerHandler.DATA_TYPE_ARCHIVE_PATH_KEY,
				null, DataTypeManagerHandler.DISABLED_DATA_TYPE_ARCHIVE_PATH_KEY);
			addWorkPanel(pathManager.getComponent());
			addOKButton();
			addCancelButton();
		}

		@Override
		protected void okCallback() {
			pathManager.saveToPreferences(DataTypeManagerHandler.DATA_TYPE_ARCHIVE_PATH_KEY,
				DataTypeManagerHandler.DISABLED_DATA_TYPE_ARCHIVE_PATH_KEY);
			close();
		}

		@Override
		public void close() {
			super.close();
			pathManager.dispose();
		}
	}

}
