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
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.core.datamgr.ArchiveManager;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.services.Recover;
import ghidra.app.services.Upgrade;
import ghidra.app.util.HelpTopics;
import ghidra.framework.main.OpenVersionedFileDialog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.dtarchive.ProjectDataTypeArchive;
import ghidra.util.HelpLocation;

/**
 * Action for opening file datatype archives.
 */
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
		PluginTool tool = plugin.getTool();
		ArchiveManager archiveManager = plugin.getArchiveManager();
		OpenVersionedFileDialog<ProjectDataTypeArchive> dialog = new OpenVersionedFileDialog<>(tool,
			"Open Project Data Type Archive", ProjectDataTypeArchive.class);
		dialog.setHelpLocation(new HelpLocation(HelpTopics.PROGRAM, "Open_File_Dialog"));
		dialog.addOkActionListener(ev -> {
			DomainFile domainFile = dialog.getDomainFile();
			int version = dialog.getVersion();
			if (domainFile == null) {
				dialog.setStatusText("Please choose a Project Data Type Archive");
			}
			else {
				dialog.close();
				archiveManager.openProjectArchiveInTask(domainFile, version, Upgrade.ASK,
					Recover.ASK, true);
			}
		});

		tool.showDialog(dialog);
	}

}
