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
import generic.util.Path;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler;
import ghidra.framework.model.DomainFile;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;

/**
 * Class for action to open a recently opened data type archive.
 */
public class RecentlyOpenedArchiveAction extends DockingAction {

	private final String projectName; // only used for project archive path
	private final String archivePath;
	private final DataTypeManagerPlugin plugin;

	public RecentlyOpenedArchiveAction(DataTypeManagerPlugin plugin, String archivePath,
			String menuGroup) {
		this(plugin, archivePath, getDisplayPath(archivePath), menuGroup);
	}

	public RecentlyOpenedArchiveAction(DataTypeManagerPlugin plugin, String archivePath,
			String displayedPath, String menuGroup) {
		super(menuGroup + ": \"" + archivePath + "\"", plugin.getName(), false);
		this.plugin = plugin;
		String[] projectPathname = DataTypeManagerHandler.parseProjectPathname(archivePath);
		if (projectPathname == null) {
			this.projectName = null;
			this.archivePath = archivePath;
		}
		else {
			this.projectName = projectPathname[0];
			this.archivePath = projectPathname[1];
		}
		setMenuBarData(new MenuData(new String[] { menuGroup, displayedPath }, null, menuGroup));

		setDescription("Opens the indicated archive in the data type manager.");
		setEnabled(true);
	}

	private static String getDisplayPath(String filepath) {
		String[] projectPathname = DataTypeManagerHandler.parseProjectPathname(filepath);
		if (projectPathname == null) {
			return filepath;
		}
		return projectPathname[0] + ":" + projectPathname[1];
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (projectName == null) {
			DataTypeManagerHandler archiveManager = plugin.getDataTypeManagerHandler();
			Path path = new Path(archivePath);
			OpenArchiveTask task = new OpenArchiveTask(archiveManager, path);
			new TaskLauncher(task, plugin.getProvider().getComponent());
		}
		else {
			DomainFile df = plugin.getProjectArchiveFile(projectName, archivePath);
			if (df != null) {
				plugin.openArchive(df);
			}
			else {
				Msg.showError(this, null, "Project Archive Open Error",
					"Project data type archive not found: " + getMenuBarData().getMenuItemName());
			}
		}
	}

	private class OpenArchiveTask extends Task {
		private final Path archivePath;
		private final DataTypeManagerHandler archiveManager;

		OpenArchiveTask(DataTypeManagerHandler archiveManager, Path archivePath) {
			super("Opening Archive " + archivePath.getPath().getName(), false, false, true);
			this.archiveManager = archiveManager;
			this.archivePath = archivePath;
		}

		@Override
		public void run(ghidra.util.task.TaskMonitor monitor) {
			try {
				archiveManager.openArchive(archivePath.getPath(), false, true);
			}
			catch (Throwable t) {
				DataTypeManagerHandler.handleArchiveFileException(plugin, archivePath.getPath(), t);
			}
		}
	}
}
