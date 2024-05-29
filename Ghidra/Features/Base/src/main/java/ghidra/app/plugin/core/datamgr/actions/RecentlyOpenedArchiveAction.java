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

	private static final String EXTENSIONS_PATH_PREFIX = Path.GHIDRA_HOME + "/Extensions/Ghidra";

	private final String projectName; // only used for project archive path
	private final String archivePath;
	private final DataTypeManagerPlugin plugin;

	public RecentlyOpenedArchiveAction(DataTypeManagerPlugin plugin, String archivePath,
			String menuGroup) {
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

		String menuPath = getMenuPath(archivePath);
		setMenuBarData(new MenuData(new String[] { menuGroup, menuPath }, null, menuGroup));

		setDescription("Opens the indicated archive in the data type manager.");
		setEnabled(true);
	}

	private static String getMenuPath(String filepath) {

		if (filepath.contains("/data/typeinfo/")) {
			return getTypeInfoRelativeName(filepath);
		}

		String[] projectPathname = DataTypeManagerHandler.parseProjectPathname(filepath);
		if (projectPathname == null) {
			return filepath;
		}
		return projectPathname[0] + ":" + projectPathname[1];
	}

	/*
	 
	 Inputs:
	 		$GHIDRA_HOME/Extensions/Ghidra/Extension1/data/typeinfo/foo.gdt -> "Extension1: "
		    $GHIDRA_HOME/Features/Base/data/typeinfo/foo.gdt -> ""	 
	 */
	private static String getExtensionName(String fullPath) {

		if (!fullPath.startsWith(EXTENSIONS_PATH_PREFIX)) {
			return "";
		}

		int start = EXTENSIONS_PATH_PREFIX.length() + 1;
		int slashIndex = fullPath.indexOf("/", start);
		if (slashIndex < 0) {
			return ""; // no folder; shouldn't happen
		}

		// return the first folder name, which is the extension name
		return fullPath.substring(start, slashIndex) + ": ";
	}

	/*
	 	Input path is expected to contain '/data/typeinfo'.  It may or may not be an extension path.
	 	
			$GHIDRA_HOME/Extensions/Ghidra/Extension1/data/typeinfo/foo.gdt -> "Extension1: "
			$GHIDRA_HOME/Features/Base/data/typeinfo/foo.gdt -> ""
	 */
	private static String getTypeInfoRelativeName(String fullPath) {

		String[] parts = fullPath.split("/data/typeinfo/");
		String relativePath = parts[1];

		// e.g., "Extension1: " or ""
		String extensionName = getExtensionName(fullPath);
		return extensionName + relativePath;
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
		private final Path taskArchivePath;
		private final DataTypeManagerHandler archiveManager;

		OpenArchiveTask(DataTypeManagerHandler archiveManager, Path archivePath) {
			super("Opening Archive " + archivePath.getPath().getName(), false, false, true);
			this.archiveManager = archiveManager;
			this.taskArchivePath = archivePath;
		}

		@Override
		public void run(ghidra.util.task.TaskMonitor monitor) {
			try {
				archiveManager.openArchive(taskArchivePath.getPath(), false, true);
			}
			catch (Exception e) {
				DataTypeManagerHandler.handleArchiveFileException(plugin, taskArchivePath.getPath(),
					e);
			}
		}
	}
}
