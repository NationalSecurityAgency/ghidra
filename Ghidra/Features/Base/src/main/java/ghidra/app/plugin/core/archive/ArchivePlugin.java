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
package ghidra.app.plugin.core.archive;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;
import java.util.zip.ZipEntry;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.framework.main.*;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.*;

/**
 * The archive plugin provides menu action from the front end allowing the
 * user to archive a project or restore an archived project.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = ArchivePlugin.GROUP_NAME,
	shortDescription = "Archives/restores projects",
	description = "The archive plugin provides a menu action from the project window allowing the user to archive a project or restore an archived project. "
)
//@formatter:on
public class ArchivePlugin extends Plugin implements FrontEndOnly, ProjectListener {

	private static final String PROJECT_GROUP_C_2 = "CProject2";

	static final String LAST_ARCHIVE_DIR = "last.project.archive.dir";

	static final String TOOL_RUNNING_TITLE = "Cannot Archive while Tools are Running";
	static final String GROUP_NAME = "Archiving";
	static final String ARCHIVE_EXTENSION = ".gar";
	static final String DOT_DOT_DOT = ". . .";
	static final String TOOLS_FOLDER_NAME = "tools";
	static final String GROUPS_FOLDER_NAME = "groups";
	static final String SAVE_FOLDER_NAME = "save";
	static final String ARCHIVE_ERROR_TITLE = "Error Archiving Project";
	static final String RESTORE_ERROR_TITLE = "Error Restoring Project";
	static final String DB_LOCK_EXT = ".ulock";
	static final String JAR_VERSION_TAG = "JAR_FORMAT";
	static final SimpleDateFormat formatter = new SimpleDateFormat("yyyy_MM_dd");

	// project properties file should not be restored
	static final String PROJECT_PROPERTY_FILE = "project.prp";

	// current project state file should not be restored
	static final String PROJECT_STATE_FILE = "projectState";

	// old project state folder should not be restored
	static final String OLD_PROJECT_SAVE_DIR = "save";

	// old project group folder should not be restored
	static final String OLD_PROJECT_GROUPS_DIR = "groups";

	// Old folder properties file should not be restored
	static final String OLD_FOLDER_PROPERTIES_FILE = ".properties";

	private ArchiveDialog archiveDialog;
	private RestoreDialog restoreDialog;
	private String lastRestoreArchivePathName; // The path name of the archive file.
	private ProjectLocator lastRestoreLocator;

	private DockingAction archiveAction;
	private DockingAction restoreAction;

	private volatile boolean isArchiving;
	private volatile boolean isRestoring;
	private TaskListener archivingListener;
	private TaskListener restoringListener;

	//////////////////////////////////////////////////////////////////

	/**
	 * The archive plugin provides menu action from the front end allowing the
	 * user to archive a project or restore an archived project.
	 * @param tool the tool that contains this plugin. The actions will only
	 * appear if the tool is the Ghidra front end tool.
	 */
	public ArchivePlugin(PluginTool tool) {
		super(tool);
		setupActions();
	}

	@Override
	public void dispose() {
		super.dispose();
	}

	/////////////////////////////////////////////////////////////////////

	/**
	 * @see ghidra.framework.model.ProjectListener#projectClosed(Project)
	 */
	@Override
	public void projectClosed(Project project) {
		archiveAction.setEnabled(false);
		restoreAction.setEnabled(true);
	}

	/**
	 * @see ghidra.framework.model.ProjectListener#projectOpened(Project)
	 */
	@Override
	public void projectOpened(Project project) {
		archiveAction.setEnabled(true);
		restoreAction.setEnabled(false);
	}

	/**
	 * for JUnits...
	 */
	boolean isArchiving() {
		return isArchiving;
	}

	/**
	 * for JUnits...
	 */
	boolean isRestoring() {
		return isRestoring;
	}

	/**
	 * Sets up the menu actions that this plugin wants to listen for
	 */
	private void setupActions() {
		archiveAction = new DockingAction("Archive Project", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				archiveProject();
			}
		};

		ProjectManager projectManager = tool.getProjectManager();
		String[] archiveMenuPath = { ToolConstants.MENU_FILE, "Archive Current Project..." };
		archiveAction.setMenuBarData(new MenuData(archiveMenuPath, PROJECT_GROUP_C_2));
		archiveAction.setEnabled(projectManager.getActiveProject() != null);
		archiveAction.setHelpLocation(new HelpLocation("FrontEndPlugin", "Archive_Project"));

		restoreAction = new DockingAction("Restore Archived Project", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				restoreProject();
			}
		};
		String[] restoreMenuPath = { ToolConstants.MENU_FILE, "Restore Project..." };
		restoreAction.setMenuBarData(new MenuData(restoreMenuPath, PROJECT_GROUP_C_2));
		restoreAction.setEnabled(projectManager.getActiveProject() == null);
		restoreAction.setHelpLocation(new HelpLocation("FrontEndPlugin", "Restore_Project"));

		if (tool instanceof FrontEndTool) {
			tool.addAction(archiveAction);
			tool.addAction(restoreAction);
			((FrontEndTool) tool).addProjectListener(this);
		}
		if (tool.getProject() == null) {
			archiveAction.setEnabled(false);
		}
		else {
			restoreAction.setEnabled(false);
		}
	}

	/**
	 * menu listener for File | Archive ...
	 */
	private void archiveProject() {

		FrontEndTool feTool = (FrontEndTool) tool;
		Project activeProject = AppInfo.getActiveProject();
		if (activeProject.getToolManager().getRunningTools().length > 0) {
			Msg.showInfo(getClass(), tool.getToolFrame(), TOOL_RUNNING_TITLE,
				"You must close running tools before starting the archive process.");
			return;
		}

		activeProject.saveToolTemplate("FRONTEND", feTool.saveToolToToolTemplate());
		activeProject.save();

		if (archiveDialog == null) {
			archiveDialog = new ArchiveDialog(this);
		}

		ProjectLocator projectLocator = activeProject.getProjectLocator();
		String archivePathName = getArchivePathName(projectLocator);
		if (!archiveDialog.showDialog(projectLocator, archivePathName, tool)) {
			return;
		}

		archivePathName = archiveDialog.getArchivePathName();

		File archiveJar = new File(archivePathName);
		File parentFile = archiveJar.getParentFile();
		Preferences.setProperty(LAST_ARCHIVE_DIR, parentFile.getAbsolutePath());

		isArchiving = true;
		archivingListener = new TaskListener() {
			@Override
			public void taskCompleted(Task task) {
				isArchiving = false;
			}

			@Override
			public void taskCancelled(Task task) {
				isArchiving = false;
			}
		};

		Task task = new ArchiveTask(activeProject, archiveJar);
		task.addTaskListener(archivingListener);
		new TaskLauncher(task, tool.getToolFrame());
	}

	private String getArchivePathName(ProjectLocator projectLocator) {
		String defaultDirString = projectLocator.getLocation();
		String dirString = Preferences.getProperty(LAST_ARCHIVE_DIR, defaultDirString);
		String dateString = formatter.format(new Date());
		String projectName = projectLocator.getName();
		if (!dirString.endsWith(File.separator)) {
			dirString = dirString + File.separator;
		}
		return dirString + projectName + "_" + dateString + ArchivePlugin.ARCHIVE_EXTENSION;
	}

	/**
	 * menu listener for File | Restore Archive ...
	 */
	private void restoreProject() {

		if (restoreDialog == null) {
			restoreDialog = new RestoreDialog(this);
		}

		String archiveName = lastRestoreArchivePathName;
		ProjectLocator locator = lastRestoreLocator;
		if (!restoreDialog.showDialog(archiveName, locator)) {
			return;
		}

		lastRestoreArchivePathName = restoreDialog.getArchivePathName();
		lastRestoreLocator = restoreDialog.getRestoreURL();
		File archiveJar = new File(lastRestoreArchivePathName);
		try {
			if (!isJarFormat(archiveJar)) {
				Msg.showError(this, null, "File Format Error",
					"Can't read the file: " + lastRestoreArchivePathName);
				return;
			}
		}
		catch (IOException e) {
			Msg.showError(this, null, "File Format Error",
				"Can't read the file: " + lastRestoreArchivePathName, e);
			return;
		}

		isRestoring = true;

		restoringListener = new TaskListener() {
			@Override
			public void taskCompleted(Task task) {
				isRestoring = false;
			}

			@Override
			public void taskCancelled(Task task) {
				isRestoring = false;
			}
		};

		Task task = new RestoreTask(lastRestoreLocator, archiveJar, this);
		task.addTaskListener(restoringListener);
		new TaskLauncher(task, tool.getToolFrame());
	}

	/**
	 * Return true if the jar file contains the JAR_FORMAT tag to indicate
	 * the new jar file format.
	 * @param jarFile
	 * @throws IOException
	 */
	private boolean isJarFormat(File jarFile) throws IOException {
		JarInputStream jarIn = new JarInputStream(new FileInputStream(jarFile));
		JarEntry entry = jarIn.getNextJarEntry();

		// the next entry should be JAR_FORMAT
		entry = jarIn.getNextJarEntry();
		String format = entry.getName();
		jarIn.close();

		if (format.equalsIgnoreCase(ArchivePlugin.JAR_VERSION_TAG)) {
			return true;
		}
		return false;
	}

	/**
	 * Gets the project name for the indicated project archive file.
	 * @param archivePathName the archive project file.
	 * @return the project name or null if the file is not a valid
	 * project archive file.
	 */
	static String getProjectName(String archivePathName) {
		if (archivePathName == null) {
			return null;
		}
		File archiveFile = new File(archivePathName);
		FileInputStream fileIn = null;
		JarInputStream jarIn = null;
		try {
			fileIn = new FileInputStream(archiveFile);
			jarIn = new JarInputStream(fileIn);
			while (true) {
				ZipEntry zipEntry = jarIn.getNextEntry();
				if (zipEntry == null) {
					break;
				}
				String name = zipEntry.getName();
				jarIn.closeEntry();
				if (name.endsWith(ProjectLocator.getProjectExtension())) {
					int endIndex = name.length() - ProjectLocator.getProjectExtension().length();
					String projectName = name.substring(0, endIndex);
					return projectName;
				}
			}
		}
		catch (IOException e) {
			// just return null below
		}
		finally {
			if (jarIn != null) {
				try {
					jarIn.close();
				}
				catch (IOException e) {
					// we tried
				}
			}
			if (fileIn != null) {
				try {
					fileIn.close();
				}
				catch (IOException e) {
					// we tried
				}
			}
		}
		return null;
	}

	void cleanupRestoredProject(ProjectLocator projectLocator) {

		ProjectManager projectManager = tool.getProjectManager();

		// delete the project at the given project location
		if (!projectManager.deleteProject(projectLocator)) {
			Msg.showError(this, null, "All Files in Project not Removed",
				"Not all files have been deleted from project " + projectLocator.getName());
		}
	}
}
