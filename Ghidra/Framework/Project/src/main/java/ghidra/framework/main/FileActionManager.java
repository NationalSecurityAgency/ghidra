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
package ghidra.framework.main;

import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.action.*;
import docking.action.builder.ActionBuilder;
import docking.tool.ToolConstants;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.wizard.WizardDialog;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.main.wizard.project.ProjectWizardModel;
import ghidra.framework.model.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.PluginToolAccessUtils;
import ghidra.framework.store.LockException;
import ghidra.util.*;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskLauncher;

/**
 * Helper class to manage actions on the File menu.
 */
class FileActionManager {

	private final static int CLOSE_ACCELERATOR = KeyEvent.VK_W;
	private final static int SAVE_ACCELERATOR = KeyEvent.VK_S;

	private final static String LAST_SELECTED_PROJECT_DIRECTORY = "LastSelectedProjectDirectory";
	private static final String DISPLAY_DATA = "DISPLAY_DATA";

	private FrontEndTool tool;
	private FrontEndPlugin plugin;

	private DockingAction closeProjectAction;
	private DockingAction saveAction;

	private List<ViewInfo> reopenList;

	private boolean firingProjectOpened;

	FileActionManager(FrontEndPlugin plugin) {
		this.plugin = plugin;
		tool = (FrontEndTool) plugin.getTool();
		reopenList = new ArrayList<>();
		createActions();
	}

	/**
	 * creates all the menu items for the File menu
	 */
	private void createActions() {
		new ActionBuilder("New Project", plugin.getName())
				.menuPath(ToolConstants.MENU_FILE, "New Project...")
				.menuGroup("AProject")
				.keyBinding("ctrl N")
				.onAction(c -> newProject())
				.buildAndInstall(tool);

		new ActionBuilder("Open Project", plugin.getName())
				.menuPath(ToolConstants.MENU_FILE, "Open Project...")
				.menuGroup("AProject")
				.keyBinding("ctrl O")
				.onAction(c -> openProject())
				.buildAndInstall(tool);

		saveAction = new DockingAction("Save Project", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				saveProject();
				tool.saveToolConfigurationToDisk();
			}
		};
		saveAction.setEnabled(false);
		saveAction.setKeyBindingData(
			new KeyBindingData(KeyStroke.getKeyStroke(SAVE_ACCELERATOR, ActionEvent.CTRL_MASK)));
		saveAction.setMenuBarData(
			new MenuData(new String[] { ToolConstants.MENU_FILE, "Save Project" }, "BProject"));
		tool.addAction(saveAction);

		closeProjectAction = new DockingAction("Close Project", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				closeProject(false); // not exiting
			}
		};
		closeProjectAction.setEnabled(false);
		closeProjectAction.setKeyBindingData(
			new KeyBindingData(KeyStroke.getKeyStroke(CLOSE_ACCELERATOR, ActionEvent.CTRL_MASK)));
		closeProjectAction.setMenuBarData(
			new MenuData(new String[] { ToolConstants.MENU_FILE, "Close Project" }, "BProject"));
		tool.addAction(closeProjectAction);

		new ActionBuilder("Delete Project", plugin.getName())
				.menuPath(ToolConstants.MENU_FILE, "Delete Project...")
				.menuGroup("CProject")
				.onAction(c -> deleteProject())
				.buildAndInstall(tool);

	}

	/**
	 * creates the recent projects menu
	 */
	void buildRecentProjectsMenu() {

		for (ViewInfo info : reopenList) {
			tool.removeAction(info.getAction());
		}

		reopenList.clear();

		ProjectLocator[] recentProjects = plugin.getRecentProjects();

		// the project manager maintains the order of the projects
		// with the most recent being first in the list
		for (ProjectLocator projectLocator : recentProjects) {
			String filename = projectLocator.toString();
			DockingAction action = new ReopenProjectAction(projectLocator, filename);
			reopenList.add(new ViewInfo(action, projectLocator.getURL()));
			tool.addAction(action);
		}
	}

	/**
	 * Create a new project using a wizard to get the project information.
	 */
	void newProject() {
		ProjectWizardModel model = new ProjectWizardModel(tool);
		WizardDialog dialog = new WizardDialog(model);
		dialog.show(tool.getToolFrame());

		if (model.wasCancelled()) {
			return;
		}

		if (!closeProject(false)) { // false --> not exiting
			return; // user canceled
		}

		ProjectLocator projectLocator = model.getProjectLocator();
		RepositoryAdapter repository = model.getRepository();

		Project newProject = createProject(projectLocator, repository);
		if (newProject == null && repository != null) {
			repository.disconnect();
			return;
		}

		// make the new project the active one
		tool.setActiveProject(newProject);

		// update our list of recent projects
		plugin.rebuildRecentMenus();

		if (newProject != null) {
			openProjectAndNotify(newProject);
		}
	}

	private Project createProject(ProjectLocator locator, RepositoryAdapter repository) {
		try {
			return tool.getProjectManager().createProject(locator, repository, true);
		}
		catch (Exception e) {
			Msg.showError(this, tool.getToolFrame(), "Create Project Failed",
				"Failed to create new project '" + locator.getName() + "': " + e.getMessage(), e);
		}
		return null;
	}

	private void openProject() {
		ProjectLocator currentProjectLocator = null;
		Project activeProject = plugin.getActiveProject();
		if (activeProject != null) {
			currentProjectLocator = activeProject.getProjectLocator();
		}

		GhidraFileChooser fileChooser = plugin.createFileChooser(LAST_SELECTED_PROJECT_DIRECTORY);
		ProjectLocator projectLocator =
			plugin.chooseProject(fileChooser, "Open", LAST_SELECTED_PROJECT_DIRECTORY);
		if (projectLocator != null) {
			if (!doOpenProject(projectLocator) && currentProjectLocator != null) {
				doOpenProject(currentProjectLocator);
			}
		}
		fileChooser.dispose();
	}

	/**
	 * Opens the given project in a task that will show a dialog to block input while opening
	 * the project in the swing thread.
	 * @param projectLocator the project locator
	 * @return true if the project was opened 
	 */
	final boolean openProject(ProjectLocator projectLocator) {
		OpenTaskRunnable openRunnable = new OpenTaskRunnable(projectLocator);
		TaskLauncher.launchModal("Opening Project", () -> Swing.runNow(openRunnable));
		return openRunnable.getResult();
	}

	/**
	 * Open an existing project, using a file chooser to specify where the
	 * existing project folder is stored.
	 * @param projectLocator the project locator
	 * @return true if the project was opened
	 */
	final boolean doOpenProject(ProjectLocator projectLocator) {
		Project project = null;
		try {
			// first close the active project (if there is one)
			// but if user cancels operation, don't continue
			if (!closeProject(false)) {
				return true;
			}
			ProjectManager pm = plugin.getProjectManager();
			project = pm.openProject(projectLocator, true, false);
			firingProjectOpened = true;
			tool.setActiveProject(project);
			openProjectAndNotify(project);
			firingProjectOpened = false;
			Msg.info(this, "Opened project: " + projectLocator.getName());
		}
		catch (NotFoundException nfe) {
			String msg = "Project not found for " + projectLocator;
			Msg.showInfo(getClass(), tool.getToolFrame(), "Error Opening Project", msg);
			Msg.error(this, msg);
		}
		catch (NotOwnerException e) {
			Msg.showError(this, null, "Not Project Owner", "Cannot open project " + projectLocator +
				"\n" + e.getMessage() +
				"\n \nEach user must create their own project. If needed, another user's project may be viewed\n" +
				"and files copied, using the View Other action from your own open project.  Alternatively, \n" +
				"creating a \"Shared Project\" will allow a group of users to use a shared server-based repository.");
			Msg.error(this, "Cannot open project: " + e.getMessage());
		}
		catch (LockException e) {
			Msg.showInfo(this, null, "Open Project Failed", e.getMessage());
		}
		catch (Exception e) {
			Msg.showError(this, null, "Open Project Failed",
				"Error opening project: " + projectLocator, e);
		}
		finally {
			// update our list of recent projects
			plugin.rebuildRecentMenus();
		}

		return project != null;
	}

	/**
	 * Called by clients that wish to close the project before performing project-related work.
	 * 
	 * @param isExiting true if we are closing the project because Ghidra is exiting
	 * @return false if user cancels the close operation
	 */
	boolean closeProject(boolean isExiting) {
		// if there is no active project currently, ignore request
		Project activeProject = plugin.getActiveProject();
		if (activeProject == null) {
			return true;
		}

		FrontEndTool frontEndTool = plugin.getFrontEndTool();
		PluginTool[] runningTools = activeProject.getToolManager().getRunningTools();
		List<PluginTool> subTools = List.of(runningTools);
		if (!PluginToolAccessUtils.canClose(frontEndTool, subTools)) {
			return false;
		}

		if (!activeProject.saveSessionTools()) {
			return false;
		}

		doSaveProject(activeProject);

		String name = activeProject.getName();
		ProjectLocator projectLocator = activeProject.getProjectLocator();
		activeProject.close();

		// Note: This should be done by tool.setActiveProject which should always be invoked.  If 
		// so, we can remove this code.
		fireProjectClosed(activeProject);

		if (!isExiting) {
			// update the gui now that active project is closed
			tool.setActiveProject(null);
			Msg.info(this, "Closed project: " + name);

			plugin.rebuildRecentMenus();
			plugin.getProjectManager().setLastOpenedProject(null);
		}
		else {
			plugin.getProjectManager().setLastOpenedProject(projectLocator);
		}

		if (tool.getManagePluginsDialog() != null) {
			tool.getManagePluginsDialog().close();
		}

		return true;
	}

	private void doSaveProject(Project project) {
		project.setSaveableData(DISPLAY_DATA, tool.getSaveableDisplayData());
		project.save();
	}

	private void openProjectAndNotify(Project project) {
		doRestoreProject(project);
		fireProjectOpened(project);
	}

	private void doRestoreProject(Project project) {
		SaveState saveState = project.getSaveableData(DISPLAY_DATA);
		if (saveState == null) {
			return;
		}
		tool.setSaveableDisplayData(saveState);
	}

	void setActiveProject(Project activeProject) {
		plugin.rebuildRecentMenus();
		if (!firingProjectOpened && activeProject != null) {
			openProjectAndNotify(activeProject);
		}
	}

	/**
	 * menu listener for File | Save Project
	 */
	void saveProject() {
		Project project = plugin.getActiveProject();
		if (project == null) {
			return;
		}

		if (!project.saveSessionTools()) {
			// if tools have conflicting options, user is presented with a dialog that can
			// be cancelled. If they press the cancel button, abort the entire save project action.
			return;
		}

		doSaveProject(project);
		Msg.info(this, "Saved project: " + project.getName());
	}

	private boolean allowDelete(Project activeProject) {
		if (activeProject != null) {
			Msg.showWarn(getClass(), tool.getToolFrame(), "Cannot Delete Active Project",
				"You must close your project to delete it.");
			return false;
		}
		return true;
	}

	/**
	 * menu listener for File | Delete Project...
	 */
	private void deleteProject() {

		GhidraFileChooser fileChooser = plugin.createFileChooser(LAST_SELECTED_PROJECT_DIRECTORY);
		ProjectLocator projectLocator =
			plugin.chooseProject(fileChooser, "Delete", LAST_SELECTED_PROJECT_DIRECTORY);
		fileChooser.dispose();
		if (projectLocator == null) {
			return; // user canceled
		}
		ProjectManager pm = plugin.getProjectManager();
		if (!pm.projectExists(projectLocator)) {
			Msg.showInfo(getClass(), tool.getToolFrame(), "Project Does Not Exist",
				"Project " + projectLocator.getName() + " was not found.");
			return;
		}
		// confirm delete before continuing
		Project activeProject = plugin.getActiveProject();

		// give a special confirm message if user is about to
		// remove the active project
		StringBuilder confirmMsg = new StringBuilder("Project: ");
		confirmMsg.append(projectLocator.toString());
		confirmMsg.append(" ?\n");
		boolean isActiveProject =
			(activeProject != null && activeProject.getProjectLocator().equals(projectLocator));
		// also give special warning if we open this project as read-only view
		boolean isOpenProjectView = isOpenProjectView(projectLocator);

		if (!allowDelete(isActiveProject ? activeProject : null)) {
			return;
		}

		confirmMsg.append(" \n");
		confirmMsg.append("WARNING: Delete CANNOT be undone!");

		if (!plugin.confirmDelete(confirmMsg.toString())) {
			return;
		}

		String projectName = projectLocator.getName();
		try {
			if (!pm.deleteProject(projectLocator)) {
				Msg.showInfo(getClass(), tool.getToolFrame(), "Error Deleting Project",
					"All files from project " + projectName + " were not deleted.");
			}
		}
		catch (Exception e) {
			Msg.error(this, "Error deleting project: " + projectName + ", " + e.getMessage(), e);
			return;
		}

		if (isActiveProject) {
			activeProject.close();
			fireProjectClosed(activeProject);
			tool.setActiveProject(null);
		}
		else if (isOpenProjectView) {
			// update the read-only project views if affected
			plugin.getProjectActionManager().closeView(projectLocator.getURL());
		}

		// update our list of recent projects
		plugin.rebuildRecentMenus();

		Msg.info(this, "Deleted project: " + projectName);
	}

	private boolean isOpenProjectView(ProjectLocator projectLocator) {
		boolean isOpenView = false;
		ProjectLocator[] openViews = plugin.getProjectDataPanel().getProjectViews();
		for (int v = 0; !isOpenView && v < openViews.length; v++) {
			isOpenView = openViews[v].equals(projectLocator);
		}

		return isOpenView;
	}

	void enableActions(boolean enabled) {
		closeProjectAction.setEnabled(enabled);
		saveAction.setEnabled(enabled);
	}

	/**
	 * Fire the project opened event
	 * @param project project being opened
	 */
	private void fireProjectOpened(Project project) {
		for (ProjectListener listener : tool.getListeners()) {
			listener.projectOpened(project);
		}
	}

	/**
	 * Fire the project closed event.
	 * @param project project being closed
	 */
	private void fireProjectClosed(Project project) {
		for (ProjectListener listener : tool.getListeners()) {
			listener.projectClosed(project);
		}
	}

	private class OpenTaskRunnable implements Runnable {

		private final ProjectLocator newProjectLocator;
		private boolean result = false;

		OpenTaskRunnable(ProjectLocator newProjectLocator) {
			this.newProjectLocator = newProjectLocator;
		}

		@Override
		public void run() {
			result = doOpenProject(newProjectLocator);
		}

		boolean getResult() {
			return result;
		}
	}

	private class ReopenProjectAction extends DockingAction {
		private ProjectLocator projectLocator;

		private ReopenProjectAction(ProjectLocator projectLocator, String filename) {
			super(filename, plugin.getName(), false);
			this.projectLocator = projectLocator;

			setMenuBarData(new MenuData(
				new String[] { ToolConstants.MENU_FILE, "Reopen", filename }, null, "AProject"));

			tool.setMenuGroup(new String[] { ToolConstants.MENU_FILE, "Reopen" }, "AProject");
			setEnabled(true);
			setHelpLocation(new HelpLocation(plugin.getName(), "Reopen_Project"));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			doOpenProject(projectLocator);
		}

	}
}
