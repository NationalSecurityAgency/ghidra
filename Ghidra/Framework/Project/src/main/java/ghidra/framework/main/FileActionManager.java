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
import java.io.IOException;
import java.util.*;

import javax.swing.Icon;
import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.action.*;
import docking.tool.ToolConstants;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.wizard.WizardManager;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.model.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.store.LockException;
import ghidra.util.*;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskLauncher;
import resources.ResourceManager;

/**
 * Helper class to manage actions on the File menu.
 */
class FileActionManager {

	private final static int NEW_ACCELERATOR = KeyEvent.VK_N;
	private final static int OPEN_ACCELERATOR = KeyEvent.VK_O;
	private final static int CLOSE_ACCELERATOR = KeyEvent.VK_W;
	private final static int SAVE_ACCELERATOR = KeyEvent.VK_S;
	private final static Icon NEW_PROJECT_ICON = ResourceManager.loadImage("images/folder_add.png");
	private final static String LAST_SELECTED_PROJECT_DIRECTORY = "LastSelectedProjectDirectory";

	private static final String DISPLAY_DATA = "DISPLAY_DATA";

	private FrontEndTool tool;
	private FrontEndPlugin plugin;

	private DockingAction newAction;
	private DockingAction openAction;
	private DockingAction closeProjectAction;
	private DockingAction deleteAction;
	private DockingAction saveAction;

	private List<ViewInfo> reopenList;
	private GhidraFileChooser fileChooser;

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
		// create the menu items and their listeners
		newAction = new DockingAction("New Project", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				newProject();
			}
		};
		newAction.setEnabled(true);
		newAction.setKeyBindingData(
			new KeyBindingData(KeyStroke.getKeyStroke(NEW_ACCELERATOR, ActionEvent.CTRL_MASK)));
		newAction.setMenuBarData(
			new MenuData(new String[] { ToolConstants.MENU_FILE, "New Project..." }, "AProject"));
		tool.addAction(newAction);

		openAction = new DockingAction("Open Project", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				openProject();
			}
		};
		openAction.setEnabled(true);
		openAction.setKeyBindingData(
			new KeyBindingData(KeyStroke.getKeyStroke(OPEN_ACCELERATOR, ActionEvent.CTRL_MASK)));
		openAction.setMenuBarData(
			new MenuData(new String[] { ToolConstants.MENU_FILE, "Open Project..." }, "AProject"));
		tool.addAction(openAction);

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
				closeProject(false); //not exiting
			}
		};
		closeProjectAction.setEnabled(false);
		closeProjectAction.setKeyBindingData(
			new KeyBindingData(KeyStroke.getKeyStroke(CLOSE_ACCELERATOR, ActionEvent.CTRL_MASK)));
		closeProjectAction.setMenuBarData(
			new MenuData(new String[] { ToolConstants.MENU_FILE, "Close Project" }, "BProject"));
		tool.addAction(closeProjectAction);

		deleteAction = new DockingAction("Delete Project", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				deleteProject();
			}
		};
		deleteAction.setEnabled(true);
		deleteAction.setMenuBarData(new MenuData(
			new String[] { ToolConstants.MENU_FILE, "Delete Project..." }, "CProject"));
		tool.addAction(deleteAction);
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
		NewProjectPanelManager panelManager = new NewProjectPanelManager(tool);
		WizardManager wm = new WizardManager("New Project", true, panelManager, NEW_PROJECT_ICON);
		wm.showWizard(tool.getToolFrame());
		ProjectLocator newProjectLocator = panelManager.getNewProjectLocation();
		RepositoryAdapter newRepo = panelManager.getProjectRepository();

		if (newProjectLocator == null) {
			return; // user canceled
		}

		Project newProject = null;
		try {
			// if all is well and we already have an active project, close it
			Project activeProject = plugin.getActiveProject();
			if (activeProject != null) {
				if (!closeProject(false)) { // false -->not exiting
					return; // user canceled
				}
			}

			if (newRepo != null) {
				try {
					if (newRepo.getServer().isConnected()) {
						newRepo.connect();
					}
				}
				catch (IOException e) {
					ClientUtil.handleException(newRepo, e, "Repository Connection",
						tool.getToolFrame());
				}
			}

			newProject = tool.getProjectManager().createProject(newProjectLocator, newRepo, true);
		}
		catch (Exception e) {
			String msg = e.getMessage();
			if (msg == null) {
				msg = e.toString();
			}
			Msg.showError(this, tool.getToolFrame(), "Create Project Failed",
				"Failed to create new project '" + newProjectLocator.getName() + "': " + msg, e);
		}
		finally {
			if (newProject == null && newRepo != null) {
				newRepo.disconnect();
			}
		}

		// make the new project the active one
		tool.setActiveProject(newProject);

		// update our list of recent projects
		plugin.rebuildRecentMenus();

		if (newProject != null) {
			openProjectAndNotify(newProject);
		}
	}

	private void openProject() {
		ProjectLocator currentProjectLocator = null;
		Project activeProject = plugin.getActiveProject();
		if (activeProject != null) {
			currentProjectLocator = activeProject.getProjectLocator();
		}
		if (fileChooser == null) {
			fileChooser = plugin.createFileChooser(LAST_SELECTED_PROJECT_DIRECTORY);
		}

		ProjectLocator projectLocator =
			plugin.chooseProject(fileChooser, "Open", LAST_SELECTED_PROJECT_DIRECTORY);
		if (projectLocator != null) {

			if (!doOpenProject(projectLocator) && currentProjectLocator != null) {
				doOpenProject(currentProjectLocator);
			}

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
		String status = "Opened project: " + projectLocator.getName();
		Project project = null;
		boolean openStatus = false;
		try {
			// first close the active project (if there is one)
			// but if user cancels operation, don't continue
			if (!closeProject(false)) {
				return true;
			}
			ProjectManager pm = plugin.getProjectManager();
			project = pm.openProject(projectLocator, true, false);
			if (project == null) {
				status = "Error opening project: " + projectLocator.toString();
			}
			else {
				firingProjectOpened = true;
				tool.setActiveProject(project);
				openProjectAndNotify(project);
				openStatus = true;
				firingProjectOpened = false;
			}
		}
		catch (NotFoundException nfe) {
			status = "Project not found for " + projectLocator.toString();
			Msg.showInfo(getClass(), tool.getToolFrame(), "Error Opening Project", status);
		}
		catch (NotOwnerException e) {
			status = "Cannot open project: " + e.getMessage();
			Msg.showError(this, null, "Not Project Owner", "Cannot open project " + projectLocator +
				"\n" + e.getMessage() +
				"\n \nEach user must create their own project. If needed, another user's project may be viewed\n" +
				"and files copied, using the View Other action from your own open project.  Alternatively, \n" +
				"creating a \"Shared Project\" will allow a group of users to use a shared server-based repository.");
		}
		catch (LockException e) {
			status = "Project is already open for update: " + projectLocator.toString();
			Msg.showError(this, null, "Open Project Failed", status);
		}
		catch (Exception e) {
			status = "Error opening project: " + projectLocator.toString();
			Msg.showError(this, null, "Open Project Failed", status, e);
		}
		finally {
			// update our list of recent projects
			plugin.rebuildRecentMenus();
		}

		if (!openStatus) {
			Msg.error(this, status);
		}
		else {
			Msg.info(this, status);
		}
		return openStatus;
	}

	/**
	 * Obtain domain objects from files and lock.  If unable to lock 
	 * one or more of the files, none are locked and null is returned.
	 * @param files the files
	 * @return locked domain objects, or null if unable to lock
	 * all domain objects.
	 */
	private DomainObject[] lockDomainObjects(List<DomainFile> files) {
		DomainObject[] objs = new DomainObject[files.size()];
		int lastIndex = 0;
		boolean locked = true;
		while (lastIndex < files.size()) {
			try {
				objs[lastIndex] = files.get(lastIndex).getDomainObject(this, false, false, null);
			}
			catch (Throwable t) {
				Msg.error(this, "Failed to aqcuire domain object instance", t);
				locked = false;
				break;
			}
			if (!objs[lastIndex].lock(null)) {
				String title = "Exit Ghidra";
				StringBuffer buf = new StringBuffer();
				UndoableDomainObject udo = (UndoableDomainObject) objs[lastIndex];
				buf.append("The File " + files.get(lastIndex).getPathname() +
					" is currently being modified by the\n");
				buf.append("the following actions:\n \n");
				Transaction t = udo.getCurrentTransaction();
				List<String> list = t.getOpenSubTransactions();
				Iterator<String> it = list.iterator();
				while (it.hasNext()) {
					buf.append("\n     ");
					buf.append(it.next());
				}
				buf.append("\n \n");
				buf.append(
					"You may exit Ghidra, but the above action(s) will be aborted and all\n");
				buf.append("changes made by those actions (and all changes made since those\n");
				buf.append("actions started),will be lost!  You will still have the option of \n");
				buf.append("saving any changes made before those actions began.\n \n");
				buf.append("Do you want to abort the action(s) and exit Ghidra?");

				int result = OptionDialog.showOptionDialog(tool.getToolFrame(), title,
					buf.toString(), "Exit Ghidra", OptionDialog.WARNING_MESSAGE);

				if (result == OptionDialog.CANCEL_OPTION) {
					locked = false;
					objs[lastIndex].release(this);
					break;
				}
				udo.forceLock(true, null);
			}
			++lastIndex;
		}
		if (!locked) {
			//skip the last one that could not be locked...
			for (int i = 0; i < lastIndex; i++) {
				objs[i].unlock();
				objs[i].release(this);
			}
			return null;
		}
		return objs;
	}

	/**
	 * menu listener for File | Close Project...
	 * <p>
	 * This method will always save the FrontEndTool and project, but not the data unless 
	 * <tt>confirmClose</tt> is called.
	 * 
	 * @param isExiting true if we are closing the project because 
	 * Ghidra is exiting
	 * @return false if user cancels the close operation
	 */
	boolean closeProject(boolean isExiting) {
		// if there is no active project currently, ignore request
		Project activeProject = plugin.getActiveProject();
		if (activeProject == null) {
			return true;
		}

		// check for any changes since last saved
		PluginTool[] runningTools = activeProject.getToolManager().getRunningTools();
		for (PluginTool runningTool : runningTools) {
			if (!runningTool.canClose(isExiting)) {
				return false;
			}
		}

		boolean saveSuccessful = saveChangedData(activeProject);
		if (!saveSuccessful) {
			return false;
		}

		if (!activeProject.saveSessionTools()) {
			return false;
		}

		doSaveProject(activeProject);

		// close the project
		String name = activeProject.getName();
		ProjectLocator projectLocator = activeProject.getProjectLocator();
		activeProject.close();

		// TODO: This should be done by tool.setActiveProject which should always be invoked
		fireProjectClosed(activeProject);

		if (!isExiting) {
			// update the gui now that active project is closed
			tool.setActiveProject(null);
			Msg.info(this, "Closed project: " + name);

			// update the list of project views to include the "active"
			// project that is no longer active
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

	private boolean saveChangedData(Project activeProject) {
		List<DomainFile> data = activeProject.getOpenData();
		if (data.isEmpty()) {
			return true;
		}

		DomainObject[] lockedObjects = lockDomainObjects(data);
		if (lockedObjects == null) {
			return false;
		}

		List<DomainFile> changedFiles = getChangedFiles(data);

		try {
			if (!checkReadOnlyFiles(lockedObjects)) {
				return false;
			}

			// pop up dialog to save the data
			SaveDataDialog saveDialog = new SaveDataDialog(tool);
			if (!saveDialog.showDialog(changedFiles)) {
				// user hit the cancel button on the "Save" dialog
				// so cancel closing the project
				return false;
			}
		}
		finally {
			for (DomainObject lockedObject : lockedObjects) {
				lockedObject.unlock();
				lockedObject.release(this);
			}
		}
		return true;
	}

	private List<DomainFile> getChangedFiles(List<DomainFile> data) {
		List<DomainFile> changedFiles = new ArrayList<>();
		for (DomainFile domainFile : data) {
			if (domainFile.isChanged()) {
				changedFiles.add(domainFile);
			}
		}
		return changedFiles;
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
		if (fileChooser == null) {
			fileChooser = plugin.createFileChooser(LAST_SELECTED_PROJECT_DIRECTORY);
		}
		ProjectLocator projectLocator =
			plugin.chooseProject(fileChooser, "Delete", LAST_SELECTED_PROJECT_DIRECTORY);
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
		StringBuffer confirmMsg = new StringBuffer("Project: ");
		confirmMsg.append(projectLocator.toString());
		confirmMsg.append(" ?\n");
		boolean isActiveProject =
			(activeProject != null && activeProject.getProjectLocator().equals(projectLocator));
		// also give special warning if we open this project as read-only voew
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

	final void enableActions(boolean enabled) {
//      renameAction.setEnabled(enabled);
		closeProjectAction.setEnabled(enabled);
		saveAction.setEnabled(enabled);
	}

	/**
	 * Checks the list for read-only files; if any are found, pops up
	 * a dialog for whether to save now or lose changes.
	 * @param objs list of files which correspond to modified 
	 * domain objects.
	 * @return true if there are no read only files OR if the user
	 * wants to lose his changes; false if the user wants to save the
	 * files now, so don't continue.
	 */
	private boolean checkReadOnlyFiles(DomainObject[] objs) {
		ArrayList<DomainObject> list = new ArrayList<>(10);
		for (DomainObject domainObject : objs) {
			try {
				if (domainObject.isChanged() && !domainObject.getDomainFile().canSave()) {
					list.add(domainObject);
				}
			}
			catch (Exception e) {
				Msg.showError(this, null, null, null, e);
			}
		}
		if (list.size() == 0) {
			return true;
		}

		StringBuffer sb = new StringBuffer();
		sb.append("The following files are Read-Only and cannot be\n" +
			" saved 'As Is.' You must do a manual 'Save As' for these\n" + " files: \n \n");

		for (DomainObject obj : list) {
			sb.append(obj.getDomainFile().getPathname());
			sb.append("\n");
		}
		// note: put the extra space in or else OptionDialog will not show
		// the new line char
		sb.append(" \nChoose 'Cancel' to cancel Close Project, or \n");
		sb.append("'Lose Changes' to continue.");

		if (OptionDialog.showOptionDialog(tool.getToolFrame(), "Read-Only Files", sb.toString(),
			"Lose Changes", OptionDialog.QUESTION_MESSAGE) == OptionDialog.OPTION_ONE) {
			return true; // Lose changes, so close the project
		}
		return false;
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

	/**
	 * Action for a recently opened project.
	 *
	 */
	private class ReopenProjectAction extends DockingAction {
		private ProjectLocator projectLocator;

		private ReopenProjectAction(ProjectLocator projectLocator, String filename) {
			super(filename, plugin.getName(), false);
			this.projectLocator = projectLocator;
// ACTIONS - auto generated
			setMenuBarData(new MenuData(
				new String[] { ToolConstants.MENU_FILE, "Reopen", filename }, null, "AProject"));

			tool.setMenuGroup(new String[] { ToolConstants.MENU_FILE, "Reopen" }, "AProject");
			setEnabled(true);
			setHelpLocation(new HelpLocation(plugin.getName(), "Reopen_Project"));
		}

		/* (non Javadoc)
		 * @see java.awt.event.ActionListener#actionPerformed(java.awt.event.ActionEvent)
		 */
		@Override
		public void actionPerformed(ActionContext context) {
			doOpenProject(projectLocator);
		}

	}
}
