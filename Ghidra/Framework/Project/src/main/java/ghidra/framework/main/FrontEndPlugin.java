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

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.*;

import javax.swing.*;
import javax.swing.border.BevelBorder;

import docking.*;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import docking.widgets.OkDialog;
import docking.widgets.OptionDialog;
import docking.widgets.dialogs.InputDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.label.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.GenericRunInfo;
import ghidra.framework.client.*;
import ghidra.framework.main.datatable.ProjectDataTablePanel;
import ghidra.framework.main.datatree.ClearCutAction;
import ghidra.framework.main.datatree.ProjectDataTreePanel;
import ghidra.framework.main.projectdata.actions.*;
import ghidra.framework.model.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.framework.remote.User;
import ghidra.util.*;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;
import resources.ResourceManager;

/**
 * Main plugin component for the Ghidra Project Window, which is
 * a PluginTool. This plugin manages all of the GUI elements, e.g., the
 * Data tree panel, view panels for other projects, etc.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = "Ghidra Core",
	category = PluginCategoryNames.COMMON,
	shortDescription = "Front End",
	description = "Front End Components for Ghidra",
	servicesProvided = { FrontEndService.class }
)
//@formatter:on
public class FrontEndPlugin extends Plugin
		implements FrontEndService, RemoteAdapterListener, ProgramaticUseOnly {

	private final static String TITLE_PREFIX = "Ghidra: ";
	private final static String EXPORT_TOOL_ACTION_NAME = "Export Tool";
	private final static String DELETE_TOOL_ACTION_NAME = "Delete Tool";
	private final static String CLOSE_TOOL_ACTION_NAME = "Close Tool";
	private final static String PROPERTIES_ACTION_NAME = "Configure Plugins";

	private JPanel mainGuiPanel;
	private ProjectToolBar toolBar;
	private ProjectDataTreePanel dataTreePanel;
	private ProjectDataTablePanel dataTablePanel;
	private ToolButtonTransferable toolButtonTransferable;
	private WorkspacePanel workspacePanel;
	private Project activeProject;
	private ProjectManager projectManager;

	/**
	 * the sash panel that contains the active project data and
	 * optionally any opened project data views that are displayed
	 * when the user requests to view other project(s)
	 */
	private ProjectDataPanel projectDataPanel;

	/**
	 * the main scrollable status area used by the DataManager
	 * and ToolManager to provide feedback to the user
	 */
	private LogPanel statusPanel;
	private String projectName;

	private FileActionManager fileActionManager;
	private ProjectActionManager projectActionManager;
	private ToolActionManager toolActionManager;

	// remove the "." from the project extension
	private static String PROJECT_EXTENSION = ProjectLocator.getProjectExtension().substring(1);

	private DockingAction closeToolAction;
	private DockingAction exportToolAction;
	private DockingAction deleteToolAction;
	private DockingAction propertiesAction;
	private ToolButtonAction renameToolAction;

	private JLabel repositoryLabel;
	private JLabel connectionLabel;
	private JPanel connectionIconPanel;
	private JButton connectionButton;

	static final Icon CONNECTED_ICON = ResourceManager.loadImage("images/connected.gif");
	static final Icon DISCONNECTED_ICON = ResourceManager.loadImage("images/disconnected.gif");
	private Icon emptyIcon = ResourceManager.loadImage("images/EmptyIcon.gif");

	private FrontEndProvider frontEndProvider;

	private ProjectDataCutAction cutAction;
	private ClearCutAction clearCutAction;
	private ProjectDataCopyAction copyAction;
	private ProjectDataPasteAction pasteAction;
	private ProjectDataRenameAction renameAction;
	private ProjectDataOpenDefaultToolAction openAction;
	private ProjectDataExpandAction expandAction;
	private ProjectDataCollapseAction collapseAction;
	private ProjectDataSelectAction selectAction;
	private ProjectDataReadOnlyAction readOnlyAction;
	private ProjectDataRefreshAction refreshAction;
	private ProjectDataNewFolderAction newFolderAction;
	private ProjectDataDeleteAction deleteAction;
	protected List<DockingAction> openActions = new ArrayList<>();

	private VersionControlAddAction addAction; // add to Version Control
	private VersionControlUpdateAction mergeAction;
	private VersionControlCheckInAction checkInAction;
	private VersionControlCheckOutAction checkOutAction;
	private VersionControlUndoCheckOutAction undoCheckOutsAction;
	private VersionControlShowHistoryAction historyAction;
	private VersionControlViewCheckOutAction viewCheckOutAction;
	private VersionControlUndoHijackAction undoHijackAction;
	private FindCheckoutsAction findCheckoutsAction;
	private ToolChestChangeListener toolChestChangeListener;

	/**
	 * Construct a new FrontEndPlugin. This plugin is constructed once when
	 * the Front end tool (Ghidra Project Window) is created. When a
	 * previously opened project is created, the Ghidra Project Window is
	 * restored to the state associated with that project.
	 * @param tool the front end tool
	 */
	public FrontEndPlugin(PluginTool tool) {
		super(tool);

		SystemUtilities.assertTrue(tool instanceof FrontEndTool,
			"FrontEndPlugin requires a FrontEndTool");
		projectActionManager = new ProjectActionManager(this);
		frontEndProvider = new FrontEndProvider(tool);
		tool.addComponentProvider(frontEndProvider, true);
		tool.setDefaultComponent(frontEndProvider);

		new EditActionManager(this);
		buildGui();

		toolChestChangeListener = new MyToolChestChangeListener();

		fileActionManager = new FileActionManager(this);
		toolActionManager = new ToolActionManager(this);
		setProjectName();

		createActions();
		createVersionControlActions();
		createToolSpecificOpenActions();
	}

	protected void createToolSpecificOpenActions() {
		for (DockingAction action : openActions) {
			tool.removeAction(action);
		}

		if (activeProject == null) {
			return;
		}
		ToolChest toolChest = activeProject.getLocalToolChest();
		if (toolChest == null) {
			return;
		}

		tool.setMenuGroup(new String[] { "Open With" }, "Open");

		ToolTemplate[] templates = toolChest.getToolTemplates();
		for (ToolTemplate toolTemplate : templates) {
			final String toolName = toolTemplate.getName();
			DockingAction toolAction =
				new ProjectDataOpenToolAction(getName(), "Open", toolName, toolTemplate.getIcon());
			tool.addAction(toolAction);
			openActions.add(toolAction);
		}
	}

	private void createActions() {
		String owner = getName();

		String groupName = "Cut/copy/paste/new1";
		newFolderAction = new FrontEndProjectDataNewFolderAction(owner, groupName);

		groupName = "Cut/copy/paste/new2";
		cutAction = new ProjectDataCutAction(owner, groupName);
		clearCutAction = new ClearCutAction(owner);
		copyAction = new ProjectDataCopyAction(owner, groupName);
		pasteAction = new ProjectDataPasteAction(owner, groupName);

		groupName = "Delete/Rename";
		renameAction = new ProjectDataRenameAction(owner, groupName);
		deleteAction = new ProjectDataDeleteAction(owner, groupName);
		openAction = new ProjectDataOpenDefaultToolAction(owner, "Open");

		groupName = "Expand/Collapse";
		expandAction = new FrontEndProjectDataExpandAction(owner, groupName);
		collapseAction = new FrontEndProjectDataCollapseAction(owner, groupName);

		groupName = "Select/Toggle";
		selectAction = new ProjectDataSelectAction(owner, groupName);
		readOnlyAction = new ProjectDataReadOnlyAction(owner, groupName);

		groupName = "XRefresh";
		refreshAction = new ProjectDataRefreshAction(owner, groupName);

		tool.addAction(newFolderAction);
		tool.addAction(cutAction);
		tool.addAction(clearCutAction);
		tool.addAction(copyAction);
		tool.addAction(pasteAction);
		tool.addAction(deleteAction);
		tool.addAction(openAction);
		tool.addAction(renameAction);
		tool.addAction(expandAction);
		tool.addAction(collapseAction);
		tool.addAction(selectAction);
		tool.addAction(readOnlyAction);
		tool.addAction(refreshAction);
	}

	private void createVersionControlActions() {
		String owner = getName();

		// in the toolbar
		addAction = new VersionControlAddAction(this);

		checkOutAction = new VersionControlCheckOutAction(this);

		mergeAction = new VersionControlUpdateAction(this);

		checkInAction = new VersionControlCheckInAction(this, projectDataPanel);

		undoCheckOutsAction = new VersionControlUndoCheckOutAction(this);

		historyAction = new VersionControlShowHistoryAction(this);

		viewCheckOutAction = new VersionControlViewCheckOutAction(this);

		undoHijackAction = new VersionControlUndoHijackAction(this);

		findCheckoutsAction = new FindCheckoutsAction(owner, this);

		tool.addAction(addAction);
		tool.addAction(checkOutAction);
		tool.addAction(mergeAction);
		tool.addAction(checkInAction);
		tool.addAction(undoCheckOutsAction);
		tool.addAction(historyAction);
		tool.addAction(viewCheckOutAction);
		tool.addAction(undoHijackAction);
		tool.addAction(findCheckoutsAction);
	}

	FrontEndProvider getFrontEndProvider() {
		return frontEndProvider;
	}

	FrontEndTool getFrontEndTool() {
		return (FrontEndTool) tool;
	}

	public JComponent getComponent() {
		return mainGuiPanel;
	}

	@Override
	public void connectionStateChanged(final Object adapter) {
		if (activeProject != null) {
			final RepositoryAdapter repository = activeProject.getRepository();
			if (repository == adapter) {
				Runnable r = () -> {
					updateConnectionPanel(activeProject);
					projectActionManager.connectionStateChanged((RepositoryAdapter) adapter);
					if (!activeProject.isClosed() && !repository.isConnected() &&
						repository.hadUnexpectedDisconnect()) {

						showDisconnectedDialog(repository);
					}
				};
				if (SwingUtilities.isEventDispatchThread()) {
					r.run();
				}
				else {
					SwingUtilities.invokeLater(r);
				}
			}
		}
	}

	private void showDisconnectedDialog(final RepositoryAdapter repository) {

		// @formatter:off
		String message = "The Ghidra Server repository unexpectedly disconnected: " +
			repository +
			"\nThis can occur if your system becomes suspended or due to a server/network problem." +
			"\n \nRepository status and actions will be unavailable until" +
			"\nthe server connection is re-established.  Any files opened from the" +
			"\nserver may be forced to close as a result.";
		// @formatter:on

		OkDialog info = new OkDialog("Ghidra Server Error", message, DISCONNECTED_ICON);
		info.show(tool.getToolFrame());
	}

	/**
	 * Set the project manager; try to reopen the last project that was
	 * opened.
	 * @param pm the project manager
	 */
	void setProjectManager(ProjectManager pm) {
		this.projectManager = pm;
	}

	/**
	 * Sets the handle to the activeProject, as well as updating the
	 * active data tree to show the new active project's data
	 * @param project the active project
	 */
	void setActiveProject(Project project) {

		// clean up before setting the new project to be the active one
		if (activeProject != null) {

			// Remove the ToolChestListener from the closedProject
			ToolChest toolChest = activeProject.getLocalToolChest();
			toolChest.removeToolChestChangeListener(toolActionManager);
			toolChest.removeToolChestChangeListener(toolBar);
			toolChest.removeToolChestChangeListener(toolChestChangeListener);
			// Remove the repository listener
			RepositoryAdapter repository = activeProject.getRepository();
			if (repository != null) {
				repository.removeListener(this);
			}
		}

		// set the active project handle to the specified "new" project
		activeProject = project;

		// disable the menu entries that apply when no active project
		enableProjectMenuItems(project != null);

		// update the rest of the panels with new (or inactive) project
		toolBar.setActiveProject(project);
		projectDataPanel.setActiveProject(project);
		fileActionManager.setActiveProject(activeProject);
		projectActionManager.setActiveProject(activeProject);
		toolActionManager.setActiveProject(activeProject);
		if (project != null) {
			GenericRunInfo.setProjectsDirPath(project.getProjectLocator().getLocation());
		}

		workspacePanel.setActiveProject(project);
		// update the title bar and other panel's border titles
		setProjectName();
		updateConnectionPanel(project);

		if (activeProject != null) {

			// Add the toolMenu as a ToolChestListener on the new active project
			ToolChest toolChest = project.getLocalToolChest();
			toolChest.addToolChestChangeListener(toolActionManager);
			toolChest.addToolChestChangeListener(toolBar);
			toolChest.addToolChestChangeListener(toolChestChangeListener);
			createToolSpecificOpenActions();
			// Add the repository listener
			RepositoryAdapter repository = activeProject.getRepository();
			if (repository != null) {
				repository.addListener(this);
			}
		}

//        gui.validate();
	}

	/**
	 * sets the name of the project, using the default name if no project is active
	 */
	void setProjectName() {
		projectName =
			(activeProject == null ? ToolConstants.NO_ACTIVE_PROJECT : activeProject.getName());
		String title = TITLE_PREFIX + projectName;

		tool.setToolName(title);
		projectDataPanel.setBorder(projectName);
	}

	@Override
	public void writeDataState(SaveState saveState) {
		projectDataPanel.writeDataState(saveState);
	}

	@Override
	public void readDataState(SaveState saveState) {
		projectDataPanel.readDataState(saveState);
	}

	/**
	 * Exit the Ghidra application; the parameter indicates whether
	 * the user should be prompted to save the project that is about
	 * to be closed
	 */
	void exitGhidra() {
		boolean okToExit = closeActiveProject();
		if (okToExit) {
			System.exit(0);

		}
		else if (!tool.isVisible()) {
			tool.setVisible(true);
		}
	}

	private boolean closeActiveProject() {
		if (activeProject == null) {
			return true;
		}
		try {
			return fileActionManager.closeProject(true);
		}
		catch (Exception e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e); // Keep this.
			int result = OptionDialog.showOptionDialog(tool.getToolFrame(), "Close Project Failed",
				"Error Description: [ " + e + " ]" + "\n" +
					"=====> Do you wish to exit Ghidra, possibly losing changes? <=====",
				"Exit Ghidra (Possibly Lose Changes)", OptionDialog.ERROR_MESSAGE);
			if (result == OptionDialog.CANCEL_OPTION) {
				return false;
			}
		}
		return true;
	}

	/**
	 * general project utility that brings up a file chooser for
	 * the user to specify a directory and filename that are used
	 * for the Project location and name
	 * 
	 * @param fileChooser the chooser used to pick the project
	 * @param mode read-only or not
	 * @param preferenceName the preference property name used to save the last opened project
	 * @return the project locator for the opened project 
	 */
	ProjectLocator chooseProject(GhidraFileChooser fileChooser, String mode,
			String preferenceName) {
		boolean create = (mode.equals("Create")) ? true : false;
		fileChooser.setTitle(mode + " a Ghidra Project");
		fileChooser.setApproveButtonText(mode + " Project");
		fileChooser.setApproveButtonToolTipText(mode + " a Ghidra Project");
		fileChooser.setSelectedFile(null);

		boolean validInput = false;
		while (!validInput) {
			File file = fileChooser.getSelectedFile();

			if (file != null) {
				String path = file.getAbsoluteFile().getParent();
				String filename = file.getName();

				// strip off extension since the LocalRootFolder takes care of it
				if (filename.endsWith(PROJECT_EXTENSION)) {
					filename = filename.substring(0, filename.lastIndexOf(PROJECT_EXTENSION) - 1);
				}
				// if user enters the name of the project manually and leaves off
				// the extension, try to open or create using the extension
				else if (!create && filename.lastIndexOf(".") > path.lastIndexOf(File.separator)) {
					// treat opening a file without the ghidra extension as an error
					Msg.showError(getClass(), tool.getToolFrame(), "Invalid Project File",
						"Cannot open '" + file.getName() + "' as a Ghidra Project");
					continue;
				}
				if (!NamingUtilities.isValidProjectName(filename)) {
					Msg.showError(getClass(), tool.getToolFrame(), "Invalid Project Name",
						filename + " is not a valid project name");
					continue;
				}
				Preferences.setProperty(preferenceName, path);
				try {
					Preferences.store();
				}
				catch (Exception e) {
					Msg.debug(this,
						"Unexpected exception storing preferences to" + Preferences.getFilename(),
						e);
				}
				return new ProjectLocator(path, filename);
			}
			return null;
		}

		return null;
	}

	boolean confirmDelete(String message) {
		int option = OptionDialog.showOptionDialogWithCancelAsDefaultButton(tool.getToolFrame(),
			"Confirm Delete", "Are you sure you want to delete\n" + message, "Delete",
			OptionDialog.QUESTION_MESSAGE);

		return (option != OptionDialog.CANCEL_OPTION);
	}

	void selectFiles(final Set<DomainFile> files) {
		// Do this later in case any of the given files are newly created, which means that the
		// GUIs may have not yet been notified.
		SwingUtilities.invokeLater(() -> {
			// there was a delete bug; make the set unmodifiable to catch this earlier
			Set<DomainFile> unmodifiableFiles = Collections.unmodifiableSet(files);
			dataTreePanel.selectDomainFiles(unmodifiableFiles);
			dataTablePanel.setSelectedDomainFiles(unmodifiableFiles);
		});
	}

	final ProjectDataTreePanel getActiveDataTree() {
		return dataTreePanel;
	}

	final Project getActiveProject() {
		return activeProject;
	}

	final ProjectManager getProjectManager() {
		return projectManager;
	}

	public final Workspace getActiveWorkspace() {
		return workspacePanel.getActiveWorkspace();
	}

	final ProjectActionManager getProjectActionManager() {
		return projectActionManager;
	}

	final ToolActionManager getToolActionManager() {
		return toolActionManager;
	}

	final WorkspacePanel getWorkspacePanel() {
		return workspacePanel;
	}

	final ProjectDataPanel getProjectDataPanel() {
		return projectDataPanel;
	}

	final FileActionManager getFileActionManager() {
		return fileActionManager;
	}

	LogPanel getStatusPanel() {
		return statusPanel;
	}

	ActionContext getActionContext(ComponentProvider provider, MouseEvent e) {
		ActionContext actionContext = projectDataPanel.getActionContext(provider, e);
		if (actionContext == null) {
			if (e != null) {
				Component source = (Component) e.getSource();
				if (source instanceof ToolButton) {
					return new ActionContext(provider, source);
				}
			}
		}

		return actionContext;
	}

	ToolButtonTransferable getToolButtonTransferable() {
		return toolButtonTransferable;
	}

	void setToolButtonTransferable(ToolButtonTransferable t) {
		if (t == null && toolButtonTransferable != null) {
			toolButtonTransferable.clearTransferData();
		}
		toolButtonTransferable = t;
	}

	void updateToolConnectionDialog() {
		toolActionManager.updateConnectionDialog();
	}

	void rebuildRecentMenus() {
		fileActionManager.buildRecentProjectsMenu();
		projectActionManager.buildRecentViewsActions();
	}

	void newProject() {
		fileActionManager.newProject();
	}

	URL[] getRecentViewedProjects() {
		return projectManager.getRecentViewedProjects();
	}

	ProjectLocator[] getRecentProjects() {
		return projectManager.getRecentProjects();
	}

	/**
	 * Popup up file chooser dialog so the user can select the
	 * location for the exported tool file.
	 * @param template template to export
	 * @param msgSource source of status message for successful export
	 */
	void exportToolConfig(ToolTemplate template, String msgSource) {

		ToolTemplate updatedTeplate = getUpToDateTemplate(template);
		ToolServices services = activeProject.getToolServices();

		try {
			File savedFile = services.exportTool(updatedTeplate);
			if (savedFile != null) {
				Msg.info(this, msgSource + ": Successfully exported " + updatedTeplate.getName() +
					" to " + savedFile.getAbsolutePath());
			}
		}
		catch (Exception e) {
			Msg.showError(this, null, "Error Exporting Tool", "Error exporting tool tool", e);
		}
	}

	private ToolTemplate getUpToDateTemplate(ToolTemplate template) {

		ToolManager toolManager = activeProject.getToolManager();
		PluginTool[] runningTools = toolManager.getRunningTools();
		String templateName = template.getName();
		for (PluginTool runningTool : runningTools) {
			if (runningTool.getName().equals(templateName)) {
				return runningTool.getToolTemplate(true);
			}
		}

		return template;
	}

	private void updateConnectionPanel(Project project) {
		repositoryLabel.setText("     ");
		connectionIconPanel.remove(connectionLabel);
		if (connectionButton != null) {
			connectionIconPanel.remove(connectionButton);
		}
		if (project == null || project.getRepository() == null) {
			connectionLabel = new GIconLabel(emptyIcon);
			connectionIconPanel.add(connectionLabel);
			return;
		}

		RepositoryAdapter repository = project.getRepository();
		User user = null;
		boolean isConnected = repository.isConnected();
		connectionButton = new JButton(isConnected ? CONNECTED_ICON : DISCONNECTED_ICON);
		connectionButton.addActionListener(e -> connect());

		connectionButton.setContentAreaFilled(false);
		connectionButton.setSelected(isConnected);
		connectionButton.setBorder(
			isConnected ? BorderFactory.createBevelBorder(BevelBorder.LOWERED)
					: BorderFactory.createBevelBorder(BevelBorder.RAISED));
		connectionIconPanel.add(connectionButton);
		if (isConnected) {

			try {
				user = repository.getUser();
			}
			catch (IOException e) {
				Msg.debug(this, "Unexpected exception retrieving user from repository", e);
			}
		}
		repositoryLabel.setText(
			"Project Repository:   " + repository.getName() + getAccessString(user));

		String serverName = repository.getServerInfo().getServerName();
		connectionButton.setToolTipText(
			isConnected ? "Connected as '" + repository.getServer().getUser() + "' to " + serverName
					: HTMLUtilities.toHTML(
						"Disconnected from " + serverName + "\nActivate this button to connect"));
	}

	private void connect() {
		RepositoryAdapter repository = activeProject.getRepository();
		if (repository != null) {
			if (!repository.isConnected()) {
				try {
					repository.connect();
				}
				catch (NotConnectedException e) {
					// don't think this can happen
				}
				catch (IOException e) {
					ClientUtil.handleException(repository, e, "Repository Connection",
						getTool().getToolFrame());
				}
			}
		}
	}

	private String getAccessString(User user) {
		if (user == null) {
			return "";
		}
		if (user.isAdmin()) {
			return "   (Administrator)";
		}
		if (user.isReadOnly()) {
			return "   (Read Only)";
		}
		return "   (Read/Write)";
	}

	GhidraFileChooser createFileChooser(String preferenceName) {
		// start the browsing in the user's preferred project directory
		File projectDir = new File(GenericRunInfo.getProjectsDirPath());
		if (preferenceName != null) {
			String dirPath = Preferences.getProperty(preferenceName, null, true);
			if (dirPath != null) {
				projectDir = new File(dirPath);
			}
		}

		GhidraFileChooser fileChooser = new GhidraFileChooser(tool.getToolFrame());
		fileChooser.setCurrentDirectory(projectDir);
		fileChooser.setMultiSelectionEnabled(false);
		fileChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		fileChooser.setFileFilter(new GhidraFileFilter() {
			@Override
			public String getDescription() {
				return "Ghidra Projects (*" + ProjectLocator.getProjectExtension() + ")";
			}

			@Override
			public boolean accept(File pathname, GhidraFileChooserModel model) {
				String lowerCaseName = pathname.getName().toLowerCase();
				if (model.isDirectory(pathname)) {
					return !lowerCaseName.endsWith(ProjectLocator.getProjectDirExtension());
				}
				if (lowerCaseName.endsWith(ProjectLocator.getProjectExtension())) {
					return true;
				}
				return false;
			}
		});
		fileChooser.rescanCurrentDirectory();
		return fileChooser;
	}

	private void enableProjectMenuItems(boolean enabled) {
		// will get enabled based on what is selected in the data tree...
		toolActionManager.enableActions(enabled);
		projectActionManager.enableActions(enabled);
		fileActionManager.enableActions(enabled);

	}

	/**
	 * builds the gui for the new front end
	 */
	private void buildGui() {

		// create the major GUI components for the user interface

		toolBar = new ProjectToolBar(this);

		// build the panels used in the front end GUI
		buildPanels();

		createToolButtonActions();
	}

	@Override
	protected void dispose() {
		dataTablePanel.dispose();
		dataTreePanel.dispose();
	}

	private void buildPanels() {

		// build the status panel since some of the other panels update status
		// when there is an active project at start up
		statusPanel = new LogPanel(this);
		statusPanel.setHelpLocation(new HelpLocation("FrontEndPlugin", "StatusWindow"));

		dataTreePanel = new ProjectDataTreePanel(this);
		dataTablePanel = new ProjectDataTablePanel(this);

		dataTreePanel.setHelpLocation(new HelpLocation(getName(), "ProjectDataTree"));
		dataTablePanel.setHelpLocation(new HelpLocation(getName(), "ProjectDataTable"));
		workspacePanel = new WorkspacePanel(this);

		projectDataPanel = new ProjectDataPanel(this, dataTreePanel, dataTablePanel, projectName);

		JPanel connectionPanel = new JPanel();
		connectionPanel.setLayout(new BorderLayout());
		repositoryLabel = new GDLabel();
		repositoryLabel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 0));
		connectionIconPanel = new JPanel();
		connectionLabel = new GLabel();
		connectionIconPanel.add(connectionLabel);
		connectionPanel.add(repositoryLabel, BorderLayout.CENTER);
		connectionPanel.add(connectionIconPanel, BorderLayout.EAST);

		// construct the main panel to contain the toolbar and
		// data tree panels (active and read-only views)
		JPanel mainPanel = new JPanel(new BorderLayout());
		mainPanel.add(toolBar, BorderLayout.NORTH);
		mainPanel.add(projectDataPanel, BorderLayout.CENTER);

		JPanel bottomPane = new JPanel();
		bottomPane.setLayout(new BoxLayout(bottomPane, BoxLayout.Y_AXIS));
		bottomPane.add(workspacePanel);
		bottomPane.add(Box.createVerticalGlue());
		bottomPane.add(Box.createVerticalStrut(2));

		bottomPane.add(connectionPanel);
		bottomPane.add(statusPanel);
		bottomPane.add(Box.createVerticalGlue());

		mainGuiPanel = new JPanel(new BorderLayout(5, 5));
		mainGuiPanel.add(mainPanel, BorderLayout.CENTER);
		mainGuiPanel.add(bottomPane, BorderLayout.SOUTH);
	}

	private void createToolButtonActions() {

		exportToolAction = new ToolButtonAction(EXPORT_TOOL_ACTION_NAME) {
			@Override
			public void actionPerformed(ActionContext context) {
				ToolButton tb = (ToolButton) context.getContextObject();
				exportToolConfig(tb.getToolTemplate(), "ToolButton");
			}

			@Override
			boolean isEnabledForContext(ToolButton toolButton) {
				return !toolButton.isRunningTool();
			}
		};
		exportToolAction.setPopupMenuData(new MenuData(new String[] { "Export..." }, "tool"));
		exportToolAction.setHelpLocation(
			new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, EXPORT_TOOL_ACTION_NAME));

		deleteToolAction = new ToolButtonAction(DELETE_TOOL_ACTION_NAME) {
			@Override
			public void actionPerformed(ActionContext context) {
				ToolButton tb = (ToolButton) context.getContextObject();
				delete(tb.getToolTemplate().getName());
			}

			@Override
			boolean isEnabledForContext(ToolButton toolButton) {
				return !toolButton.isRunningTool();
			}

		};
		deleteToolAction.setPopupMenuData(new MenuData(new String[] { "Delete..." }, "tool"));
		deleteToolAction.setHelpLocation(
			new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, DELETE_TOOL_ACTION_NAME));

		closeToolAction = new ToolButtonAction(CLOSE_TOOL_ACTION_NAME) {
			@Override
			public void actionPerformed(ActionContext context) {
				ToolButton tb = (ToolButton) context.getContextObject();
				tb.closeTool();
			}

			@Override
			public boolean isEnabledForContext(ToolButton toolButton) {
				return toolButton.isRunningTool();
			}
		};
		closeToolAction.setPopupMenuData(new MenuData(new String[] { "Close" }, "tool"));
		closeToolAction.setHelpLocation(
			new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, CLOSE_TOOL_ACTION_NAME));

		renameToolAction = new ToolButtonAction("Rename Tool") {
			@Override
			public void actionPerformed(ActionContext context) {
				Object contextObject = context.getContextObject();
				if (!(contextObject instanceof ToolButton)) {
					return;
				}

				ToolButton toolButton = (ToolButton) contextObject;
				ToolTemplate toolTemplate = toolButton.getToolTemplate();
				if (isToolRunning(toolTemplate)) {
					Msg.showWarn(this, toolButton, "Unable to Rename", "You must first close " +
						"any running instances of a tool before you can rename");
					return;
				}

				String oldName = toolTemplate.getName();
				String newName = getNewToolName(oldName);
				if (newName == null) {
					return;
				}

				ToolChest localToolChest = activeProject.getLocalToolChest();
				localToolChest.remove(oldName);
				toolTemplate.setName(newName);
				localToolChest.addToolTemplate(toolTemplate);
			}

			private String getNewToolName(String currentName) {
				InputDialog inputDialog =
					new InputDialog("Rename Tool", "Please enter a new name: ", currentName);
				tool.showDialog(inputDialog);

				if (inputDialog.isCanceled()) {
					return null;
				}

				String newName = inputDialog.getValue();
				if (currentName.equals(newName)) {
					return null;
				}

				return newName;
			}

			@Override
			public boolean isEnabledForContext(ToolButton toolButton) {
				return true;
			}

			private boolean isToolRunning(ToolTemplate template) {
				ToolManager toolManager = activeProject.getToolManager();
				PluginTool[] runningTools = toolManager.getRunningTools();
				for (PluginTool runningTool : runningTools) {
					if (runningTool.getToolName().equals(template.getName())) {
						return true;
					}
				}
				return false;
			}

			@Override
			public boolean isValidContext(ToolButton toolButton) {
				return !toolButton.isRunningTool();
			}
		};
		renameToolAction.setPopupMenuData(new MenuData(new String[] { "Rename..." }, "tool"));
		renameToolAction.setHelpLocation(
			new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, "Rename Tool"));

		propertiesAction = new ToolButtonAction(PROPERTIES_ACTION_NAME) {
			@Override
			public void actionPerformed(ActionContext context) {
				ToolButton tb = (ToolButton) context.getContextObject();
				PluginTool pluginTool = tb.getRunningTool();
				pluginTool.showConfig(true, false);
			}

			@Override
			boolean isEnabledForContext(ToolButton toolButton) {
				if (toolButton.isRunningTool()) {
					PluginTool pluginTool = toolButton.getRunningTool();
					return pluginTool.isConfigurable();
				}
				return false;
			}

		};
		propertiesAction.setPopupMenuData(
			new MenuData(new String[] { "Configure Plugins..." }, "zproperties"));

		propertiesAction.setHelpLocation(
			new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, "Configure_Tool"));

		tool.addLocalAction(frontEndProvider, exportToolAction);
		tool.addLocalAction(frontEndProvider, renameToolAction);
		tool.addLocalAction(frontEndProvider, deleteToolAction);
		tool.addLocalAction(frontEndProvider, closeToolAction);
		tool.addLocalAction(frontEndProvider, propertiesAction);
	}

	private void delete(String toolName) {
		if (!confirmDelete(toolName + " from your local tool chest?")) {
			return;
		}
		activeProject.getLocalToolChest().remove(toolName);
	}

	private abstract class ToolButtonAction extends DockingAction {
		ToolButtonAction(String name) {
			super(name, FrontEndPlugin.this.getName(), false);
			setEnabled(true);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			Object contextObject = context.getContextObject();
			if (contextObject instanceof ToolButton) {
				return isEnabledForContext((ToolButton) contextObject);
			}
			return false;
		}

		@Override
		public boolean isAddToPopup(ActionContext context) {
			if (!(context.getContextObject() instanceof ToolButton)) {
				return false;
			}
			return isValidContext((ToolButton) context.getContextObject());
		}

		abstract boolean isEnabledForContext(ToolButton toolButton);

		boolean isValidContext(ToolButton toolButton) {
			return isEnabledForContext(toolButton);
		}
	}

	@Override
	public void addProjectListener(ProjectListener l) {
		((FrontEndTool) tool).addProjectListener(l);
	}

	@Override
	public void removeProjectListener(ProjectListener l) {
		if (tool != null) { // tool is null when we've been disposed
			((FrontEndTool) tool).removeProjectListener(l);
		}
	}

	class FrontEndProvider extends ComponentProvider {
		public FrontEndProvider(PluginTool tool) {
			super(tool, "FrontEnd", "FrontEnd Tool");
			setTitle("Project Window");
			setDefaultWindowPosition(WindowPosition.TOP);
		}

		@Override
		public JComponent getComponent() {
			return FrontEndPlugin.this.getComponent();
		}

		@Override
		public ActionContext getActionContext(MouseEvent e) {
			return FrontEndPlugin.this.getActionContext(this, e);
		}

		@Override
		public HelpLocation getHelpLocation() {
			return new HelpLocation(FrontEndPlugin.this.getName(), "Project_Window");
		}
	}

	public void openDomainFile(DomainFile domainFile) {
		Project project = tool.getProject();
		final ToolServices toolServices = project.getToolServices();
		ToolTemplate defaultToolTemplate = toolServices.getDefaultToolTemplate(domainFile);

		if (defaultToolTemplate == null) {
			// assume no tools in the tool chest
			Msg.showInfo(this, tool.getToolFrame(), "Cannot Find Tool",
				"<html>Cannot find tool to open file: <b>" +
					HTMLUtilities.escapeHTML(domainFile.getName()) +
					"</b>.<br><br>Make sure you have an appropriate tool installed <br>from the " +
					"<b>Tools->Import Default Tools...</b> menu.  Alternatively, you can " +
					"use <b>Tool->Set Tool Associations</b> menu to change how Ghidra " +
					"opens this type of file");
			return;
		}

		ToolButton button = toolBar.getToolButtonForToolConfig(defaultToolTemplate);
		button.launchTool(domainFile);

	}

	private class MyToolChestChangeListener implements ToolChestChangeListener {

		@Override
		public void toolTemplateAdded(ToolTemplate toolTemplate) {
			createToolSpecificOpenActions();
		}

		@Override
		public void toolSetAdded(ToolSet toolset) {
			createToolSpecificOpenActions();
		}

		@Override
		public void toolRemoved(String toolName) {
			createToolSpecificOpenActions();
		}

	}
}
