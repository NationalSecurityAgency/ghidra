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

import java.awt.*;
import java.awt.event.ItemEvent;
import java.beans.PropertyChangeEvent;
import java.util.HashMap;

import javax.swing.*;
import javax.swing.border.Border;

import docking.help.Help;
import docking.help.HelpService;
import docking.widgets.combobox.GComboBox;
import docking.widgets.dialogs.InputDialog;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

class WorkspacePanel extends JPanel implements WorkspaceChangeListener {
	private final static long serialVersionUID = 1L;
	private final static String RUNNING_TOOLS_TITLE = "Running Tools";
	private final static Border ACTIVE_WORKSPACE_BORDER =
		BorderFactory.createTitledBorder(RUNNING_TOOLS_TITLE);
	private final static String NO_ACTIVE_WORKSPACE = "INACTIVE";
	private final static Border INACTIVE_BORDER =
		BorderFactory.createTitledBorder(RUNNING_TOOLS_TITLE + ": " + NO_ACTIVE_WORKSPACE);

	final static int TYPICAL_NUM_RUNNING_TOOLS = 3;

	private JComboBox<String> workspaceChooser;
	private DefaultComboBoxModel<String> workspaceModel;
	private CardLayout workspaceManager;
	private JPanel inactivePanel;
	private JPanel runningToolsCardPanel;
	private HashMap<String, RunningToolsPanel> runningToolsMap;
	private Workspace activeWorkspace;
	private FrontEndPlugin plugin;
	private Project activeProject;
	private boolean valueIsAdjusting;

	WorkspacePanel(FrontEndPlugin plugin) {
		super(new BorderLayout(0, 0));
		this.plugin = plugin;

		// create the plugin only to manage the running tools in the workspace(s)
		workspaceManager = new CardLayout();
		runningToolsCardPanel = new JPanel(workspaceManager);
		runningToolsMap = new HashMap<>(TYPICAL_NUM_RUNNING_TOOLS);

		// create the combo box that allows the user to choose which
		// workspace becomes active
		workspaceModel = new DefaultComboBoxModel<>();
		workspaceChooser = new GComboBox<>(workspaceModel);
		workspaceChooser.addItemListener(e -> {
			if (e.getStateChange() == ItemEvent.SELECTED) {
				chooseWorkspace((String) workspaceModel.getSelectedItem());
			}
		});
		workspaceChooser.setPreferredSize(
			new Dimension(200, (int) workspaceChooser.getPreferredSize().getHeight()));
		setHelpLocation();
		JPanel wcPanel = new JPanel();
		wcPanel.add(workspaceChooser);
		add(wcPanel, BorderLayout.EAST);
		add(runningToolsCardPanel, BorderLayout.CENTER);
		setBorder(INACTIVE_BORDER);

	}

	/**
	 * Tool was removed from the given workspace.
	 */
	@Override
	public void toolRemoved(Workspace ws, PluginTool tool) {
		removeTool(ws.getName(), tool);
		plugin.getToolActionManager().enableConnectTools();
	}

	/**
	 * Tool was added to the given workspace.
	 */
	@Override
	public void toolAdded(Workspace ws, PluginTool tool) {
		addTool(ws.getName(), tool);
		plugin.getToolActionManager().enableConnectTools();
	}

	/**
	 * called when a workspace is added by the ToolManager
	 */
	@Override
	public void workspaceAdded(Workspace ws) {
		if (ws == null) {
			return;
		}

		String wsName = ws.getName();

		RunningToolsPanel rtp = new RunningToolsPanel(plugin, ws);
		runningToolsCardPanel.add(rtp, wsName);
		runningToolsMap.put(wsName, rtp);

		workspaceModel.addElement(wsName);

		validate();
	}

	/**
	 * called when a workspace is removed by the ToolManager
	 */
	@Override
	public void workspaceRemoved(Workspace ws) {
		if (ws == null) {
			return;
		}

		String workspaceName = ws.getName();
		workspaceModel.removeElement(workspaceName);

		RunningToolsPanel rtp = runningToolsMap.get(workspaceName);
		runningToolsMap.remove(workspaceName);
		runningToolsCardPanel.remove(rtp);
	}

	/**
	 * called when a workspace is setActive() by the ToolManager
	 */
	@Override
	public void workspaceSetActive(Workspace ws) {
		if (ws == null) {
			throw new IllegalArgumentException("Active Workspace cannot be null");
		}
		workspaceSetActive(ws, ws.getName());
	}

	private void workspaceSetActive(Workspace ws, String workspaceName) {
		// set the active workspace handle
		activeWorkspace = ws;

		if (ws == null) {
			showInactiveWorkspace();
			return;
		}

		// show the right workspace in the chooser
		workspaceModel.setSelectedItem(workspaceName);

		// show the running tools in the specified workspace
		workspaceManager.show(runningToolsCardPanel, workspaceName);
		setPanelEnabled(true);

		setBorder(ACTIVE_WORKSPACE_BORDER);

		validate();
		repaint();
	}

	@Override
	public void propertyChange(PropertyChangeEvent event) {
		if (activeProject == null || activeWorkspace == null) {
			return;
		}

		// get the active workspace and type of property being changed
		String eventPropertyName = event.getPropertyName();

		// if this is a workspace name change, update our running
		// tools map so we can identify the runningToolsPanel properly
		if (eventPropertyName.equals(ToolManager.WORKSPACE_NAME_PROPERTY)) {
			String oldName = (String) event.getOldValue();
			String newName = (String) event.getNewValue();
			renameWorkspace(activeWorkspace, oldName, newName);
			return;
		}

		// if this is a change in a tool, update the running tools panel
		// containing the tool
		Object eventSource = event.getSource();
		if (eventSource instanceof PluginTool) {
			PluginTool tool = (PluginTool) eventSource;
			ToolTemplate template = tool.getToolTemplate(true);
			Icon icon = tool.getIconURL().getIcon();
			String workspaceName = activeWorkspace.getName();
			RunningToolsPanel rtp = runningToolsMap.get(workspaceName);
			if (eventPropertyName.equals(PluginTool.TOOL_NAME_PROPERTY)) {
				rtp.toolNameChanged(tool);
			}
			else {
				rtp.updateToolButton(tool, template, icon);
			}
		}
	}

	/**
	 * called whenever the active project changes or is being set for
	 * the first time
	 * @param project the project
	 */
	void setActiveProject(Project project) {
		// clear state from previous project
		clearAll();

		// if no active project, provide default workspace panel
		if (project == null) {
			showInactiveWorkspace();
			activeProject = null;
			return;
		}

		// set the workspace up to know about changes made to it in the framework
		// first remove ourselves from the previous project's tool manager's listeners
		if (activeProject != null) {
			ToolManager tm = activeProject.getToolManager();
			tm.removeWorkspaceChangeListener(this);
		}

		// now add ourselves to the new active project's tool manager's listeners
		ToolManager toolManager = project.getToolManager();
		toolManager.addWorkspaceChangeListener(this);

		PluginTool[] tools = toolManager.getRunningTools();
		for (PluginTool tool : tools) {
			tool.addPropertyChangeListener(this);
		}

		setPanelEnabled(true);
		this.activeProject = project;

		// because of timing of state being restored on projects
		// being opened and created by the ProjectManager, we initialize
		// our workspace state manually whenever a project is opened
		initProjectState(activeProject);
	}

	void addTool(String workspaceName, PluginTool runningTool) {
		RunningToolsPanel rtp = runningToolsMap.get(workspaceName);
		if (rtp != null) {
			rtp.addTool(runningTool);
			runningTool.addPropertyChangeListener(this);
		}
		validate();
		repaint();
	}

	/**
	 * adds a new empty workspace to the project with the name of the
	 * workspace set by the user; called from the Workspace menu.
	 */
	void addWorkspace() {
		// query the user for the name of the workspace
		InputDialog nameDialog = new InputDialog("Create New Workspace", "Workspace Name",
			ToolManager.DEFAULT_WORKSPACE_NAME);
		plugin.getTool().showDialog(nameDialog);
		if (nameDialog.isCanceled()) {
			return; // user canceled
		}

		String workspaceName = nameDialog.getValue();
		try {
			ToolManager tm = activeProject.getToolManager();
			tm.createWorkspace(workspaceName);
		}
		catch (DuplicateNameException e) {
			String msg = "Workspace named: " + workspaceName + " already exists.";
			Msg.showError(getClass(), plugin.getTool().getToolFrame(), "Workspace Name Exists",
				msg);
		}
	}

	/**
	 * used by the action listener on the combo-box workspace chooser
	 */
	private void chooseWorkspace(String workspaceName) {
		if (valueIsAdjusting) {
			return;
		}

		ToolManager tm = activeProject.getToolManager();
		Workspace[] workspaces = tm.getWorkspaces();
		Workspace ws = null;
		for (int w = 0; ws == null && w < workspaces.length; w++) {
			if (workspaces[w].getName().equals(workspaceName)) {
				ws = workspaces[w];
			}
		}

		if (ws != null) {
			ws.setActive();
		}
		else {
			// must have been a rename that set this and not the action
			// listener, so don't do anything
		}

	}

	/**
	 * removes the active workspace
	 */
	void removeWorkspace() {
		if (activeWorkspace == null) {
			return;
		}

		String workspaceName = activeWorkspace.getName();
		if (!plugin.confirmDelete("Workspace: " + workspaceName)) {
			return; // user canceled
		}

		// remove the workspace from the framework model
		ToolManager tm = activeProject.getToolManager();
		tm.removeWorkspace(activeWorkspace);
	}

	/**
	 * renames the active workspace
	 */
	void renameWorkspace() {
		if (activeWorkspace == null) {
			return;
		}
		boolean done = false;
		while (!done) {
			// query the user for the name of the workspace
			String workspaceName = activeWorkspace.getName();
			InputDialog nameDialog =
				new InputDialog("Rename Workspace", "Workspace Name", workspaceName);
			plugin.getTool().showDialog(nameDialog);
			if (nameDialog.isCanceled()) {
				return;
			}

			String newName = nameDialog.getValue();
			if (newName.equals(workspaceName)) {
				return;
			}
			if (newName.length() > 0) {

				try {
					activeWorkspace.setName(newName);
					// ToolManager will send a propertyChange event that we will
					// handle there when the name changes
					break;
				}
				catch (DuplicateNameException e) {
					Msg.showError(getClass(), plugin.getTool().getToolFrame(),
						"Error Renaming Workspace",
						"Workspace named: " + newName + " already exists.");
				}
			}
		}
	}

	private void renameWorkspace(Workspace ws, String oldName, String newName) {
		RunningToolsPanel rtp = runningToolsMap.get(oldName);
		runningToolsMap.remove(oldName);
		runningToolsMap.put(newName, rtp);

		// update the workspace model
		valueIsAdjusting = true;
		workspaceModel.removeElement(oldName);
		workspaceModel.addElement(newName);
		valueIsAdjusting = false;

		// remove the panel from our layout, and add it back in with the new name
		runningToolsCardPanel.remove(rtp);
		runningToolsCardPanel.add(rtp, newName);

		workspaceSetActive(ws, newName);
	}

	/**
	 * because of timing of state being restored on projects
	 * being opened and created by the ProjectManager, we initialize
	 * our workspace state manually whenever a project is opened
	 * This should ONLY be called by setActiveProject()!
	 */
	private void initProjectState(Project project) {
		// set this value so the workspaceAdded() routine doesn't set selected item
		// in the workspace chooser
		valueIsAdjusting = true;

		ToolManager tm = project.getToolManager();
		Workspace[] workspaces = tm.getWorkspaces();

		for (Workspace workspace : workspaces) {
			workspaceAdded(workspace);
		}

		valueIsAdjusting = false;

		workspaceSetActive(tm.getActiveWorkspace());
	}

	/**
	 * @return the active workspace for the project
	 */
	Workspace getActiveWorkspace() {
		return activeWorkspace;
	}

	/**
	 * Cause the specified workspace to be the active one
	 * NOTE: this workspace must already be known to the ToolManager
	 * @param ws the workspace
	 */
	void setActiveWorkspace(Workspace ws) {
		chooseWorkspace(ws.getName());
	}

	private void clearAll() {
		runningToolsMap.clear();

		workspaceModel.removeAllElements();

		runningToolsCardPanel.removeAll();

		validate();
	}

	private void showInactiveWorkspace() {
		// if this is the first time we're showing it, create it
		if (inactivePanel == null) {
			inactivePanel = new JPanel();
			runningToolsCardPanel.add(inactivePanel, NO_ACTIVE_WORKSPACE);
		}
		if (runningToolsCardPanel.getComponentCount() == 0) {
			runningToolsCardPanel.add(inactivePanel, NO_ACTIVE_WORKSPACE);
		}

		activeWorkspace = null;

		setPanelEnabled(false);
		workspaceManager.show(runningToolsCardPanel, NO_ACTIVE_WORKSPACE);
		setBorder(INACTIVE_BORDER);
	}

	private void removeTool(String workspaceName, PluginTool tool) {
		RunningToolsPanel rtp = runningToolsMap.get(workspaceName);
		if (rtp != null) {
			rtp.removeTool(tool);
			tool.removePropertyChangeListener(this);
		}
		validate();
		repaint();
	}

	private void setPanelEnabled(boolean enabled) {
		workspaceChooser.setEnabled(enabled);
		runningToolsCardPanel.setEnabled(enabled);
		validate();
		repaint();
	}

	private void setHelpLocation() {
		HelpService help = Help.getHelpService();
		help.registerHelp(workspaceChooser, new HelpLocation(plugin.getName(), "Workspace"));
	}
}
