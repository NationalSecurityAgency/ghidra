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
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.help.Help;
import docking.help.HelpService;
import docking.widgets.tabbedpane.DockingTabRenderer;
import ghidra.framework.main.datatable.ProjectDataTablePanel;
import ghidra.framework.main.datatree.ProjectDataTreePanel;
import ghidra.framework.model.*;
import ghidra.framework.options.SaveState;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * Manages the data tree for the active project, and the trees for the
 * project views.
 */
class ProjectDataPanel extends JSplitPane {
	private final static String BORDER_PREFIX = "Active Project: ";
	private final static String READ_ONLY_BORDER = "READ-ONLY Project Data";
	private final static int TYPICAL_NUM_VIEWS = 2;
	private final static int DIVIDER_SIZE = 2;
	private final static double DIVIDER_LOCATION = 0.50d;

	private static final String EXPANDED_PATHS = "EXPANDED_PATHS";

	private FrontEndPlugin frontEndPlugin;
	private JTabbedPane projectTab;
	private JTabbedPane readOnlyTab;
	private Map<ProjectLocator, ProjectDataTreePanel> readOnlyViews;
	private FrontEndTool tool;

	private ProjectDataTreePanel treePanel;
	private ProjectDataTablePanel tablePanel;
	private JPanel bugFixPanel;

	ProjectDataPanel(FrontEndPlugin plugin, ProjectDataTreePanel activePanel,
			ProjectDataTablePanel tablePanel, String projectName) {
		super();
		this.frontEndPlugin = plugin;
		this.tablePanel = tablePanel;
		tool = ((FrontEndTool) plugin.getTool());
		this.treePanel = activePanel;

		// initialize the table of views being managed
		readOnlyViews = new HashMap<>(TYPICAL_NUM_VIEWS);

		projectTab = new JTabbedPane(SwingConstants.BOTTOM);
		projectTab.setBorder(BorderFactory.createTitledBorder(BORDER_PREFIX));
		projectTab.addChangeListener(e -> frontEndPlugin.getTool().contextChanged(null));

		projectTab.addTab("Tree View", activePanel);
		projectTab.addTab("Table View", tablePanel);
		// setup the active data tree panel
		this.add(projectTab, JSplitPane.LEFT);
		projectTab.setBorder(BorderFactory.createTitledBorder(BORDER_PREFIX));

		// initialize the read-only project view tabbed pane
		// create a container panel just to have a title border because of a bug in
		// the JTabbedPane when you add custom tab renderers (which we will later)
		// 
		bugFixPanel = new JPanel(new BorderLayout());

		readOnlyTab = new JTabbedPane(SwingConstants.BOTTOM);
		bugFixPanel.add(readOnlyTab, BorderLayout.CENTER);
		bugFixPanel.setBorder(BorderFactory.createTitledBorder(READ_ONLY_BORDER));

		setHelpOnReadOnlyTab();
		this.add(bugFixPanel, JSplitPane.RIGHT);

		//setBorder(projectName);

		setViewsVisible(false);
	}

	private void setHelpOnReadOnlyTab() {
		HelpService help = Help.getHelpService();
		help.registerHelp(readOnlyTab,
			new HelpLocation(frontEndPlugin.getName(), "ReadOnlyProjectDataPanel"));
	}

	/**
	 * Populates the project views data tree panel(s) whenever a project is
	 * made active.
	 * If no project views are open, the tabbed pane is not visible.
	 */
	private void populateReadOnlyViews(Project project) {
//		readOnlyTab.setBorder(BorderFactory.createTitledBorder(READ_ONLY_BORDER));

		if (project == null) {
			setViewsVisible(false);
			return;
		}
		ProjectLocator[] views = project.getProjectViews();
		HelpLocation helpLocation =
			new HelpLocation(frontEndPlugin.getName(), "ReadOnlyProjectDataPanel");
		for (ProjectLocator view : views) {
			try {
				ProjectData projectData = project.getProjectData(view);
				ProjectLocator projectLocator = projectData.getProjectLocator();
				String viewName = projectLocator.getName();
				final ProjectDataTreePanel dtp =
					new ProjectDataTreePanel(viewName, false, frontEndPlugin, null); //not active,  no filter

				dtp.setProjectData(viewName, projectData);
				dtp.setHelpLocation(helpLocation);

				readOnlyTab.addTab(viewName, dtp);
				int index = readOnlyTab.indexOfComponent(dtp);
				readOnlyTab.setTabComponentAt(index, new DockingTabRenderer(readOnlyTab, viewName,
					viewName, e -> viewRemoved(dtp, getProjectURL(dtp), true)));
				readOnlyViews.put(view, dtp);
			}
			catch (Exception e) {
				Msg.showError(this, null, "Error", "Cannot restore project view", e);
			}
		}

		// update the close views menu and set the views pane visible
		// if we have open views
		setViewsVisible(views.length > 0);
	}

	private void clearReadOnlyViews() {
		readOnlyTab.removeAll();
		readOnlyViews.clear();
		setViewsVisible(false);
	}

	private void setViewsVisible(boolean visible) {
		bugFixPanel.setVisible(visible);
		this.setDividerSize(visible ? DIVIDER_SIZE : 0);
		this.setDividerLocation(visible ? DIVIDER_LOCATION : 1.0);
	}

	void openView(URL projectView) {
		ProjectManager projectManager = tool.getProjectManager();
		Project activeProject = tool.getProject();

		ProjectDataTreePanel dtp = getViewPanel(projectView);

		if (dtp != null) {
			readOnlyTab.setSelectedComponent(dtp);
			try {
				activeProject.addProjectView(projectView);
				projectManager.rememberViewedProject(projectView);
			}
			catch (Exception e) {
				projectManager.forgetViewedProject(projectView);
				Msg.showError(getClass(), tool.getToolFrame(), "Error Adding View", e.toString());
			}
			return;
		}

		try {
			// TODO: addProjectView should be done in a model task
			ProjectData projectData = activeProject.addProjectView(projectView);
			projectManager.rememberViewedProject(projectView);
			String viewName = projectData.getProjectLocator().getName();
			final ProjectDataTreePanel newPanel =
				new ProjectDataTreePanel(viewName, false /*isActiveProject*/, frontEndPlugin, null); // no filter

			newPanel.setProjectData(viewName, projectData);
			newPanel.setHelpLocation(
				new HelpLocation(frontEndPlugin.getName(), "ReadOnlyProjectDataPanel"));
			readOnlyTab.insertTab(viewName, null, newPanel, null, 0);
			int index = readOnlyTab.indexOfComponent(newPanel);
			readOnlyTab.setTabComponentAt(index, new DockingTabRenderer(readOnlyTab, viewName,
				viewName, e -> viewRemoved(newPanel, getProjectURL(newPanel), true)));
			readOnlyTab.setSelectedIndex(0);
			readOnlyViews.put(projectData.getProjectLocator(), newPanel);
			setViewsVisible(true);
		}
		catch (Exception e) {
			projectManager.forgetViewedProject(projectView);
			Msg.showError(getClass(), tool.getToolFrame(), "Error Adding View",
				"Failed to view project/repository: " + e.getMessage());
		}
		validate();
	}

	ProjectLocator[] getProjectViews() {
		int numViews = readOnlyViews.size();
		ProjectLocator[] projViews = new ProjectLocator[numViews];
		readOnlyViews.keySet().toArray(projViews);

		return projViews;
	}

	/**
	 * Get the project data for the given project view
	 * 
	 * @param projectView the locator for the project to retrieve
	 * @return null if project view was not found
	 */
	ProjectData getProjectData(ProjectLocator projectView) {
		ProjectDataTreePanel dtp = readOnlyViews.get(projectView);
		if (dtp != null) {
			return dtp.getProjectData();
		}
		return null;
	}

	/**
	 * remove (close) the specified project view
	 * @param projectView the url for the view to close
	 */
	void closeView(URL projectView) {
		Project activeProject = tool.getProject();
		if (activeProject == null) {
			Msg.showError(getClass(), tool.getToolFrame(), "Views Only Allowed With Active Project",
				"Cannot remove project view: " + projectView);
			return;
		}

		ProjectDataTreePanel dtp = getViewPanel(projectView);
		if (dtp == null) {
			Msg.showError(getClass(), tool.getToolFrame(), "Cannot Remove Project Not In View",
				"Project view: " + projectView + " not found.");
			return;
		}

		viewRemoved(dtp, projectView, false);
	}

	private ProjectDataTreePanel getViewPanel(URL projectView) {
		for (ProjectLocator locator : readOnlyViews.keySet()) {
			if (projectView.equals(locator.getURL())) {
				return readOnlyViews.get(locator);
			}
		}
		return null;
	}

	private void removeViewPanel(URL projectView) {
		for (ProjectLocator locator : readOnlyViews.keySet()) {
			if (projectView.equals(locator.getURL())) {
				readOnlyViews.remove(locator);
				break;
			}
		}
	}

	/**
	 * returns the ProjectURL for the current active view; null if no views open
	 * @return the ProjectURL for the current active view; null if no views open
	 */
	URL getCurrentView() {
		return getProjectURL(treePanel);
	}

	private URL getProjectURL(ProjectDataTreePanel panel) {
		return panel.getProjectData().getProjectLocator().getURL();
	}

	private void viewRemoved(Component view, URL url, boolean notify) {
		removeViewPanel(url);

		// remove the component from the tabbed pane
		readOnlyTab.remove(view);
		((ProjectDataTreePanel) view).dispose();

		// if we have no more views, hide the read-only tabbed pane
		if (readOnlyViews.size() == 0) {
			setViewsVisible(false);
		}
		tool.getProject().removeProjectView(url);
		validate();
	}

	void setActiveProject(Project project) {

		// close the current active data tree
		treePanel.closeRootFolder();

		// clear previous project views
		clearReadOnlyViews();

		// if we have a new active project, display its data tree
		if (project != null) {
			treePanel.setProjectData(project.getName(), project.getProjectData());
			tablePanel.setProjectData(project.getName(), project.getProjectData());
			populateReadOnlyViews(project);
		}
		else {
			tablePanel.setProjectData("No Active Project", null);
		}

		validate();

	}

	void setBorder(String projectName) {
		projectTab.setBorder(BorderFactory.createTitledBorder(BORDER_PREFIX + projectName));
		treePanel.updateProjectName(projectName);
	}

	ActionContext getActionContext(ComponentProvider provider, MouseEvent e) {
		Component comp = e == null ? projectTab.getSelectedComponent() : e.getComponent();

		while (comp != null) {
			if (comp instanceof JTabbedPane) {
				return new ActionContext(provider, comp);
			}
			if (comp instanceof ProjectDataTreePanel) {
				ProjectDataTreePanel panel = (ProjectDataTreePanel) comp;
				return panel.getActionContext(provider, e);
			}
			if (comp instanceof ProjectDataTablePanel) {
				ProjectDataTablePanel panel = (ProjectDataTablePanel) comp;
				return panel.getActionContext(provider, e);
			}
			comp = comp.getParent();
		}

		// the clicked component is not a child of a ProjectDataTreePanel--no context
		return null;
	}

	void writeDataState(SaveState saveState) {
		String[] expandedPaths = treePanel.getExpandedPathsByNodeName();
		if (expandedPaths == null || expandedPaths.length == 0) {
			return;
		}

		saveState.putStrings(EXPANDED_PATHS, expandedPaths);
		saveState.putBoolean("SHOW_TABLE", isTableShowing());
	}

	void readDataState(SaveState saveState) {
		String[] expandedPaths = saveState.getStrings(EXPANDED_PATHS, null);
		if (expandedPaths == null) {
			return;
		}
		treePanel.setExpandedPathsByNodeName(expandedPaths);
		boolean showTable = saveState.getBoolean("SHOW_TABLE", false);
		if (showTable) {
			showTable();
		}
	}

	private void showTable() {
		projectTab.setSelectedIndex(1);
	}

	private boolean isTableShowing() {
		return projectTab.getSelectedIndex() == 1;
	}

}
