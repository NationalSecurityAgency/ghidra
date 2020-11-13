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
package ghidra.framework.main.datatree;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;

import javax.swing.JPanel;
import javax.swing.JTree;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.help.Help;
import docking.help.HelpService;
import docking.widgets.tree.*;
import docking.widgets.tree.support.DepthFirstIterator;
import docking.widgets.tree.support.GTreeSelectionListener;
import ghidra.framework.main.FrontEndPlugin;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Panel that contains a DataTree for showing project data.
 * Controls whether the data tree supports drag and drop operations.
 */
public class ProjectDataTreePanel extends JPanel {

	private static final String EXPANDED_PATHS_SEPARATOR = ":";

	private DataTree tree;
	private ProjectData projectData;
	private GTreeNode root;
	private DomainFileFilter filter;
	private ChangeManager changeMgr;
	private boolean isActiveProject;

	// these may be null if the panel is inside of a dialog
	private FrontEndTool tool;
	private FrontEndPlugin plugin;

	/**
	 * Construct an empty panel that is going to be used as the active panel
	 * @param plugin front end plugin
	 */
	public ProjectDataTreePanel(FrontEndPlugin plugin) {
		this(null, true, plugin, null);
	}

	/**
	 * Constructor
	 * 
	 * @param projectName name of project
	 * @param isActiveProject true if the project is active, and the
	 * data tree may be modified
	 * @param plugin front end plugin; will be null if the panel is used in a dialog
	 * @param filter optional filter that is used to hide programs from view
	 */
	public ProjectDataTreePanel(String projectName, boolean isActiveProject, FrontEndPlugin plugin,
			DomainFileFilter filter) {
		super(new BorderLayout());
		this.isActiveProject = isActiveProject;
		if (plugin != null) {
			this.tool = (FrontEndTool) plugin.getTool();
			this.plugin = plugin;
		}
		this.filter = filter;

		create(projectName);

		tree.addMouseListener(new MyMouseListener());
	}

	public TreeSelectionModel getTreeSelectionModel() {
		return tree.getSelectionModel();
	}

	/**
	 * Set the project data for this data tree and populate it with
	 * nodes for the users in the project.
	 * @param projectName name of project
	 * @param projectData data that has the root folder for the project
	 */
	public void setProjectData(String projectName, ProjectData projectData) {
		if (this.projectData != null) {
			this.projectData.removeDomainFolderChangeListener(changeMgr);
		}
		this.projectData = projectData;

		GTreeNode oldRoot = root;
		root = createRootNode(projectName);
		tree.setRootNode(root);
		oldRoot.dispose();

		changeMgr = new ChangeManager(this);
		projectData.addDomainFolderChangeListener(changeMgr);
		isActiveProject = projectData.getRootFolder().isInWritableProject();
		tree.setProjectActive(isActiveProject);
	}

	/**
	 * Update the project name
	 * @param newName the new name
	 */
	public void updateProjectName(String newName) {
		if (root instanceof DomainFolderRootNode) {
			((DomainFolderRootNode) root).setName(newName);
		}
	}

	/**
	 * Close the root folder for this data tree.
	 */
	public void closeRootFolder() {
		isActiveProject = false;
		tree.setProjectActive(false);
		GTreeNode oldRoot = root;
		root = new NoProjectNode();
		tree.setRootNode(root);
		oldRoot.removeAll();
	}

	/**
	 * Select the root data folder (not root node in the tree which
	 * shows the project name).
	 */
	public void selectRootDataFolder() {
		tree.setSelectionPath(root.getTreePath());
	}

	public void selectDomainFolder(DomainFolder domainFolder) {
		Iterator<GTreeNode> it = root.iterator(true);
		while (it.hasNext()) {
			GTreeNode child = it.next();
			if (child instanceof DomainFolderNode) {
				DomainFolder nodeFolder = ((DomainFolderNode) child).getDomainFolder();
				if (nodeFolder.equals(domainFolder)) {
					tree.expandPath(child);
					tree.setSelectedNode(child);
					return;
				}
			}
		}
	}

	public void selectDomainFiles(final Set<DomainFile> files) {
		tree.runTask(new SelectDomainFilesTask(tree, files));
	}

	private void doSelectDomainFiles(Set<DomainFile> files) {

		List<GTreeNode> nodes = getNodesForFiles(files);
		tree.setSelectedNodes(nodes);
	}

	private List<GTreeNode> getNodesForFiles(Set<DomainFile> files) {
		List<GTreeNode> nodes = new ArrayList<>();
		DepthFirstIterator it = new DepthFirstIterator(root);
		while (it.hasNext()) {
			GTreeNode node = it.next();
			if (node instanceof DomainFileNode) {
				DomainFile nodeFile = ((DomainFileNode) node).getDomainFile();
				if (files.contains(nodeFile)) {
					// it was in the list, add the the nodes list
					nodes.add(node);
				}
			}
		}

		return nodes;
	}

	public void selectDomainFile(DomainFile domainFile) {
		Iterator<GTreeNode> it = root.iterator(true);
		while (it.hasNext()) {
			GTreeNode child = it.next();
			if (child instanceof DomainFileNode) {
				DomainFile nodeFile = ((DomainFileNode) child).getDomainFile();
				if (nodeFile.equals(domainFile)) {
					tree.expandPath(child);
					tree.setSelectedNode(child);
					return;
				}
			}
		}
	}

	public void setHelpLocation(HelpLocation helpLocation) {
		HelpService help = Help.getHelpService();
		help.registerHelp(tree, helpLocation);
	}

	/**
	  * Set the filter on this data tree.
	  * @param filter determines what should be included in the data tree
	  */
	public void setDomainFileFilter(DomainFileFilter filter) {
		this.filter = filter;
	}

	/**
	 * Get the number of selected items in the tree.  These could be either files or folders.
	 * 
	 * @return the number of selected items in the tree.
	 */
	public int getSelectedItemCount() {
		return tree.getSelectionCount();
	}

	/**
	 * Get the last selected domain folder.
	 * @return null if no domain folder is selected.
	 */
	public DomainFolder getSelectedDomainFolder() {
		GTreeNode node = tree.getLastSelectedPathComponent();
		if (node instanceof DomainFolderNode) {
			return ((DomainFolderNode) node).getDomainFolder();
		}
		return null;
	}

	/**
	 * Get the last selected domain file.
	 * @return null if no domain file is selected.
	 */
	public DomainFile getSelectedDomainFile() {
		GTreeNode node = tree.getLastSelectedPathComponent();
		if (node instanceof DomainFileNode) {
			return ((DomainFileNode) node).getDomainFile();
		}
		return null;
	}

	/**
	 * Add the tree selection listener to the data tree. When the
	 * listener is notified of the selection change, it should
	 * call <code>getSelectedDomainFolder()</code> and
	 * <code>getSelectedDomainFile()</code> to get the last selected
	 * object.
	 * @param l listener to add
	 */
	public void addTreeSelectionListener(GTreeSelectionListener l) {
		tree.addGTreeSelectionListener(l);
	}

	/**
	 * Remove the tree selection listener from the data tree.
	 * @param l listener to remove
	 */
	public void removeTreeSelectionListener(GTreeSelectionListener l) {
		tree.removeGTreeSelectionListener(l);
	}

	public void addTreeMouseListener(MouseListener l) {
		tree.addMouseListener(l);
	}

	public void removeTreeMouseListener(MouseListener l) {
		tree.removeMouseListener(l);
	}

	public void setPreferredTreePanelSize(Dimension d) {
		tree.setPreferredSize(d);
	}

	public ProjectData getProjectData() {
		return projectData;
	}

	/**
	 * Notification that the project was renamed; update the root node name
	 * and reload the node
	 * @param newName the new project name
	 */
	public void projectRenamed(String newName) {
		updateProjectName(newName);
	}

	public void dispose() {
		if (projectData != null) {
			projectData.removeDomainFolderChangeListener(changeMgr);
		}
		tree.dispose();
	}

	/**
	 * Get the data tree node that is selected
	 * 
	 * @param provider the provider with which to construct the new context 
	 * @param e mouse event for the popup; may be null if this is being called as a result of 
	 *        the key binding pressed
	 * @return the new context; null if there is no selection
	 */
	public ActionContext getActionContext(ComponentProvider provider, MouseEvent e) {
		if (root instanceof NoProjectNode) {
			return null;
		}

		if (e != null) {
			Component component = e.getComponent();
			if (!(component instanceof JTree)) {
				return null;
			}
		}

		TreePath[] selectionPaths = tree.getSelectionPaths();

		List<DomainFile> domainFileList = new ArrayList<>();
		List<DomainFolder> domainFolderList = new ArrayList<>();

		for (TreePath treePath : selectionPaths) {
			GTreeNode node = (GTreeNode) treePath.getLastPathComponent();
			if (node instanceof DomainFolderNode) {
				domainFolderList.add(((DomainFolderNode) node).getDomainFolder());
			}
			else if (node instanceof DomainFileNode) {
				domainFileList.add(((DomainFileNode) node).getDomainFile());
			}
		}

		// provider is null when called from the DataTreeDialog, use different context
		if (provider == null) {
			return new DialogProjectTreeContext(projectData, selectionPaths, domainFolderList,
				domainFileList, tree);
		}

		return new FrontEndProjectTreeContext(provider, projectData, selectionPaths,
			domainFolderList, domainFileList, tree, isActiveProject);
	}

	public DataTree getDataTree() {
		return tree;
	}

	/**
	 * Adds or removes the filter from the tree.
	 * 
	 * @param enabled Tree adds the filter; false removes it
	 */
	public void setTreeFilterEnabled(boolean enabled) {
		tree.setFilterVisible(enabled);
	}

	public String[] getExpandedPathsByNodeName() {
		List<TreePath> expandedPaths = tree.getExpandedPaths(root);
		if (expandedPaths == null || expandedPaths.size() == 0) {
			return null;
		}

		String[] pathsArray = new String[expandedPaths.size()];
		Iterator<TreePath> iterator = expandedPaths.iterator();
		for (int counter = 0; iterator.hasNext(); counter++) {
			StringBuffer buffy = new StringBuffer();
			TreePath treePath = iterator.next();
			Object[] path = treePath.getPath();
			for (Object object : path) {
				GTreeNode node = (GTreeNode) object;
				buffy.append(node.getName()).append(EXPANDED_PATHS_SEPARATOR);
			}
			pathsArray[counter] = buffy.toString();
		}
		return pathsArray;
	}

	public void setExpandedPathsByNodeName(String[] stringPaths) {
		List<TreePath> paths = new ArrayList<>();
		for (String string : stringPaths) {
			String[] pathParts = string.split(EXPANDED_PATHS_SEPARATOR);
			TreePath treePath = getFolderTreePathForStringPath(pathParts);
			if (treePath != null) {
				paths.add(treePath);
			}
		}
		tree.expandPaths(paths);
	}

	private TreePath getFolderTreePathForStringPath(String[] pathParts) {
		if (pathParts.length == 0) {
			return null;
		}
		Object[] nodeParts = new Object[pathParts.length];
		GTreeNode searchNode = root;
		nodeParts[0] = root;
		for (int i = 1; i < pathParts.length; i++) {
			GTreeNode node = findFolderNodeChild(searchNode, pathParts[i]);
			if (node == null) {
				return null; // bad path
			}
			nodeParts[i] = node;
			searchNode = node;
		}
		return new TreePath(nodeParts);
	}

	private GTreeNode findFolderNodeChild(GTreeNode node, String text) {
		List<GTreeNode> children = node.getChildren();
		for (GTreeNode child : children) {
			if ((child instanceof DomainFolderNode) && child.getName().equals(text)) {
				return child;
			}
		}
		return null;
	}

	private void create(String projectName) {

		root = createRootNode(projectName);

		tree = new DataTree(tool, root);

		if (plugin != null) {
			tree.addGTreeSelectionListener(e -> {
				PluginTool pluginTool = plugin.getTool();
				pluginTool.contextChanged(null);
			});
		}

		add(tree, BorderLayout.CENTER);

		tree.setProjectActive(isActiveProject);
	}

	void domainChange() {
		if (plugin == null) {
			return;
		}

		plugin.getTool().contextChanged(null);
	}

	/**
	 * Create the root node for this data tree.
	 */
	private GTreeNode createRootNode(String projectName) {
		if (projectData == null) {
			return new NoProjectNode();
		}
		return new DomainFolderRootNode(projectName, projectData.getRootFolder(), projectData,
			filter);
	}

	public void checkOpen(MouseEvent e) {
		if (tool == null) { // dialog use
			return;
		}
		if (e.getButton() != MouseEvent.BUTTON1 || e.getClickCount() != 2) {
			return;
		}

		e.consume();
		Point point = e.getPoint();
		TreePath pathForLocation = tree.getPathForLocation(point.x, point.y);
		if (pathForLocation == null) {
			return;
		}

		GTreeNode node = (GTreeNode) pathForLocation.getLastPathComponent();
		if (!(node instanceof DomainFileNode)) {
			return;
		}

		DomainFile domainFile = ((DomainFileNode) node).getDomainFile();
		plugin.openDomainFile(domainFile);
	}

	/**
	 * Find a node that has the given name and select it.
	 * @param s node name
	 */
	public void findAndSelect(String s) {
		tree.expandTree(root);
		Iterator<GTreeNode> it = root.iterator(true);
		while (it.hasNext()) {
			GTreeNode node = it.next();
			if (node.getName().equals(s)) {
				tree.setSelectedNode(node);
				return;
			}
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class MyMouseListener extends MouseAdapter {
		@Override
		public void mousePressed(MouseEvent e) {
			checkOpen(e);
		}
	}

	private class SelectDomainFilesTask extends GTreeTask {

		private final Set<DomainFile> files;

		public SelectDomainFilesTask(GTree tree, Set<DomainFile> files) {
			super(tree);
			this.files = files;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			doSelectDomainFiles(files);
		}
	}
}
