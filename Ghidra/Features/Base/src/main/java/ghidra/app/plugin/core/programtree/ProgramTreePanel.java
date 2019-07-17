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
package ghidra.app.plugin.core.programtree;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;

import ghidra.app.events.TreeSelectionPluginEvent;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GroupPath;
import ghidra.program.util.GroupView;

/**
 * Wrapper for a ProgramDnDTree that supports drag and drop and
 * option menus and actions for cut, paste, rename, delete, and
 * merge operations. This class generates ProgramTreeSelection events.
 */
class ProgramTreePanel extends JPanel implements ChangeListener {

	private Program program;
	private ProgramDnDTree tree;
	private JScrollPane scrollp;
	private DefaultTreeModel treeModel;
	private Comparator<TreePath> nodeComparator;
	private PluginTool tool;
	private ProgramTreePlugin plugin;

	/**
	 * Construct a new empty ProgramTree.
	 */
	ProgramTreePanel(String treeName, ProgramTreePlugin plugin) {
		super();
		this.plugin = plugin;
		create(treeName);
		initialize();

		// Disable tree expand/collapse on double-click. 
		if (tree != null) {
			tree.setToggleClickCount(0);
		}
	}

	// ChangeListener interface method
	/**
	 * Invoked when the target of the listener has changed its state.
	 * @param e  a ChangeEvent object
	 */
	@Override
	public void stateChanged(ChangeEvent e) {

		if (e.getSource() instanceof JViewport) {
			// note: this code is a workaround certain JVMs (VisualCafe,
			// jdk1.2.2) where the PageDown key is not handled correctly for
			// scrolling the JTree; the tree ends up a the bottom of the
			// viewport -- not desirable.
			JViewport viewport = (JViewport) e.getSource();
			Rectangle viewRect = viewport.getViewRect();

			Rectangle treeRect = tree.getBounds();
			if (viewRect.y < treeRect.y) {
				// force y position to be at the top of the viewport
				treeRect.y = 0;
				tree.setBounds(treeRect);
			}
			invalidate();
			validate();
		}
		else {
			tool.setConfigChanged(true);
		}
	}

	void setTreeName(String treeName) {
		tree.setTreeName(treeName);
	}

	/**
	 * Set the program.
	 */
	void setProgram(Program p) {

		tree.clearSelection();
		tree.setProgram(p);
		program = p;
		if (p != null) {
			ProgramNode root = (ProgramNode) treeModel.getRoot();
			tree.setViewPaths(new TreePath[] { root.getTreePath() });
		}
	}

	/**
	 * Get the program.
	 */
	Program getProgram() {
		return program;
	}

	/**
	 * Add a listener for this program tree.
	 */
	void addTreeListener(TreeListener l) {
		tree.addTreeListener(l);
	}

	/**
	 * Remove a listener for this program tree.
	 */
	void removeTreeListener() {
		tree.removeTreeListener();
	}

	/**
	 * Add the TreePath that corresponds to the given groupPath
	 * to the current view.
	 */
	void addGroupViewPath(GroupPath p) {
		tree.addGroupViewPath(p);
	}

	/**
	 * Use the paths in the GroupView to set the current view.
	 */
	void setGroupView(GroupView view) {

		int count = view.getCount();
		GroupPath[] gp = new GroupPath[count];

		for (int i = 0; i < count; i++) {
			gp[i] = view.getPath(i);
		}
		tree.setGroupViewPaths(gp);
	}

	void setGroupSelection(GroupPath[] groupPaths) {
		tree.setGroupSelection(groupPaths);
	}

	/**
	 * Get the currently viewed group paths.
	 */
	GroupView getGroupView() {
		ArrayList<TreePath> viewList = tree.getViewList();
		ArrayList<GroupPath> list = new ArrayList<GroupPath>();
		for (int i = 0; i < viewList.size(); i++) {
			TreePath p = viewList.get(i);
			ProgramNode node = (ProgramNode) p.getLastPathComponent();
			GroupPath gp = node.getGroupPath();
			if (gp != null) {
				list.add(gp);
			}
		}
		GroupPath[] gps = new GroupPath[list.size()];
		gps = list.toArray(gps);
		return new GroupView(gps);
	}

	/**
	 * Get the currently selected group paths.
	 * @return zero length array if no selection exists
	 */
	GroupPath[] getSelectedGroupPaths() {
		return tree.getSelectedGroupPaths();
	}

	/**
	 * Set whether this tree has focus.
	 */
	void setHasFocus(boolean state) {
		tree.setHasFocus(state);
	}

	ProgramNode prepareSelectionForPopup(MouseEvent event) {
		return tree.prepareSelectionForPopup(event);
	}

	GroupPath[] getViewedGroups() {
		ArrayList<TreePath> list = new ArrayList<TreePath>(tree.getViewList());
		Collections.sort(list, nodeComparator);
		GroupPath[] gp = new GroupPath[list.size()];
		for (int i = 0; i < gp.length; i++) {
			TreePath path = list.get(i);
			ProgramNode node = (ProgramNode) path.getLastPathComponent();
			gp[i] = node.getGroupPath();
		}
		return gp;
	}

	ProgramNode getSelectedNode() {
		if (tree.getSelectionCount() == 0) {
			return null;
		}
		return (ProgramNode) tree.getSelectionPath().getLastPathComponent();
	}

	/**
	 * Get the name of this tree which is the same name as the view in
	 * the program.
	 * @return String name of the tree
	 */
	String getTreeName() {
		return tree.getTreeName();
	}

	/**
	 * Get the actual JTree.
	 * @return ProgramDnDTree
	 */
	ProgramDnDTree getDnDTree() {
		return tree;
	}

	///////////////////////////////////////////////////////////////////////////
	// ** private methods **
	///////////////////////////////////////////////////////////////////////////

	/**
	 * Create a new TreeModel and add it to this panel.
	 */
	private void create(String treeName) {
		setLayout(new BorderLayout());
		ProgramNode root = null;

		root = new ProgramNode(null, "No Program");

		treeModel = new DefaultTreeModel(root);
		tree = new ProgramDnDTree(treeName, treeModel, plugin);

		scrollp = new JScrollPane(tree);
		scrollp.setPreferredSize(new Dimension(300, 300));

		add(scrollp, BorderLayout.CENTER);

		// add change listener on viewport to know when the pageDown
		// key is hit; see the stateChanged() method.
		scrollp.getViewport().addChangeListener(this);

		setFocusable(false);
	}

	/**
	 * Initialize variables.
	 */
	private void initialize() {
		addListeners();
		nodeComparator = tree.getNodeComparator();
	}

	/**
	 * Fire the tree selection plugin event.
	 */
	private void fireSelectionEvent() {
		GroupPath[] groupPaths = getSelectedGroupPaths();
		plugin.firePluginEvent(
			new TreeSelectionPluginEvent(plugin.getName(), getTreeName(), groupPaths));
	}

	/**
	 * Set the action state depending on what the user double-clicked. 
	 * 
	 * Row = -1: The user clicked the expand/collapse icon.  Just nothing regarding
	 *           selection or the view.
	 * Row = 0+: The user clicked a node (root or fragment); select that node
	 *           for view.
	 */
	private void checkMouseEvent(MouseEvent e) {
		int selectedRow = tree.getRowForLocation(e.getX(), e.getY());

		if (selectedRow < 0) {
			return;
		}

		if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
			TreePath path = tree.getPathForRow(selectedRow);
			ProgramNode node = (ProgramNode) path.getLastPathComponent();
			plugin.doubleClick(node);
		}
	}

	void replaceView(ProgramNode node) {
		tree.setViewPaths(new TreePath[] { node.getTreePath() });
	}

	/**
	 * Handles mouse clicks on the program tree.
	 */
	private void addListeners() {

		tree.addMouseListener(new MouseAdapter() {

			@Override
			public void mouseClicked(MouseEvent e) {
				checkMouseEvent(e);
			}
		});
		tree.addTreeSelectionListener(new TreeSelectionListener() {
			@Override
			public void valueChanged(TreeSelectionEvent e) {
				fireSelectionEvent();
			}
		});
	}
}
