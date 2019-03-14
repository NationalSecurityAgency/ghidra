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

import java.awt.Component;
import java.awt.event.*;
import java.util.List;

import javax.swing.JTree;
import javax.swing.KeyStroke;
import javax.swing.tree.TreePath;

import docking.DockingUtils;
import docking.util.KeyBindingUtils;
import docking.widgets.tree.*;
import docking.widgets.tree.support.GTreeRenderer;
import ghidra.framework.main.FrontEndTool;

/**
 * Tree that shows the folders and domain files in a Project.
 */
public class DataTree extends GTree {
	static {
		DataFlavorHandlerService.registerDataFlavorHandlers();
	}

	private boolean isActive;
	private DataTreeDragNDropHandler dragNDropHandler;

	/**
	 * Constructor
	 * @param folder root domain folder for the project.
	 */
	DataTree(FrontEndTool tool, GTreeRootNode root) {

		super(root);
		setName("Data Tree");
		setCellRenderer(new DataTreeCellRenderer());
		setShowsRootHandles(true); // need this to "drill down"

		docking.ToolTipManager.sharedInstance().registerComponent(this);

		//When the user right clicks, change selection to what the mouse was under
		addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent evt) {
				if (evt.getButton() == MouseEvent.BUTTON3) {
					//Find the would-be newly selected path
					TreePath newPath = getPathForLocation(evt.getX(), evt.getY());
					if (newPath == null) {
						return;
					}
					//Determine if the path is already selected--If so, do not change the selection
					TreePath[] paths = getSelectionPaths();
					if (paths != null) {
						for (TreePath element : paths) {
							if (element.equals(newPath)) {
								return;
							}
						}
					}
				}
			}
		});
		dragNDropHandler = new DataTreeDragNDropHandler(tool, this, isActive);
		setDragNDropHandler(dragNDropHandler);
		initializeKeyEvents();
	}

	private void initializeKeyEvents() {

		// remove Java's default bindings for Copy/Paste on this tree, as they cause conflicts
		// with Ghidra's key bindings
		KeyBindingUtils.clearKeyBinding(getJTree(),
			KeyStroke.getKeyStroke(KeyEvent.VK_C, DockingUtils.CONTROL_KEY_MODIFIER_MASK));
		KeyBindingUtils.clearKeyBinding(getJTree(),
			KeyStroke.getKeyStroke(KeyEvent.VK_V, DockingUtils.CONTROL_KEY_MODIFIER_MASK));
		KeyBindingUtils.clearKeyBinding(getJTree(),
			KeyStroke.getKeyStroke(KeyEvent.VK_X, DockingUtils.CONTROL_KEY_MODIFIER_MASK));
	}

	void setProjectActive(boolean b) {
		dragNDropHandler.setProjectActive(b);
	}

	/**
	 * Return true if this path has all of its subpaths expanded.
	 */
	public boolean allPathsExpanded(TreePath path) {

		GTreeNode node = (GTreeNode) path.getLastPathComponent();
		if (node.isLeaf()) {
			return true;
		}
		if (isCollapsed(path)) {
			return false;
		}

		boolean allLeaves = true;

		List<GTreeNode> children = node.getChildren();
		for (GTreeNode child : children) {
			if (child.isLeaf()) {
				continue;
			}
			allLeaves = false;
			if (!isExpanded(child.getTreePath())) {
				return false;
			}

			if (!allPathsExpanded(child.getTreePath())) {
				return false;
			}
		}
		if (allLeaves) {
			return isExpanded(path);
		}
		return true;
	}

	/**
	 * Return true if this path has all of its subpaths collapsed.
	 */
	public boolean allPathsCollapsed(TreePath path) {
		GTreeNode node = (GTreeNode) path.getLastPathComponent();

		if (isExpanded(path)) {
			return false;
		}
		boolean allLeaves = true; // variable for knowing whether all children are leaves

		node.getChildren();
		for (GTreeNode child : node) {
			if (child.isLeaf()) {
				continue;
			}
			allLeaves = false;
			if (!isCollapsed(child.getTreePath())) {
				return false;
			}

			if (!allPathsCollapsed(child.getTreePath())) {
				return false;
			}
		}
		if (allLeaves) {
			return isCollapsed(path);
		}
		return true;
	}

	public void clearSelection() {
		getJTree().clearSelection();
	}

	public int getSelectionCount() {
		return getJTree().getSelectionCount();
	}

	public GTreeNode getLastSelectedPathComponent() {
		return (GTreeNode) getJTree().getLastSelectedPathComponent();
	}

	public void removeSelectionPath(TreePath path) {
		getJTree().removeSelectionPath(path);
	}

	@Override
	public void stopEditing() {
		getJTree().stopEditing();
	}

	//////////////////////////////////////////////////////////////////////
	// *** private methods
	//////////////////////////////////////////////////////////////////////
	/**
	 * Tree cell renderer to use the appropriate icons for the
	 * DataTreeNodes.
	 */
	private class DataTreeCellRenderer extends GTreeRenderer {

		/**
		 * Configures the renderer based on the passed in components.
		 * The icon is set according to value, expanded, and leaf
		 * parameters.
		 */
		@Override
		public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel,
				boolean expanded, boolean leaf, int row, boolean doesHaveFocus) {

			super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row,
				doesHaveFocus);
			if (value instanceof DomainFileNode) {
				DomainFileNode domainFileNode = (DomainFileNode) value;
				setText(domainFileNode.getDisplayName());
			}
			return this;
		}

	}

}
