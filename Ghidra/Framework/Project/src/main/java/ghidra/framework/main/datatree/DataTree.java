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
import java.awt.event.KeyEvent;

import javax.swing.*;
import javax.swing.tree.TreePath;

import docking.DockingUtils;
import docking.actions.KeyBindingUtils;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeRenderer;
import ghidra.framework.main.FrontEndTool;

/**
 * Tree that shows the folders and domain files in a Project
 */
public class DataTree extends GTree {

	private boolean isActive;
	private DataTreeDragNDropHandler dragNDropHandler;

	DataTree(FrontEndTool tool, GTreeNode root) {

		super(root);
		setName("Data Tree");
		setCellRenderer(new DataTreeCellRenderer());
		setShowsRootHandles(true); // need this to "drill down"

		ToolTipManager.sharedInstance().registerComponent(this);

		if (tool != null) {
			dragNDropHandler = new DataTreeDragNDropHandler(tool, this, isActive);
			setDragNDropHandler(dragNDropHandler);
		}

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

	void setProjectActive(boolean isActive) {
		if (dragNDropHandler != null) {
			dragNDropHandler.setProjectActive(isActive);
		}
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

	private class DataTreeCellRenderer extends GTreeRenderer {
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
