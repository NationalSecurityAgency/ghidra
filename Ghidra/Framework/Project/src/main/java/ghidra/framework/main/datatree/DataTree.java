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

import java.awt.event.KeyEvent;
import java.io.IOException;

import javax.swing.KeyStroke;
import javax.swing.ToolTipManager;
import javax.swing.tree.TreePath;

import docking.DockingUtils;
import docking.action.DockingAction;
import docking.actions.KeyBindingUtils;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.framework.data.LinkHandler.LinkStatus;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.*;

/**
 * Tree that shows the folders and domain files in a Project
 */
public class DataTree extends GTree {

	private boolean isActive;
	private DataTreeDragNDropHandler dragNDropHandler;

	DataTree(FrontEndTool tool, GTreeNode root) {

		super(root);
		setName("Data Tree");
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

	@Override
	protected boolean isAddToPopup(DockingAction action) {

		String name = action.getName();
		switch (name) {
			case "Tree Expand All":
			case "Tree Expand Node":
			case "Tree Collapse Node":
				// case "Tree Collapse All": // this action seems ok
				return false;
			default:
				return true;
		}
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

	/**
	 * Method returns either a {@link DomainFolder} within the node's project or null.  
	 * The following cases indicate how the return value is established
	 * based on the specified {@link GTreeNode node}:
	 * <ol>  
	 * <li>{@link DomainFolderNode} - the node's domain folder will be returned</li>
	 * <li>{@link DomainFileNode} (folder-link content type) - the referenced folder within the node's 
	 * project will be returned under the following conditions, otherwise null will be returned:
	 * <ul>
	 * <li>The file corresponds to a folder-link, and</li>
	 * <li>the folder-link ultimately refers to a domain folder within the same project
	 * (i.e., a URL-based link path is not used and link status is {@link LinkStatus#INTERNAL}).</li>
	 * </ul></li>
	 * <li>{@link DomainFileNode} (normal file or file-link) - the node's parent folder will be
	 * returned.</li>
	 * </ol>
	 * <P>
	 * Folder-links which reference other internal folder-links will be followed until a
	 * folder can be identified or the link-chain is considered is {@link LinkStatus#BROKEN} 
	 * or {@link LinkStatus#EXTERNAL} in which case null will be returned.
	 * <P>
	 * A {@link LinkedDomainFolder} will always be resolved to its real folder which it corresponds to.
	 * 
	 * @param node Data Tree Node to be evaluated for its real internal folder
	 * @return internal project folder which corresponds to the specified node. 
	 */
	public static DomainFolder getRealInternalFolderForNode(GTreeNode node) {
		DomainFolder folder = null;
		if (node instanceof DomainFolderNode folderNode) {
			folder = folderNode.getDomainFolder();
		}
		else if (node instanceof DomainFileNode fileNode) {
			if (fileNode.isFolderLink()) {
				// Handle case where file node corresponds to a folder-link.
				// Folder-Link status needs to be checked to ensure it corresponds to a folder
				// internal to the same project.
				LinkFileInfo linkInfo = fileNode.getDomainFile().getLinkInfo();
				if (linkInfo == null) {
					return null; // unexpected
				}
				LinkStatus linkStatus = linkInfo.getLinkStatus(null);
				if (linkStatus != LinkStatus.INTERNAL) {
					return null;
				}
				// Get linked folder - status check ensures null will not be returned
				folder = linkInfo.getLinkedFolder();
			}
			else {
				// Handle normal file cases where we return node's parent folder
				GTreeNode parent = node.getParent();
				if (parent instanceof DomainFolderNode folderNode) {
					folder = folderNode.getDomainFolder();
				}
			}
		}
		if (folder instanceof LinkedDomainFolder linkedFolder) {
			// Resolve linked internal folder to its real folder
			try {
				folder = linkedFolder.getRealFolder();
			}
			catch (IOException e) {
				folder = null;
			}
		}
		return folder;
	}
}
