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
package ghidra.plugins.fsbrowser;

import java.awt.event.MouseEvent;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.formats.gfilesystem.*;

/**
 * {@link FileSystemBrowserPlugin}-specific action.
 */
public class FSBActionContext extends ActionContext {

	private GTree gTree;

	/**
	 * Creates a new {@link FileSystemBrowserPlugin}-specific action context.
	 * 
	 * @param provider the ComponentProvider that generated this context.
	 * @param selectedNodes selected nodes in the tree
	 * @param event MouseEvent that caused the update, or null
	 * @param gTree {@link FileSystemBrowserPlugin} provider tree.
	 */
	public FSBActionContext(FileSystemBrowserComponentProvider provider, FSBNode[] selectedNodes,
			MouseEvent event, GTree gTree) {
		super(provider, selectedNodes, gTree);
		this.gTree = gTree;
	}

	/**
	 * Returns true if the GTree is not busy
	 * @return boolean true if GTree is not busy
	 */
	public boolean notBusy() {
		return !gTree.isBusy();
	}

	/**
	 * Returns true if the GTree is busy
	 * @return boolean true if the GTree is busy
	 */
	public boolean isBusy() {
		return gTree.isBusy();
	}

	/**
	 * Gets the {@link FileSystemBrowserPlugin} provider's  tree.
	 * 
	 * @return The {@link FileSystemBrowserPlugin} provider's  tree.
	 */
	public GTree getTree() {
		return gTree;
	}

	/**
	 * Returns true if there are selected nodes in the browser tree.
	 * 
	 * @return boolean true if there are selected nodes in the browser tree
	 */
	public boolean hasSelectedNodes() {
		FSBNode[] selectedNodes = (FSBNode[]) getContextObject();

		return selectedNodes.length > 0;
	}

	/**
	 * Returns a list of the currently selected tree nodes.
	 * 
	 * @return list of currently selected tree nodes
	 */
	public List<FSBNode> getSelectedNodes() {
		return List.of((FSBNode[]) getContextObject());
	}

	/**
	 * Returns the {@link FSRL} of the currently selected item, as long as it conforms to
	 * the dirsOk requirement.
	 * 
	 * @param dirsOk boolean flag, if true the selected item can be either a file or directory
	 * element, if false, it must be a file or the root of a file system that has a container
	 * file
	 * @return FSRL of the single selected item, null if no items selected or more than 1 item
	 * selected
	 */
	public FSRL getFSRL(boolean dirsOk) {
		FSBNode[] selectedNodes = (FSBNode[]) getContextObject();
		if (selectedNodes.length != 1) {
			return null;
		}
		FSBNode node = selectedNodes[0];
		FSRL fsrl = node.getFSRL();
		if (!dirsOk && node instanceof FSBRootNode && fsrlHasContainer(fsrl.getFS())) {
			// 'convert' a file system root node back into its container file
			return fsrl.getFS().getContainer();
		}

		boolean isDir = (node instanceof FSBDirNode) || (node instanceof FSBRootNode);
		if (isDir && !dirsOk) {
			return null;
		}

		return fsrl;
	}

	private boolean fsrlHasContainer(FSRLRoot fsFSRL) {
		return fsFSRL.hasContainer() && !fsFSRL.getProtocol().equals(LocalFileSystem.FSTYPE);
	}

	/**
	 * Returns true if the currently selected items are all directory items
	 * @return boolean true if the currently selected items are all directory items
	 */
	public boolean isSelectedAllDirs() {
		FSBNode[] selectedNodes = (FSBNode[]) getContextObject();
		for (FSBNode node : selectedNodes) {
			boolean isDir = (node instanceof FSBDirNode) || (node instanceof FSBRootNode);
			if (!isDir) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Returns the currently selected tree node
	 * 
	 * @return the currently selected tree node, or null if no nodes or more than 1 node is selected
	 */
	public FSBNode getSelectedNode() {
		FSBNode[] selectedNodes = (FSBNode[]) getContextObject();
		return selectedNodes.length == 1 ? selectedNodes[0] : null;
	}

	/**
	 * Returns the FSBRootNode that contains the currently selected tree node.
	 * 
	 * @return FSBRootNode that contains the currently selected tree node, or null nothing
	 * selected
	 */
	public FSBRootNode getRootOfSelectedNode() {
		return getRootOfNode(getSelectedNode());
	}

	private FSBRootNode getRootOfNode(GTreeNode tmp) {
		while (tmp != null && !(tmp instanceof FSBRootNode)) {
			tmp = tmp.getParent();
		}
		return (tmp instanceof FSBRootNode) ? (FSBRootNode) tmp : null;
	}

	/**
	 * Returns the number of selected nodes in the tree.
	 * 
	 * @return returns the number of selected nodes in the tree.
	 */
	public int getSelectedCount() {
		FSBNode[] selectedNodes = (FSBNode[]) getContextObject();
		return selectedNodes.length;
	}

	private List<FSRL> getFSRLsFromNodes(FSBNode[] nodes, boolean dirsOk) {
		List<FSRL> fsrls = new ArrayList<>();
		for (FSBNode node : nodes) {
			FSRL fsrl = node.getFSRL();
			if (!node.isLeaf() && !dirsOk) {
				boolean canConvertToContainerNode =
					node instanceof FSBRootNode && fsrl.getFS().hasContainer();
				if (!canConvertToContainerNode) {
					continue; // skip this node
				}
				// 'convert' a file system root node back into its container file node
				fsrl = fsrl.getFS().getContainer();
			}
			fsrls.add(fsrl);
		}
		return fsrls;
	}

	/**
	 * Returns a list of FSRLs of the currently selected nodes in the tree.
	 * 
	 * @param dirsOk boolean flag, if true the selected items can be either a file or directory
	 * element, if false, it must be a file or the root of a file system that has a container
	 * file before being included in the resulting list
	 * @return list of FSRLs of the currently selected items, maybe empty but never null
	 */
	public List<FSRL> getFSRLs(boolean dirsOk) {
		FSBNode[] selectedNodes = (FSBNode[]) getContextObject();
		return getFSRLsFromNodes(selectedNodes, dirsOk);
	}

	/**
	 * Returns a list of FSRLs of the currently selected file nodes in the tree.
	 * 
	 * @return list of FSRLs of the currently selected file items, maybe empty but never null
	 */
	public List<FSRL> getFileFSRLs() {
		return getFSRLs(false);
	}

	/**
	 * Returns the FSRL of the currently selected file node
	 * 
	 * @return FSRL of the currently selected file, or null if not file or more than 1 selected
	 */
	public FSRL getFileFSRL() {
		return getFSRL(false);
	}

	/**
	 * Converts the tree-node hierarchy of the currently selected item into a string path using
	 * "/" separators.
	 * 
	 * @return string path of the currently selected tree item
	 */
	public String getFormattedTreePath() {
		FSBNode[] selectedNodes = (FSBNode[]) getContextObject();
		if (selectedNodes.length != 1) {
			return null;
		}
		TreePath treePath = selectedNodes[0].getTreePath();
		StringBuilder path = new StringBuilder();
		for (Object pathElement : treePath.getPath()) {
			if (pathElement instanceof FSBNode) {
				FSBNode node = (FSBNode) pathElement;
				FSRL fsrl = node.getFSRL();
				if (path.length() != 0) {
					path.append("/");
				}
				String s;
				if (fsrl instanceof FSRLRoot) {
					s = fsrl.getFS().hasContainer() ? fsrl.getFS().getContainer().getName()
							: "/";
				}
				else {
					s = fsrl.getName();
				}
				path.append(s);
			}
		}

		return path.toString();
	}

	/**
	 * Returns the FSRL of the currently selected item, if it is a 'loadable' item.
	 * 
	 * @return FSRL of the currently selected loadable item, or null if nothing selected or
	 * more than 1 selected
	 */
	public FSRL getLoadableFSRL() {
		FSBNode node = getSelectedNode();
		if (node == null) {
			return null;
		}
		FSRL fsrl = node.getFSRL();
		if ((node instanceof FSBDirNode) || (node instanceof FSBRootNode)) {
			FSBRootNode rootNode = getRootOfSelectedNode();
			GFileSystem fs = rootNode.getFSRef().getFilesystem();
			if (fs instanceof GFileSystemProgramProvider) {
				GFile gfile;
				try {
					gfile = fs.lookup(node.getFSRL().getPath());
					if (gfile != null &&
						((GFileSystemProgramProvider) fs).canProvideProgram(gfile)) {
						return fsrl;
					}
				}
				catch (IOException e) {
					// ignore error and fall thru to normal file handling
				}
			}
		}
		if (node instanceof FSBRootNode && fsrl.getFS().hasContainer()) {
			// 'convert' a file system root node back into its container file
			return fsrl.getFS().getContainer();
		}
		return (node instanceof FSBFileNode) ? fsrl : null;
	}

	/**
	 * Returns a list of FSRLs of the currently selected loadable items.
	 * 
	 * @return list of FSRLs of currently selected loadable items, maybe empty but never null
	 */
	public List<FSRL> getLoadableFSRLs() {
		FSBNode[] selectedNodes = (FSBNode[]) getContextObject();

		List<FSRL> fsrls = new ArrayList<>();
		for (FSBNode node : selectedNodes) {
			FSRL fsrl = node.getFSRL();

			FSRL validated = vaildateFsrl(fsrl, node);
			if (validated != null) {
				fsrls.add(validated);
				continue;
			}
			else if (node instanceof FSBRootNode && fsrl.getFS().hasContainer()) {
				// 'convert' a file system root node back into its container file
				fsrls.add(fsrl.getFS().getContainer());
			}
			else if (node instanceof FSBFileNode) {
				fsrls.add(fsrl);
			}
		}
		return fsrls;
	}

	private FSRL vaildateFsrl(FSRL fsrl, FSBNode node) {
		if ((node instanceof FSBDirNode) || (node instanceof FSBRootNode)) {
			FSBRootNode rootNode = getRootOfNode(node);
			GFileSystem fs = rootNode.getFSRef().getFilesystem();
			if (fs instanceof GFileSystemProgramProvider) {
				GFile gfile;
				try {
					gfile = fs.lookup(node.getFSRL().getPath());
					if (gfile != null &&
						((GFileSystemProgramProvider) fs).canProvideProgram(gfile)) {
						return fsrl;
					}
				}
				catch (IOException e) {
					// ignore error and return null
				}
			}
		}

		return null;
	}

}
