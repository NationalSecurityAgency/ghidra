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
import java.util.ArrayList;
import java.util.List;

import docking.DefaultActionContext;
import docking.widgets.tree.GTree;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.framework.model.DomainFile;
import ghidra.plugin.importer.ProjectIndexService;

/**
 * {@link FSBComponentProvider} context for actions
 */
public class FSBActionContext extends DefaultActionContext {

	private GTree gTree;

	/**
	 * Creates a new {@link FileSystemBrowserPlugin}-specific action context.
	 * 
	 * @param provider the ComponentProvider that generated this context.
	 * @param selectedNodes selected nodes in the tree
	 * @param event MouseEvent that caused the update, or null
	 * @param gTree {@link FileSystemBrowserPlugin} provider tree.
	 */
	public FSBActionContext(FSBComponentProvider provider,
			List<FSBNode> selectedNodes, MouseEvent event, GTree gTree) {
		super(provider, selectedNodes, gTree);
		this.gTree = gTree;
	}

	@Override
	public FSBComponentProvider getComponentProvider() {
		return (FSBComponentProvider) super.getComponentProvider();
	}

	@Override
	public List<FSBNode> getContextObject() {
		return getSelectedNodes();
	}

	@Override
	public GTree getSourceComponent() {
		return gTree;
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
		return !getSelectedNodes().isEmpty();
	}

	/**
	 * Returns a list of the currently selected tree nodes.
	 * 
	 * @return list of currently selected tree nodes
	 */
	public List<FSBNode> getSelectedNodes() {
		return (List<FSBNode>) super.getContextObject();
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
		List<FSBNode> selectedNodes = getSelectedNodes();
		if (selectedNodes.size() != 1) {
			return null;
		}
		FSBNode node = selectedNodes.get(0);
		FSRL fsrl = node.getFSRL();
		if (!dirsOk && node instanceof FSBRootNode fsRootNode &&
			fsRootNode.getContainer() != null) {
			// 'convert' a file system root node back into its container file
			return fsRootNode.getContainer();
		}

		return node.isLeaf() || dirsOk ? fsrl : null;
	}

	/**
	 * Returns true if the currently selected items are all directory items
	 * @return boolean true if the currently selected items are all directory items
	 */
	public boolean isSelectedAllDirs() {
		List<FSBNode> selectedNodes = getSelectedNodes();
		for (FSBNode node : selectedNodes) {
			if (node.isLeaf()) {
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
		List<FSBNode> selectedNodes = getSelectedNodes();
		return selectedNodes.size() == 1 ? selectedNodes.get(0) : null;
	}

	/**
	 * Returns the number of selected nodes in the tree.
	 * 
	 * @return returns the number of selected nodes in the tree.
	 */
	public int getSelectedCount() {
		return getSelectedNodes().size();
	}

	private List<FSRL> getFSRLsFromNodes(List<FSBNode> nodes, boolean dirsOk) {
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
		List<FSBNode> selectedNodes = getSelectedNodes();
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
	 * Returns the FSRL of the currently selected item, if it is a 'loadable' item.
	 * 
	 * @return FSRL of the currently selected loadable item, or null if nothing selected or
	 * more than 1 selected
	 */
	public FSRL getLoadableFSRL() {
		FSBNode node = getSelectedNode();
		return node != null ? node.getLoadableFSRL() : null;
	}

	public boolean hasSelectedLinkedNodes() {
		ProjectIndexService projectIndex = getComponentProvider().getProjectIndex();
		for (FSBNode node : getSelectedNodes()) {
			DomainFile df = projectIndex.findFirstByFSRL(node.getFSRL());
			if (df != null) {
				return true;
			}
		}
		return false;
	}

}
