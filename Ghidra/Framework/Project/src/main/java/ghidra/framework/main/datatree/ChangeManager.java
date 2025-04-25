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

import java.io.IOException;
import java.util.*;
import java.util.function.Consumer;

import javax.swing.event.TreeModelEvent;
import javax.swing.event.TreeModelListener;
import javax.swing.tree.TreePath;

import docking.widgets.tree.GTreeNode;
import ghidra.framework.data.LinkHandler;
import ghidra.framework.main.datatree.DataTreeNode.NodeType;
import ghidra.framework.model.*;

/**
 * Class to handle changes when a domain folder changes; updates the
 * tree model to reflect added/removed/renamed nodes.
 */
class ChangeManager implements DomainFolderChangeListener, TreeModelListener {

	private DomainFolderRootNode root;
	private ProjectData projectData; // may be null
	private ProjectDataTreePanel treePanel;
	private DataTree tree;

	//
	// Link back-reference tree
	//   Associates file/folder-links with their referenced linked-files and folders.
	//   This tracking allows for rapid identification of link-related tree nodes which
	//   may be impacted by changes made to other files and folders.
	//
	private LinkedTreeNode linkTreeRoot = new LinkedTreeNode(null, null);

	private boolean skipLinkUpdate = false; // updates within Swing event dispatch thread only

	ChangeManager(ProjectDataTreePanel treePanel) {
		this.treePanel = treePanel;
		projectData = treePanel.getProjectData();
		tree = treePanel.getDataTree();
		root = (DomainFolderRootNode) tree.getModelRoot();
		if (projectData != null) {
			// Without a project this change manager does nothing (e.g., empty tree)
			projectData.addDomainFolderChangeListener(this);
			tree.addGTModelListener(this);
		}
	}

	void dispose() {
		if (projectData != null) {
			projectData.removeDomainFolderChangeListener(this);
			tree.removeGTModelListener(this);
			projectData = null;
		}
	}

	//
	// File Changes
	//

	@Override
	public void domainFileAdded(DomainFile file) {
		boolean isFolderLink = file.isLink() && file.getLinkInfo().isFolderLink();
		String fileName = file.getName();
		DomainFolder parentFolder = file.getParent();
		updateLinkedContent(parentFolder, p -> addFileNode(p, fileName, isFolderLink),
			ltn -> ltn.refreshLinks(fileName));
		DomainFolderNode folderNode = findDomainFolderNode(parentFolder, true);
		if (folderNode != null && folderNode.isLoaded()) {
			addFileNode(folderNode, fileName, isFolderLink);
		}
	}

	@Override
	public void domainFileRemoved(DomainFolder parent, String name, String fileID) {
		updateLinkedContent(parent, null, ltn -> ltn.refreshLinks(name));
		DomainFolderNode folderNode = findDomainFolderNode(parent, true);
		if (folderNode != null) {
			updateChildren(folderNode);
		}
	}

	@Override
	public void domainFileRenamed(DomainFile file, String oldName) {
		boolean isFolderLink = file.isLink() && file.getLinkInfo().isFolderLink();
		updateLinkedContent(file.getParent(), p -> {
			updateChildren(p);
			addFileNode(p, file.getName(), isFolderLink);
		}, ltn -> {
			ltn.refreshLinks(oldName);
			ltn.refreshLinks(file.getName());
		});
		DomainFolder parent = file.getParent();
		skipLinkUpdate = true;
		try {
			domainFileRemoved(parent, oldName, file.getFileID());
			domainFileAdded(file);
		}
		finally {
			skipLinkUpdate = false;
		}
	}

	@Override
	public void domainFileMoved(DomainFile file, DomainFolder oldParent, String oldName) {
		domainFileRemoved(oldParent, oldName, null);
		domainFileAdded(file);
	}

	@Override
	public void domainFileStatusChanged(DomainFile file, boolean fileIDset) {
		DomainFolder parentFolder = file.getParent();
		updateLinkedContent(parentFolder, fn -> {
			/* No folder update required */
		}, ltn -> ltn.refreshLinks(file.getName()));
		DomainFileNode fileNode = findDomainFileNode(file, true);
		if (fileNode != null) {
			fileNode.refresh();
		}
		treePanel.contextChanged();
	}

	//
	// Folder Changes
	//

	@Override
	public void domainFolderAdded(DomainFolder folder) {
		String folderName = folder.getName();
		DomainFolder parentFolder = folder.getParent();
		updateLinkedContent(parentFolder, p -> addFolderNode(p, folderName),
			ltn -> ltn.refreshLinks(folderName));
		DomainFolderNode folderNode = findDomainFolderNode(parentFolder, true);
		if (folderNode != null && folderNode.isLoaded()) {
			addFolderNode(folderNode, folderName);
		}
	}

	@Override
	public void domainFolderRemoved(DomainFolder parent, String name) {
		updateLinkedContent(parent, null, ltn -> ltn.refreshLinks(name));
		DomainFolderNode folderNode = findDomainFolderNode(parent, true);
		if (folderNode != null) {
			updateChildren(folderNode);
		}
	}

	@Override
	public void domainFolderRenamed(DomainFolder folder, String oldName) {
		updateLinkedContent(folder.getParent(), p -> {
			updateChildren(p);
			addFolderNode(p, folder.getName());
		}, ltn -> {
			ltn.refreshLinks(oldName);
			ltn.refreshLinks(folder.getName());
		});
		DomainFolder parent = folder.getParent();
		skipLinkUpdate = true;
		try {
			domainFolderRemoved(parent, oldName);
			domainFolderAdded(folder);
		}
		finally {
			skipLinkUpdate = false;
		}
	}

	@Override
	public void domainFolderMoved(DomainFolder folder, DomainFolder oldParent) {
		domainFolderRemoved(oldParent, folder.getName());
		domainFolderAdded(folder);
	}

	@Override
	public void domainFolderSetActive(DomainFolder folder) {
		DomainFolderNode folderNode = findDomainFolderNode(folder, false);
		if (folderNode != null) {
			tree.setSelectedNode(folderNode);
		}
	}

	//
	// Helper methods
	//

	private DomainFolder getDomainFolder(DataTreeNode node) {
		DomainFolder folder = null;
		if (node instanceof DomainFileNode fileNode) {
			folder = fileNode.getLinkedFolder(); // may return null
		}
		else if (node instanceof DomainFolderNode folderNode) {
			folder = folderNode.getDomainFolder();
		}
		return folder;
	}

	private void addFileNode(DataTreeNode node, String fileName, boolean isFolderLink) {
		if (node.isLeaf() || !node.isLoaded()) {
			return;
		}
		// Check for existance of file by that name
		DomainFileNode fileNode = (DomainFileNode) node.getChild(fileName,
			isFolderLink ? NodeType.FOLDER_LINK : NodeType.FILE);
		if (fileNode != null) {
			domainFileStatusChanged(fileNode.getDomainFile(), false);
			return;
		}
		DomainFolder folder = getDomainFolder(node);
		if (folder != null) {
			DomainFile file = folder.getFile(fileName);
			if (file != null) {
				DomainFileNode newNode = new DomainFileNode(file, root.getDomainFileFilter());
				node.addNode(newNode);
			}
		}
	}

	private void addFolderNode(DataTreeNode node, String folderName) {
		if (node.isLeaf() || !node.isLoaded()) {
			return;
		}
		// Check for existance of folder by that name
		if (node.getChild(folderName, NodeType.FOLDER) != null) {
			return;
		}
		DomainFolder folder = getDomainFolder(node);
		if (folder != null) {
			DomainFolder f = folder.getFolder(folderName);
			if (f != null) {
				DomainFolderNode newNode = new DomainFolderNode(f, root.getDomainFileFilter());
				node.addNode(newNode);
			}
		}
	}

	private void getFolderPath(DomainFolder df, List<String> list) {
		DomainFolder parent = df.getParent();
		if (parent != null) {
			getFolderPath(parent, list);
			list.add(df.getName());
		}
	}

	private DomainFolderNode findDomainFolderNode(DomainFolder df, boolean lazy) {
		ArrayList<String> folderPath = new ArrayList<String>();
		getFolderPath(df, folderPath);
		return findDomainFolderNode(folderPath, lazy);
	}

	private DomainFolderNode findDomainFolderNode(List<String> folderPath, boolean lazy) {
		DomainFolderNode folderNode = root;
		for (String name : folderPath) {
			if (lazy && !folderNode.isLoaded()) {
				return null; // not visited 
			}
			folderNode = (DomainFolderNode) folderNode.getChild(name, NodeType.FOLDER);
			if (folderNode == null) {
				return null;
			}
		}
		return folderNode;
	}

	private DomainFileNode findDomainFileNode(DomainFile domainFile, boolean lazy) {
		DomainFolderNode folderNode = findDomainFolderNode(domainFile.getParent(), lazy);
		if (folderNode == null) {
			return null;
		}
		if (lazy && !folderNode.isLoaded()) {
			return null; // not visited 
		}
		boolean isFolderLink = domainFile.isLink() && domainFile.getLinkInfo().isFolderLink();
		return (DomainFileNode) folderNode.getChild(domainFile.getName(),
			isFolderLink ? NodeType.FOLDER_LINK : NodeType.FILE);
	}

	/**
	 * Removes all children within the specified {@code parentNode} which no longer exist.
	 * @param parentNode parent node within tree
	 */
	private void updateChildren(DataTreeNode parentNode) {

		if (!parentNode.isLoaded()) {
			return;
		}

		DomainFolder folder = null;
		if (parentNode instanceof DomainFileNode fileNode) {
			folder = fileNode.getLinkedFolder();
		}
		else if (parentNode instanceof DomainFolderNode folderNode) {
			folder = folderNode.getDomainFolder();
		}
		if (folder == null) {
			return;
		}

		// loop through children looking for nodes whose underlying model object
		// does not have this folder as its parent;
		List<GTreeNode> children = parentNode.getChildren();
		for (GTreeNode child : children) {
			if (child instanceof DomainFileNode) {
				if (folder.getFile(child.getName()) == null) {
					parentNode.removeNode(child);
				}
			}
			else if (child instanceof DomainFolderNode) {
				if (folder.getFolder(child.getName()) == null) {
					parentNode.removeNode(child);
				}
			}
		}
	}

	//
	// DataTree listener
	//

	@Override
	public void treeStructureChanged(TreeModelEvent e) {

		// This is used when an existing node is loaded to register all of its link-file children
		// since the occurance of treeNodesChanged cannot be relied upon for notification of
		// these existing children.

		TreePath treePath = e.getTreePath();
		if (treePath == null) {
			return;
		}
		Object treeNode = treePath.getLastPathComponent();
		if (!(treeNode instanceof DataTreeNode dataTreeNode)) {
			return;
		}
		if (!dataTreeNode.isLoaded()) {
			return;
		}
		// Register all visible link-file nodes
		for (GTreeNode child : dataTreeNode.getChildren()) {
			if (child instanceof DomainFileNode fileNode) {
				if (fileNode.getDomainFile().isLink()) {
					addLinkFile(fileNode);
				}
			}
		}
	}

	@Override
	public void treeNodesChanged(TreeModelEvent e) {

		// This is used to register link-file nodes which may be added to the tree as a result
		// of changes to the associated project data.

		Object treeNode = e.getTreePath().getLastPathComponent();
		if (treeNode instanceof DomainFileNode fileNode) {
			addLinkFile(fileNode);
		}
	}

	@Override
	public void treeNodesInserted(TreeModelEvent e) {
		// Do nothing
	}

	@Override
	public void treeNodesRemoved(TreeModelEvent e) {
		// Do nothing
	}

	//
	// Link tracking tree update support
	//

	/**
	 * Update link tree if the specified {@code domainFileNode} corresponds to an link-file
	 * which has an internal link-path which links to either a file or folder within the same 
	 * project.  Removal of obsolete link details within the link tree is done is a lazy 
	 * fashion when refresh methods are invoked on a {@link LinkedTreeNode}.
	 * 
	 * @param domainFileNode domain file tree node
	 */
	void addLinkFile(DomainFileNode domainFileNode) {

		DomainFile file = domainFileNode.getDomainFile();

		LinkFileInfo linkInfo = file.getLinkInfo();
		if (linkInfo == null || linkInfo.isExternalLink()) {
			return;
		}

		try {
			String linkPath = LinkHandler.getAbsoluteLinkPath(file);
			if (linkPath == null) {
				return;
			}
			boolean isFolderLink = linkInfo.isFolderLink();
			String[] pathElements = linkPath.split("/");
			int lastFolderIndex = pathElements.length - 1;
			if (!isFolderLink) {
				--lastFolderIndex;
			}
			LinkedTreeNode folderLinkNode = linkTreeRoot;
			for (int i = 1; i <= lastFolderIndex; i++) {
				folderLinkNode = folderLinkNode.addFolder(pathElements[i]);
			}

			if (isFolderLink) {
				folderLinkNode.addLinkedFolder(domainFileNode);
			}
			else {
				folderLinkNode.addLinkedFile(pathElements[lastFolderIndex + 1], domainFileNode);
			}
		}
		catch (IOException e) {
			// ignore
		}
	}

	/**
	 * Perform updates of linked tree content which relate to content within the specified
	 * {@code parentFolder}.  All loaded folder linkages which include the specified 
	 * {@code parentFolder} will be checked and the specified {@code folderNodeConsumer} will
	 * be invoked for each parent tree node which is a linked-reflection of it to facilitate 
	 * specific updates. In addition, the specified {@code linkNodeConsumer} will be invoked 
	 * once if a {@code LinkedTreeNode} is found which corresponds to the specified 
	 * {@code parentFolder}.  This allows targeted refresh of link-files.
	 * 
	 * @param parentFolder a parent folder which relates to a change
	 * @param folderNodeConsumer optional consumer which will be invoked for each loaded parent 
	 * tree node which is a linked-reflection of the specified {@code parentFolder}.  If null is 
	 * specified for this consumer a general update will be performed to remove any missing nodes.
	 * @param linkNodeConsumer optional consumer which will be invoked once if a {@code LinkedTreeNode}
	 * is found which corresponds to the specified {@code parentFolder}.
	 */
	void updateLinkedContent(DomainFolder parentFolder, Consumer<DataTreeNode> folderNodeConsumer,
			Consumer<LinkedTreeNode> linkNodeConsumer) {
		if (skipLinkUpdate) {
			return;
		}
		String pathname = parentFolder.getPathname();
		String[] pathElements = pathname.split("/");
		LinkedTreeNode folderLinkNode = linkTreeRoot;
		folderLinkNode.updateLinkedContent(pathElements, 1, folderNodeConsumer);
		for (int i = 1; i < pathElements.length; i++) {
			folderLinkNode = folderLinkNode.folderMap.get(pathElements[i]);
			if (folderLinkNode == null) {
				return; // requested folder not contained within link-tree
			}
			folderLinkNode.updateLinkedContent(pathElements, i + 1, folderNodeConsumer);
		}

		// Requested folder was found in link-tree - invoke consumer to perform
		// selective refresh
		if (linkNodeConsumer != null) {
			linkNodeConsumer.accept(folderLinkNode);
		}
	}

	private class LinkedTreeNode {

		private final LinkedTreeNode parent;
		private final String name;

		private Map<String, LinkedTreeNode> folderMap = new HashMap<>();
		private Set<DomainFileNode> folderLinks = new HashSet<>();
		private Map<String, Set<DomainFileNode>> linkedFilesMap = new HashMap<>();

		LinkedTreeNode(LinkedTreeNode parent, String name) {
			this.parent = parent;
			this.name = name;
		}

		private void updateLinkedContent(String[] pathElements, int subFolderPathIndex,
				Consumer<DataTreeNode> folderNodeConsumer) {

			// NOTE: This logic will not handle recursively linked-folders which is not supported.

			boolean updateThisNode = subFolderPathIndex >= pathElements.length;

			for (DomainFileNode folderLink : folderLinks) {

				if (!folderLink.isLoaded()) {
					continue;
				}

				if (updateThisNode) {
					if (folderNodeConsumer != null) {
						folderNodeConsumer.accept(folderLink);
					}
					else {
						updateChildren(folderLink);
					}
					continue;
				}

				DomainFolderNode folderNode = null;
				for (int ix = subFolderPathIndex; ix < pathElements.length; ++ix) {
					folderNode =
						(DomainFolderNode) folderLink.getChild(pathElements[ix], NodeType.FOLDER);
					if (folderNode == null || !folderNode.isLoaded()) {
						folderNode = null;
						break;
					}
				}
				if (folderNode != null) {
					if (folderNodeConsumer != null) {
						folderNodeConsumer.accept(folderNode);
					}
					else {
						updateChildren(folderNode);
					}
				}
			}

		}

		private void refreshLinks(String childName) {
			// We are forced to refresh file-links and folder-links since a folder-link may be
			// referencing another folder-link file and not the final referenced folder.
			if (refreshFileLinks(childName) || refreshFolderLinks(childName)) {
				purgeFolderWithoutLinks();
			}
		}

		private boolean refreshFolderLinks(String folderName) {
			LinkedTreeNode linkedTreeNode = folderMap.get(folderName);
			if (linkedTreeNode != null) {
				refresh(linkedTreeNode.folderLinks);
				return linkedTreeNode.folderLinks.isEmpty();
			}
			return false;
		}

		private boolean refreshFileLinks(String fileName) {
			Set<DomainFileNode> linkFiles = linkedFilesMap.get(fileName);
			if (linkFiles != null) {
				refresh(linkFiles);
				if (linkFiles.isEmpty()) {
					linkedFilesMap.remove(fileName);
					return true;
				}
			}
			return false;
		}

		private LinkedTreeNode addFolder(String folderName) {
			return folderMap.computeIfAbsent(folderName, n -> new LinkedTreeNode(this, n));
		}

		private void addLinkedFolder(DomainFileNode folderLink) {
			folderLinks.add(folderLink);
		}

		private void addLinkedFile(String fileName, DomainFileNode fileLink) {
			Set<DomainFileNode> fileLinks =
				linkedFilesMap.computeIfAbsent(fileName, n -> new HashSet<>());
			fileLinks.add(fileLink);
		}

		private void purgeFolderWithoutLinks() {
			if (parent != null && folderMap.isEmpty() && folderLinks.isEmpty() &&
				linkedFilesMap.isEmpty()) {
				parent.folderMap.remove(name);
				parent.purgeFolderWithoutLinks();
			}
		}

		private static void refresh(Set<DomainFileNode> linkFiles) {
			List<DomainFileNode> purgeList = null;
			for (DomainFileNode fileLink : linkFiles) {
				DomainFile file = fileLink.getDomainFile();
				// Perform lazy purge of missing link files
				if (!file.isLink()) {
					if (purgeList == null) {
						purgeList = new ArrayList<>();
					}
					purgeList.add(fileLink);
				}
				else {
					fileLink.refresh();
				}
			}
			if (purgeList != null) {
				linkFiles.removeAll(purgeList);
			}
		}

		private String getPathname() {
			if (parent == null) {
				return "/";
			}
			return parent.getPathname() + name + "/";
		}

		@Override
		public String toString() {
			return getPathname();
		}

	}

}
