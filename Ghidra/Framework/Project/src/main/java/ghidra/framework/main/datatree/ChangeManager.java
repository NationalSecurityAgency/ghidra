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
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.util.Msg;
import ghidra.util.Swing;

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

	// The refreshedTrackingSet is used to track recursive path refreshes to avoid infinite 
	// recursion.  See updateLinkedContent and LinkedTreeNode.refreshLinks methods.
	private HashSet<String> refreshedTrackingSet;

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
		updateLinkedContent(parentFolder.getPathname(), p -> addFileNode(p, fileName, isFolderLink),
			ltn -> ltn.refreshLinks(fileName));

		DomainFolderNode folderNode = findDomainFolderNode(parentFolder, true);
		if (folderNode != null && folderNode.isLoaded()) {
			addFileNode(folderNode, fileName, isFolderLink);
		}
	}

	@Override
	public void domainFileRemoved(DomainFolder parent, String name, String fileID) {

		updateLinkedContent(parent.getPathname(), null, ltn -> ltn.refreshLinks(name));

		DomainFolderNode folderNode = findDomainFolderNode(parent, true);
		if (folderNode != null) {
			updateChildren(folderNode);
		}
	}

	@Override
	public void domainFileRenamed(DomainFile file, String oldName) {

		boolean isFolderLink = file.isLink() && file.getLinkInfo().isFolderLink();
		updateLinkedContent(file.getParent().getPathname(), p -> {
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

		LinkFileInfo linkInfo = file.getLinkInfo();
		boolean isFolderLink = linkInfo != null && linkInfo.isFolderLink();

		DomainFolder parentFolder = file.getParent();
		updateLinkedContent(parentFolder.getPathname(), fn -> {
			// Refresh any linked folder content containing file
			if (fn.isLoaded()) {
				NodeType type = isFolderLink ? NodeType.FOLDER_LINK : NodeType.FILE;
				DomainFileNode fileNode = (DomainFileNode) fn.getChild(file.getName(), type);
				if (fileNode != null) {
					fileNode.refresh();
				}
			}
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
		updateLinkedContent(parentFolder.getPathname(), p -> addFolderNode(p, folderName),
			ltn -> ltn.refreshLinks(folderName));

		DomainFolderNode folderNode = findDomainFolderNode(parentFolder, true);
		if (folderNode != null && folderNode.isLoaded()) {
			addFolderNode(folderNode, folderName);
		}
	}

	@Override
	public void domainFolderRemoved(DomainFolder parent, String name) {

		updateLinkedContent(parent.getPathname(), null, ltn -> ltn.refreshLinks(name));

		DomainFolderNode folderNode = findDomainFolderNode(parent, true);
		if (folderNode != null) {
			updateChildren(folderNode);
		}
	}

	@Override
	public void domainFolderRenamed(DomainFolder folder, String oldName) {

		domainFolderMoved(folder.getParent().getPathname(), oldName, folder);

		skipLinkUpdate = true;
		try {
			domainFolderRemoved(folder.getParent(), oldName);
			domainFolderAdded(folder);
		}
		finally {
			skipLinkUpdate = false;
		}
	}

	@Override
	public void domainFolderMoved(DomainFolder folder, DomainFolder oldParent) {

		domainFolderMoved(oldParent.getPathname(), folder.getName(), folder);

		skipLinkUpdate = true;
		try {
			domainFolderRemoved(oldParent, folder.getName());
			domainFolderAdded(folder);
		}
		finally {
			skipLinkUpdate = false;
		}
	}

	@Override
	public void domainFolderSetActive(DomainFolder folder) {
		DomainFolderNode folderNode = findDomainFolderNode(folder, false);
		if (folderNode != null) {
			tree.setSelectedNode(folderNode);
		}
	}

	/**
	 * Following a folder move or rename where only a single notification is provided this
	 * method should be used to propogate link related updates which may refer to the affected
	 * folder or its children.  This method is invoked recursively for all child folders.
	 * @param oldParentPath folder's old parent path
	 * @param oldName folder's previous name
	 * @param folder folder instance following rename
	 */
	private void domainFolderMoved(String oldParentPath, String oldName, DomainFolder folder) {

		String oldFolderPathname = LocalFileSystem.getPath(oldParentPath, oldName);

		// Recurse over all child folders.
		for (DomainFolder childFolder : folder.getFolders()) {
			domainFolderMoved(oldFolderPathname, childFolder.getName(), childFolder);
		}

		// Refresh links to old placement
		updateLinkedContent(oldParentPath, null, ltn -> {
			ltn.refreshLinks(oldName);
		});

		// Refresh links to new placement
		String newName = folder.getName();
		updateLinkedContent(folder.getParent().getPathname(), p -> addFolderNode(p, newName),
			ltn -> {
				ltn.refreshLinks(newName);
			});
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

//	private List<String> getPathAsList(String pathname) {
//		ArrayList<String> folderPath = new ArrayList<String>();
//		String[] pathSplit = pathname.split(FileSystem.SEPARATOR);
//		for (int i = 1; i < pathSplit.length; i++) {
//			folderPath.add(pathSplit[i]);
//		}
//		return folderPath;
//	}
//
//	private DomainFolderNode findDomainFolderNode(String pathname, boolean lazy) {
//		List<String> folderPath = getPathAsList(pathname);
//		return findDomainFolderNode(folderPath, lazy);
//	}

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

		// NOTE: We have seen getTreePath return null in the test environment 
		// immediately before ChangeManager disposal

		TreePath treePath = e.getTreePath();

		Object[] changedChildren = e.getChildren();
		if (changedChildren != null) {
			for (Object child : changedChildren) {
				treeNodeChanged(child, true);
			}
		}
		else if (treePath != null) {
			treeNodeChanged(treePath.getLastPathComponent(), true);
		}
	}

	private void treeNodeChanged(Object treeNode, boolean processLoadedChildren) {

		if (!(treeNode instanceof DataTreeNode dataTreeNode)) {
			return;
		}

		if (treeNode instanceof DomainFileNode fileNode) {
			addLinkFile(fileNode);
		}

		// TODO: Not sure we need the following code
//		if (processLoadedChildren && dataTreeNode.isLoaded()) {
//			for (GTreeNode node : dataTreeNode.getChildren()) {
//				treeNodeChanged(node, true);
//			}
//		}
	}

	@Override
	public void treeNodesChanged(TreeModelEvent e) {

		Object[] changedChildren = e.getChildren();
		if (changedChildren != null) {
			for (Object child : changedChildren) {
				treeNodeChanged(child, false);
			}
		}
		else {
			treeNodeChanged(e.getTreePath().getLastPathComponent(), false);
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

	private void addLoadedChildren(DataTreeNode node) {

		if (!node.isLoaded()) {
			return;
		}

		for (GTreeNode child : node.getChildren()) {
			if (child instanceof DomainFileNode fileNode) {
				addLinkFile(fileNode);
			}
		}
	}

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
				addLoadedChildren(domainFileNode);
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
	 * @param parentFolderPath the parent folder path which relates to a change
	 * @param folderNodeConsumer optional consumer which will be invoked for each loaded parent 
	 * tree node which is a linked-reflection of the specified {@code parentFolder}.  If null is 
	 * specified for this consumer a general update will be performed to remove any missing nodes.
	 * @param linkNodeConsumer optional consumer which will be invoked once if a {@code LinkedTreeNode}
	 * is found which corresponds to the specified {@code parentFolder}.
	 */
	private void updateLinkedContent(String parentFolderPath,
			Consumer<DataTreeNode> folderNodeConsumer, Consumer<LinkedTreeNode> linkNodeConsumer) {

		if (!Swing.isSwingThread()) {
			throw new RuntimeException(
				"Listener and all node updates must operate in Swing thread");
		}

		if (skipLinkUpdate) {
			return;
		}

		// NOTE: This method must track those paths which have been refreshed to avoid the
		// possibility of infinite recursion when circular links exist.
		boolean clearRefreshedTrackingSet = false;
		if (refreshedTrackingSet == null) {
			refreshedTrackingSet = new HashSet<>();
			clearRefreshedTrackingSet = true;
		}

		try {
			String[] pathElements = parentFolderPath.split("/");
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
		finally {
			if (clearRefreshedTrackingSet) {
				refreshedTrackingSet = null;
			}
		}
	}

	private class LinkedTreeNode {

		// NOTE: The use of HashSet to track LinkedTreeNodes relies on identity hashcode and 
		//       same instance for equality.

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

			Iterator<DomainFileNode> folderLinkIter = folderLinks.iterator();
			while (folderLinkIter.hasNext()) {

				DomainFileNode folderLink = folderLinkIter.next();
				if (folderLink.getParent() == null) {
					// Remove disposed link node
					folderLinkIter.remove();
				}

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

			String childPathName = LocalFileSystem.getPath(getPathname(), childName);
			if (!refreshedTrackingSet.add(childPathName)) {
				return;
			}

			// If links are defined be sure to visit DomainFolder so that we pickup on change 
			// events even if not visible within tree.
// TODO: Should no longer be needed after changes were made to force domain folder events
// which would affect discovered link-files
//			if (!folderMap.isEmpty()) {
//				String path = LocalFileSystem.getPath(getPathname(), childName);
//				DomainFolder folder =
//					projectData.getFolder(path, DomainFolderFilter.ALL_INTERNAL_FOLDERS_FILTER);
//				if (folder != null) {
//					folder.getFolders(); // forced visit to folder
//				}
//			}

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
				boolean removed = linkedTreeNode.folderLinks.isEmpty();

				// Refresh all file links refering to files within this folder
				Collection<Set<DomainFileNode>> linkedFileSets =
					linkedTreeNode.linkedFilesMap.values();
				if (!linkedFileSets.isEmpty()) {
					Iterator<Set<DomainFileNode>> iterator = linkedFileSets.iterator();
					while (iterator.hasNext()) {
						Set<DomainFileNode> linkFileSet = iterator.next();
						refresh(linkFileSet);
						if (linkFileSet.isEmpty()) {
							iterator.remove();
							removed = true;
						}
					}
				}
				return removed;
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

		/**
		 * Add or get existing named child folder node for this folder node
		 * @param folderName child folder node
		 * @return new or existing named child folder node
		 */
		private LinkedTreeNode addFolder(String folderName) {
			return folderMap.computeIfAbsent(folderName, n -> new LinkedTreeNode(this, n));
		}

		/**
		 * Add a folder-link which references this folder node
		 * @param folderLink link which references this folder node
		 * @return true if the set did not already contain the specified folderLink
		 */
		private boolean addLinkedFolder(DomainFileNode folderLink) {
			return folderLinks.add(folderLink);
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

		private void refresh(Set<DomainFileNode> linkFiles) {
			Iterator<DomainFileNode> linkFileIter = linkFiles.iterator();
			while (linkFileIter.hasNext()) {
				DomainFileNode fileLink = linkFileIter.next();
				if (fileLink.getParent() == null || !fileLink.getDomainFile().isLink()) {
					linkFileIter.remove();
				}
				else {
					fileLink.refresh();

					GTreeNode linkParent = fileLink.getParent();
					if (linkParent instanceof DomainFolderNode linkParentNode) {

						// TODO: What about LinkedDomainFolders?
						ChangeManager.this.updateLinkedContent(linkParentNode.getPathname(), fn -> {
							/* do nothing */ }, ltn -> {
								ltn.refreshLinks(fileLink.getName());
							});
					}

				}
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
