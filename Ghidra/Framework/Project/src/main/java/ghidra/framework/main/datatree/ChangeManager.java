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

import java.util.*;

import docking.widgets.tree.GTreeNode;
import ghidra.framework.model.*;

/**
 * Class to handle changes when a domain folder changes; updates the
 * tree model to reflect added/removed/renamed nodes.
 */
class ChangeManager implements DomainFolderChangeListener {

	private DomainFolderRootNode root;
	private ProjectDataTreePanel treePanel;
	private DataTree tree;

	ChangeManager(ProjectDataTreePanel treePanel) {
		this.treePanel = treePanel;
		tree = treePanel.getDataTree();
		root = (DomainFolderRootNode) tree.getModelRoot();
	}

	@Override
	public void domainFileRemoved(DomainFolder parent, String name, String fileID) {
		updateFolderNode(parent);
		DomainFolderNode folderNode = findDomainFolderNode(parent, true);
		if (folderNode == null) {
			return;
		}

		List<GTreeNode> children = folderNode.getChildren();
		for (GTreeNode child : children) {
			if (child instanceof DomainFileNode) {
				if (child.getName().equals(name)) {
					folderNode.removeNode(child);
				}
			}
		}
	}

	@Override
	public void domainFolderRemoved(DomainFolder parent, String name) {
		updateFolderNode(parent);

		ArrayList<String> folderPath = new ArrayList<String>();
		getFolderPath(parent, folderPath);
		folderPath.add(name);

		DomainFolderNode folderNode = findDomainFolderNode(folderPath, true);
		if (folderNode != null) {
			folderNode.getParent().removeNode(folderNode);
		}
	}

	@Override
	public void domainFolderRenamed(DomainFolder folder, String oldName) {
		domainFolderRemoved(folder.getParent(), oldName);
		domainFolderAdded(folder);
	}

	@Override
	public void domainFileRenamed(DomainFile file, String oldName) {
		domainFileRemoved(file.getParent(), oldName, file.getFileID());
		domainFileAdded(file);
	}

	@Override
	public void domainFolderMoved(DomainFolder folder, DomainFolder oldParent) {
		domainFolderRemoved(oldParent, folder.getName());
		domainFolderAdded(folder);
	}

	@Override
	public void domainFileMoved(DomainFile file, DomainFolder oldParent, String oldName) {
		updateFolderNode(oldParent);
		domainFileAdded(file);
	}

	@Override
	public void domainFileAdded(DomainFile file) {
		DomainFileNode domainFileNode = findDomainFileNode(file, true);
		if (domainFileNode != null) {
			return;
		}
		DomainFolder parent = file.getParent();
		DomainFolderNode folderNode = findDomainFolderNode(parent, true);
		if (folderNode != null) {
			if (folderNode.isLoaded()) {
				DomainFileNode newNode = new DomainFileNode(file);
				addNode(folderNode, newNode);
			}
		}
	}

	static void addNode(GTreeNode parentNode, GTreeNode newNode) {
		List<GTreeNode> allChildren = parentNode.getChildren();
		int index = Collections.binarySearch(allChildren, newNode);
		if (index < 0) {
			index = -index - 1;
		}
		parentNode.addNode(index, newNode);
	}

	@Override
	public void domainFolderAdded(DomainFolder folder) {
		DomainFolderNode domainFolderNode = findDomainFolderNode(folder, true);
		if (domainFolderNode != null) {
			return;
		}
		DomainFolder parentFolder = folder.getParent();
		DomainFolderNode folderNode = findDomainFolderNode(parentFolder, true);
		if (folderNode != null && folderNode.isLoaded()) {
			DomainFolderNode newNode =
				new DomainFolderNode(folder, folderNode.getDomainFileFilter());
			addNode(folderNode, newNode);
		}
	}

	@Override
	public void domainFolderSetActive(DomainFolder folder) {
		DomainFolderNode folderNode = findDomainFolderNode(folder, false);
		if (folderNode != null) {
			tree.setSelectedNode(folderNode);
		}
	}

//    @Override
//    public void domainFileSaved(DomainFile file, DomainObject dobj) {
//    	treePanel.getActionManager().adjustActions();	
//    }

	@Override
	public void domainFileStatusChanged(DomainFile file, boolean fileIDset) {
		DomainFileNode fileNode = findDomainFileNode(file, true);
		if (fileNode != null) {
			fileNode.refresh();
		}
		treePanel.domainChange();
//		treePanel.getActionManager().adjustActions();
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
			// must look at all children since a folder and file may have the same name
			boolean found = false;
			for (GTreeNode node : folderNode.getChildren()) {
				if (!(node instanceof DomainFolderNode)) {
					continue;
				}
				if (name.equals(node.getName())) {
					folderNode = (DomainFolderNode) node;
					found = true;
					break;
				}
			}
			if (!found) {
				return null;
			}
		}
		return folderNode;
	}

//	private DomainFileNode findDomainFileNode(DomainFolder parent, String name, boolean lazy) {
//		DomainFolderNode folderNode = findDomainFolderNode(parent, lazy);
//		if (folderNode == null) {
//			return null;
//		}
//		if (lazy && !folderNode.isChildrenLoadedOrInProgress()) {
//			return null; // not visited 
//		}
//		GTreeNode child = folderNode.getChild(name);
//		if (child instanceof DomainFileNode) {
//			return (DomainFileNode) child;
//		}
//		return null;
//	}

	private DomainFileNode findDomainFileNode(DomainFile domainFile, boolean lazy) {
		DomainFolderNode folderNode = findDomainFolderNode(domainFile.getParent(), lazy);
		if (folderNode == null) {
			return null;
		}
		if (lazy && !folderNode.isLoaded()) {
			return null; // not visited 
		}

		GTreeNode child = folderNode.getChild(domainFile.getName());
		if (child instanceof DomainFileNode) {
			return (DomainFileNode) child;
		}
		return null;
	}

	private void updateFolderNode(DomainFolder parent) {
		DomainFolderNode folderNode = findDomainFolderNode(parent, true);
		if (folderNode == null) {
			return;
		}
		DomainFolder folder = folderNode.getDomainFolder();
		// loop through children looking for nodes whose underlying model object
		// does not have this folder as its parent;
		List<GTreeNode> children = folderNode.getChildren();
		for (GTreeNode child : children) {
			if (child instanceof DomainFileNode) {
				if (folder.getFile(child.getName()) == null) {
					folderNode.removeNode(child);
				}
			}
			else if (child instanceof DomainFolderNode) {
				if (folder.getFolder(child.getName()) == null) {
					folderNode.removeNode(child);
				}
			}
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.framework.model.DomainFolderChangeListener#domainFileObjectReplaced(ghidra.framework.model.DomainFile, ghidra.framework.model.DomainObject)
	 */
	@Override
	public void domainFileObjectReplaced(DomainFile file, DomainObject oldObject) {
		// ignored
	}

	/*
	 * @see ghidra.framework.model.DomainFolderChangeListener#domainFileObjectOpenedForUpdate(ghidra.framework.model.DomainFile, ghidra.framework.model.DomainObject)
	 */
	@Override
	public void domainFileObjectOpenedForUpdate(DomainFile file, DomainObject object) {
		// ignored
	}

	/*
	 * @see ghidra.framework.model.DomainFolderChangeListener#domainFileObjectClosed(ghidra.framework.model.DomainFile, ghidra.framework.model.DomainObject)
	 */
	@Override
	public void domainFileObjectClosed(DomainFile file, DomainObject object) {
		// ignored
	}
}
