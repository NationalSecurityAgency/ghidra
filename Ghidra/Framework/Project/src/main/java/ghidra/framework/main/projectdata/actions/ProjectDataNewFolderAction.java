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
package ghidra.framework.main.projectdata.actions;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;

import docking.action.ContextSpecificAction;
import docking.action.MenuData;
import docking.widgets.tree.GTreeNode;
import ghidra.framework.main.datatable.ProjectTreeContext;
import ghidra.framework.main.datatree.DataTree;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.util.InvalidNameException;
import ghidra.util.Swing;
import ghidra.util.exception.AssertException;
import resources.ResourceManager;

public class ProjectDataNewFolderAction<T extends ProjectTreeContext> extends ContextSpecificAction<T> {

	private static Icon icon = ResourceManager.loadImage("images/folder_add.png");

	public ProjectDataNewFolderAction(String owner, String group, Class<T> contextClass) {
		super("New Folder", owner, contextClass);
		setPopupMenuData(new MenuData(new String[] { "New Folder" }, icon, group));
		markHelpUnnecessary();
	}

	@Override
	protected void actionPerformed(T context) {
		createNewFolder(context);
	}

	@Override
	public boolean isAddToPopup(T context) {
		return (context.getFolderCount() + context.getFileCount()) == 1;
	}

	/**
	 * Create a new folder for the selected node that represents
	 * a folder.
	 */
	private void createNewFolder(T context) {
		DomainFolder parentFolder = getFolder(context);

		DomainFolder newFolder = createNewFolderWithDefaultName(parentFolder);
		DataTree tree = context.getTree();

		Swing.runLater(() -> {
			GTreeNode node = findNodeForFolder(tree, newFolder);
			if (node != null) {
				tree.setEditable(true);
				tree.startEditing(node.getParent(), node.getName());
			}
		});

	}

	private DomainFolder createNewFolderWithDefaultName(DomainFolder parentFolder) {
		String name = getNewFolderName(parentFolder);
		try {
			return parentFolder.createFolder(name);
		}
		catch (InvalidNameException | IOException e) {
			throw new AssertException("Unexpected Error creating new folder: "+name, e);
		}
	}

	/**
	 * Get folder path as list with top-level folder being first in the list.  
	 * Root folder is not included in list.
	 * @param folder
	 * @param folderPathList folder path list
	 */
	private static final void getFolderPath(DomainFolder folder, List<String> folderPathList) {
		if (folder.getParent() != null) {
			// don't recurse if we are the root, don't add our 'name' to the list
			getFolderPath(folder.getParent(), folderPathList);
			folderPathList.add(folder.getName());
		}
	}

	private GTreeNode findNodeForFolder(DataTree tree, DomainFolder newFolder) {
		List<String> folderPathList = new ArrayList<>();
		getFolderPath(newFolder, folderPathList);
		GTreeNode node = tree.getModelRoot();
		for (int i = 0; node != null && i < folderPathList.size(); i++) {
			node = node.getChild(folderPathList.get(i));
		}
		return node;
	}

	private String getNewFolderName(DomainFolder parent) {
		String baseName = "NewFolder";
		String name = baseName;
		int suffix = 1;
		while (parent.getFolder(name) != null) {
			suffix++;
			name = baseName + suffix;
		}
		return name;
	}

	private DomainFolder getFolder(T context) {
		// the following code relies on the isAddToPopup to ensure that there is exactly one
		// file or folder selected
		if (context.getFolderCount() > 0) {
			return context.getSelectedFolders().get(0);
		}
		DomainFile file = context.getSelectedFiles().get(0);
		return file.getParent();
	}

}
