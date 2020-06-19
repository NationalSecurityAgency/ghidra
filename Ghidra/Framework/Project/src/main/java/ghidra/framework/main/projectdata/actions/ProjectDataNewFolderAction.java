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

import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;
import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.action.ContextSpecificAction;
import docking.action.MenuData;
import docking.widgets.tree.GTreeNode;
import ghidra.framework.main.datatable.ProjectTreePanelContext;
import ghidra.framework.main.datatree.DataTree;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.util.Msg;
import resources.ResourceManager;

public class ProjectDataNewFolderAction<T extends ProjectTreePanelContext> extends ContextSpecificAction<T> {

	private static Icon icon = ResourceManager.loadImage("images/folder_add.png");

	public ProjectDataNewFolderAction(String owner, String group, Class<T> contextClass) {
		super("New Folder", owner, contextClass);
		setPopupMenuData(new MenuData(new String[] { "New Folder" }, icon, group));
		markHelpUnnecessary();
	}

	@Override
	public boolean isValidContext(ActionContext actionContext) {
		return super.isValidContext(actionContext);
	}

	@Override
	public boolean isEnabledForContext(ActionContext actionContext) {
		return super.isEnabledForContext(actionContext);
	}

	@Override
	public boolean isAddToPopup(ActionContext actionContext) {
		return super.isAddToPopup(actionContext);
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
		DomainFolder folder = getFolder(context);
		String name = getNewFolderName(folder);
		try {
			final DomainFolder newFolder = folder.createFolder(name);
			final DataTree tree = context.getTree();
			SwingUtilities.invokeLater(() -> {
				GTreeNode node = findNodeForFolder(tree, newFolder);
				if (node != null) {
					tree.setEditable(true);
					tree.startEditing(node.getParent(), node.getName());
				}
			});

		}
		catch (Exception e) {
			Msg.showError(this, context.getTree(), "Create Folder Failed", e.getMessage());
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
