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

import javax.swing.Icon;

import docking.action.ContextSpecificAction;
import docking.action.MenuData;
import docking.widgets.tree.GTreeNode;
import generic.theme.GIcon;
import ghidra.framework.main.datatable.ProjectTreeContext;
import ghidra.framework.main.datatree.*;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.AssertException;

public class ProjectDataNewFolderAction<T extends ProjectTreeContext>
		extends ContextSpecificAction<T> {

	private static final Icon ICON = new GIcon("icon.projectdata.new.folder");

	public ProjectDataNewFolderAction(String owner, String group, Class<T> contextClass) {
		super("New Folder", owner, contextClass);
		setPopupMenuData(new MenuData(new String[] { "New Folder" }, ICON, group));
		markHelpUnnecessary();
	}

	@Override
	protected void actionPerformed(T context) {
		createNewFolder(context);
	}

	@Override
	protected boolean isEnabledForContext(T context) {
		return getFolder(context).isInWritableProject();
	}

	private void createNewFolder(T context) {

		DomainFolder parentFolder = getFolder(context);
		DomainFolder newFolder = createNewFolderWithDefaultName(parentFolder);
		GTreeNode parent = getParentNode(context);
		DataTree tree = context.getTree();
		tree.setEditable(true);
		tree.startEditing(parent, newFolder.getName());
	}

	private DomainFolder createNewFolderWithDefaultName(DomainFolder parentFolder) {
		String name = getNewFolderName(parentFolder);
		try {
			return parentFolder.createFolder(name);
		}
		catch (InvalidNameException | IOException e) {
			throw new AssertException("Unexpected Error creating new folder: " + name, e);
		}
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
		if (context.getFolderCount() == 1 && context.getFileCount() == 0) {
			return context.getSelectedFolders().get(0);
		}
		if (context.getFileCount() == 1 && context.getFolderCount() == 0) {
			DomainFile file = context.getSelectedFiles().get(0);
			return file.getParent();
		}
		DomainFolderNode rootNode = (DomainFolderNode) context.getTree().getModelRoot();
		return rootNode.getDomainFolder();
	}

	private GTreeNode getParentNode(T context) {

		GTreeNode node = context.getContextNode();
		if (node instanceof DomainFileNode) {
			return ((DomainFileNode) node).getParent();
		}
		return node;
	}
}
