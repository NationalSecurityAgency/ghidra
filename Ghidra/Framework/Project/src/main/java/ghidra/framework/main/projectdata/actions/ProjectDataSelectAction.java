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

import javax.swing.tree.TreePath;

import docking.action.MenuData;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.tasks.GTreeExpandAllTask;
import ghidra.framework.data.LinkHandler;
import ghidra.framework.main.datatable.ProjectTreeAction;
import ghidra.framework.main.datatree.*;
import ghidra.framework.model.DomainFile;
import ghidra.framework.store.FileSystem;

public class ProjectDataSelectAction extends ProjectTreeAction {

	public ProjectDataSelectAction(String owner, String group) {
		super("Select All", owner);
		setPopupMenuData(new MenuData(new String[] { "Select Children" }, group));
		markHelpUnnecessary();
	}

	@Override
	protected void actionPerformed(FrontEndProjectTreeContext context) {
		DataTree tree = context.getTree();
		TreePath[] paths = context.getSelectionPaths();
		GTreeNode node = (GTreeNode) paths[0].getLastPathComponent();

		selectAllChildren(tree, node);
	}

	@Override
	public boolean isAddToPopup(FrontEndProjectTreeContext context) {
		if (!context.hasExactlyOneFileOrFolder()) {
			return false;
		}
		if (context.getFolderCount() == 1) {
			return true;
		}
		DomainFile folderLinkFile = context.getSelectedFiles().get(0);
		return canTraverseFolderLinkFile(folderLinkFile);
	}

	private static boolean canTraverseFolderLinkFile(DomainFile file) {
		if (file.isLink() && file.getLinkInfo().isFolderLink()) {
			// Prevent selection of folder-link which is contained within referenced link-path.
			// Cycle prevention in tree should prevent this from being an issue
			String filePath = file.getPathname() + FileSystem.SEPARATOR;
			String linkPath;
			try {
				linkPath = LinkHandler.getAbsoluteLinkPath(file);
				if (!linkPath.endsWith(FileSystem.SEPARATOR)) {
					linkPath += FileSystem.SEPARATOR;
				}
				if (!filePath.startsWith(linkPath)) {
					return true;
				}
			}
			catch (IOException e) {
				// ignore
			}
		}
		return false;
	}

	/**
	 * Select all descendants for the first selected node; called from an action
	 * listener on a menu.
	 */
	private void selectAllChildren(DataTree tree, GTreeNode node) {
		List<TreePath> paths = new ArrayList<TreePath>();

		tree.runTask(monitor -> {

			GTreeExpandAllTask task = new GTreeExpandAllTask(tree, node);
			task.run(monitor);

			getAllTreePaths(node, paths);
			tree.setSelectionPaths(paths);
		});

	}

	/**
	 * Select all descendants starting at node.
	 */
	private void getAllTreePaths(GTreeNode node, List<TreePath> paths) {

		// Origin node is intentionally not included in selection since the origin node
		// is not a child of itself.  Including the root node can present problems as well.

		List<GTreeNode> children = node.getChildren();
		for (GTreeNode child : children) {
			// Limit recursion through folder-links which may be self-referencing
			if (child instanceof DomainFileNode fileNode) {

				if (fileNode.isLeaf()) {
					// add individual child
					paths.add(child.getTreePath());
					continue;
				}

				// We should only get here is file is a internal folder link
				// which needs to be checked for possible circular ancestry issue
				if (!canTraverseFolderLinkFile(fileNode.getDomainFile())) {
					continue;
				}
			}

			// recurse and add child with its children
			paths.add(child.getTreePath());
			getAllTreePaths(child, paths);
		}
	}
}
