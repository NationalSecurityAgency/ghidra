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

import javax.swing.tree.TreePath;

import docking.action.MenuData;
import docking.widgets.tree.GTreeNode;
import ghidra.framework.main.datatable.ProjectTreeAction;
import ghidra.framework.main.datatree.DataTree;
import ghidra.framework.main.datatree.FrontEndProjectTreeContext;

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
		return context.getFolderCount() == 1 && context.getFileCount() == 0;
	}

	/**
	 * Select all descendants for the first selected node; called from an action
	 * listener on a menu.
	 */
	private void selectAllChildren(DataTree tree, GTreeNode node) {
		List<TreePath> paths = new ArrayList<TreePath>();
		getAllTreePaths(node, paths);
		tree.setSelectionPaths(paths.toArray(new TreePath[paths.size()]));
	}

	/**
	 * Select all descendants starting at node.
	 */
	private void getAllTreePaths(GTreeNode node, List<TreePath> paths) {
		paths.add(node.getTreePath());
		List<GTreeNode> children = node.getChildren();
		for (GTreeNode child : children) {
			getAllTreePaths(child, paths);
		}
	}
}
