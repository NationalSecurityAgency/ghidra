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

import java.util.HashSet;

import javax.swing.tree.TreePath;

import docking.widgets.tree.GTreeNode;
import ghidra.framework.main.datatable.ProjectTreeAction;

public abstract class ProjectDataCopyCutBaseAction extends ProjectTreeAction {

	public ProjectDataCopyCutBaseAction(String name, String owner) {
		super(name, owner);
	}

	/**
	 * Removes any path that is a descendant of a path in the selection.
	 * @param paths selected paths
	 * @return paths that do not have any descendants
	 */
	protected TreePath[] adjustSelectionPaths(TreePath[] paths) {
		HashSet<GTreeNode> set = new HashSet<>();
		for (TreePath treePath : paths) {
			set.add((GTreeNode) treePath.getLastPathComponent());
		}
		HashSet<GTreeNode> removeSet = new HashSet<>();
		for (GTreeNode node : set) {
			if (anyParentsInSet(set, node)) {
				removeSet.add(node);
			}
		}
		set.removeAll(removeSet);
		TreePath[] newPaths = new TreePath[set.size()];
		int index = 0;
		for (GTreeNode node : set) {
			newPaths[index++] = node.getTreePath();
		}
		return newPaths;
	}

	private boolean anyParentsInSet(HashSet<GTreeNode> set, GTreeNode node) {
		GTreeNode parent = node.getParent();
		if (parent == null) {
			return false;
		}
		if (set.contains(parent)) {
			return true;
		}
		return anyParentsInSet(set, parent);
	}

}
