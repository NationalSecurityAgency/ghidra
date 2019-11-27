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
package docking.widgets.tree.tasks;

import java.util.List;

import javax.swing.tree.TreePath;

import docking.widgets.tree.*;
import ghidra.util.task.TaskMonitor;

public class GTreeExpandPathsTask extends GTreeTask {

	private final List<TreePath> paths;

	public GTreeExpandPathsTask(GTree gTree, List<TreePath> paths) {
		super(gTree);
		this.paths = paths;
	}

	@Override
	public void run(TaskMonitor monitor) {
		monitor.setMessage("Expanding Paths");
		monitor.initialize(paths.size());
		for (TreePath path : paths) {
			ensurePathLoaded(path, monitor);
			expandPath(path, monitor);
			monitor.incrementProgress(1);
		}
	}

	private void ensurePathLoaded(TreePath path, TaskMonitor monitor) {
		GTreeNode parent = tree.getViewRoot();
		if (parent == null) {
			return; // disposed?
		}

		Object[] nodeList = path.getPath();
		if (nodeList.length < 2) {
			return;  // only the root is in the path
		}
		List<GTreeNode> allChildren = parent.getChildren();
		for (int i = 1; i < nodeList.length; i++) {
			if (monitor.isCancelled()) {
				return;
			}
			GTreeNode node = findNode(allChildren, (GTreeNode) nodeList[i]);
			if (node == null) {
				return;
			}
			allChildren = node.getChildren();
			parent = node;
		}
	}

	private GTreeNode findNode(List<GTreeNode> children, GTreeNode node) {
		for (GTreeNode childNode : children) {
			if (childNode.equals(node)) {
				return childNode;
			}
		}
		return null;
	}

	private void expandPath(final TreePath treePath, final TaskMonitor monitor) {
		runOnSwingThread(() -> {
			if (monitor.isCancelled()) {
				return; // we can be cancelled while waiting for Swing to run us
			}

			// 
			// JTree will do nothing if the last element in a path is a leaf.  We can do 
			// better.  We will expand the parent of the given element if it is a leaf.
			//
			TreePath validatedPath = treePath;
			GTreeNode node = (GTreeNode) treePath.getLastPathComponent();
			if (node.isLeaf()) {
				Object[] path = treePath.getPath();
				if (path.length <= 1) {
					return;
				}
				Object[] newPath = new Object[path.length - 1];
				System.arraycopy(path, 0, newPath, 0, path.length - 1);
				validatedPath = new TreePath(newPath);
			}

			jTree.expandPath(validatedPath);
		});
	}

}
