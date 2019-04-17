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

import javax.swing.JTree;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;

import docking.widgets.tree.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A GTree task to fully expand a tree node to a maximal depth.
 */
public class GTreeExpandNodeToDepthTask extends GTreeTask {

	private final TreePath[] paths;
	private final JTree jTree;
	private final int depth;

	public GTreeExpandNodeToDepthTask(GTree gTree, JTree jTree, GTreeNode node, int depth) {
		super(gTree);
		this.jTree = jTree;
		this.paths = new TreePath[] { node.getTreePath() };
		this.depth = depth;
	}

	@Override
	public void run(TaskMonitor monitor) {
		runOnSwingThread(new Runnable() {
			@Override
			public void run() {

				monitor.setMessage("Expanding Paths");
				monitor.setIndeterminate(true);

				try {
					for (TreePath path : paths) {
						expandPath(jTree, path, depth, monitor);
					}
				}
				catch (CancelledException ce) {
					// ignored
				}
				monitor.setProgress(monitor.getMaximum());
			}

		});
	}

	private static void expandPath(JTree tree, TreePath treePath, int currentDepth,
			TaskMonitor monitor) throws CancelledException {

		if (currentDepth <= 0) {
			return;
		}

		GTreeNode treeNode = (GTreeNode) treePath.getLastPathComponent();
		TreeModel treeModel = tree.getModel();
		int childCount = treeModel.getChildCount(treeNode);

		if (childCount > 0) {
			for (int i = 0; i < childCount; i++) {
				monitor.checkCanceled();

				GTreeNode n = (GTreeNode) treeModel.getChild(treeNode, i);
				TreePath path = treePath.pathByAddingChild(n);

				expandPath(tree, path, currentDepth - 1, monitor);
			}
		}

		tree.expandPath(treePath);
	}

}
