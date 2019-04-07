/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.List;

import javax.swing.tree.TreePath;

import docking.widgets.tree.*;

public class GTreeExpandAllTask extends GTreeTask {

	private final GTreeNode root;

	public GTreeExpandAllTask(GTree tree, GTreeNode node) {
		super(tree);
		this.root = node;
	}

	@Override
	public void run(TaskMonitor monitor) {
		int max = 100; // Note: this used to be root.getNonLeafCount(), but that triggered a load
		monitor.initialize(max);
		monitor.setMessage("Expanding nodes...");
		try {
			expandNode(root, monitor);
		}
		catch (CancelledException e) {
			// Not everything expanded which is ok
		}
	}

	protected void expandNode(GTreeNode node, TaskMonitor monitor) throws CancelledException {
		if (node.isLeaf()) {
			return;
		}
		monitor.checkCanceled();
		List<GTreeNode> allChildren = node.getChildren();
		if (allChildren.size() == 0) {
			return;
		}
		TreePath treePath = node.getTreePath();
		if (!jTree.isExpanded(treePath)) {
			expandPath(treePath, monitor);
		}
		for (GTreeNode child : allChildren) {
			monitor.checkCanceled();
			expandNode(child, monitor);
		}
		monitor.incrementProgress(1);
	}

	private void expandPath(final TreePath treePath, final TaskMonitor monitor) {
		runOnSwingThread(new Runnable() {
			@Override
			public void run() {
				if (monitor.isCancelled()) {
					return; // we can be cancelled while waiting for Swing to run us
				}

				jTree.expandPath(treePath);
			}
		});
	}

}
