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
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GTreeExpandAllTask extends GTreeTask {
	// The MAX number of nodes to expand. Expanding nodes is fairly expensive and must
	// be done in the Swing thread. So to avoid hanging up the GUI, we limit it to
	// a reasonable number.  Also, this task is primarily used to show filter results
	// and if you have too many results, you probably aren't going to look at them
	// all anyway.
	private static final int MAX = 1000;
	private final GTreeNode node;

	public GTreeExpandAllTask(GTree tree, GTreeNode node) {
		super(tree);
		this.node = node;
	}

	@Override
	public void run(TaskMonitor monitor) {
		monitor.initialize(1000);
		monitor.setMessage("Expanding nodes...");
		try {
			expandNode(node, monitor);
		}
		catch (CancelledException e) {
			// Not everything expanded which is ok
		}
	}

	protected void expandNode(GTreeNode parent, TaskMonitor monitor) throws CancelledException {
		// only expand MAX number of nodes.
		if (monitor.getProgress() >= MAX) {
			return;
		}
		if (parent.isLeaf()) {
			return;
		}
		monitor.checkCanceled();
		List<GTreeNode> allChildren = parent.getChildren();
		if (allChildren.size() == 0) {
			return;
		}
		TreePath treePath = parent.getTreePath();
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
