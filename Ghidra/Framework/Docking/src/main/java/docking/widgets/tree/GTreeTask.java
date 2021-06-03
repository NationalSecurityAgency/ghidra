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
package docking.widgets.tree;

import javax.swing.JTree;
import javax.swing.tree.TreePath;

import ghidra.util.SystemUtilities;
import ghidra.util.task.TaskMonitor;
import ghidra.util.worker.PriorityJob;

public abstract class GTreeTask extends PriorityJob {

	protected GTree tree;
	protected final JTree jTree;

	protected GTreeTask(GTree tree) {
		this.tree = tree;
		this.jTree = tree.getJTree();
	}

	@Override
	protected void setTaskMonitor(TaskMonitor monitor) {
		super.setTaskMonitor(monitor);
		tree.setThreadLocalMonitor(monitor);
	}

	public void runOnSwingThread(Runnable runnable) {
		if (isCancelled()) {
			return;
		}
		SystemUtilities.runSwingNow(new CheckCancelledRunnable(runnable));
	}

	/**
	 * This method allows us to take a TreePath from a previous tree and apply that path to a new
	 * tree (or a tree that has been reloaded with new nodes).  This method is required due to the
	 * fact that JTree allows you to set any path values, valid or not, and will return those path
	 * values on later calls to getSelectedPaths().  So, to handle that 'feature' of the JTree, we
	 * need to translate the given path to the equivalent path in the current tree (this code may
	 * not be needed in all uses of this task, but it protects us from the aforementioned case).
	 * @param path the path to translate
	 * @param monitor the monitor
	 * @return the translated path
	 */
	protected TreePath translatePath(TreePath path, TaskMonitor monitor) {

		// note: call this on the Swing thread, since the Swing thread maintains the node state
		//       (we have seen errors where the tree will return nodes that are in the process
		//       of being disposed)
		GTreeNode nodeForPath = SystemUtilities.runSwingNow(() -> tree.getViewNodeForPath(path));
		if (nodeForPath != null) {
			return nodeForPath.getTreePath();
		}
		return null;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	class CheckCancelledRunnable implements Runnable {
		private final Runnable runnable;

		public CheckCancelledRunnable(Runnable runnable) {
			this.runnable = runnable;
		}

		@Override
		public void run() {
			if (!isCancelled()) {
				runnable.run();
			}
		}
	}
}
