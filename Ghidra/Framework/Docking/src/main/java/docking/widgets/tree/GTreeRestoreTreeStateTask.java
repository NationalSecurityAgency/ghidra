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

import java.util.List;

import javax.swing.tree.TreePath;

import docking.widgets.tree.support.GTreeSelectionEvent.EventOrigin;
import docking.widgets.tree.tasks.GTreeExpandPathsTask;
import docking.widgets.tree.tasks.GTreeSelectPathsTask;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;

public class GTreeRestoreTreeStateTask extends GTreeTask {

	private GTreeState state;

	public GTreeRestoreTreeStateTask(GTree gTree, GTreeState state) {
		super(gTree);
		this.state = state;
	}

	@Override
	public void run(TaskMonitor monitor) {
		if (monitor.isCancelled()) {
			return;
		}

		if (state == null) {
			return;
		}

		if (tree.hasFilterText()) {
			// only restore selections when filtered, as the expansion state is driven by the filter
			monitor.setMessage("Restoring tree selection state");
			selectPathsInThisTask(state, monitor, false);
		}
		else {
			monitor.setMessage("Restoring tree expansion state");
			expandPathsInThisTask(state, monitor);

			monitor.setMessage("Restoring tree selection state");
			selectPathsInThisTask(state, monitor, true);

			// this allows some trees to perform cleanup
			tree.expandedStateRestored(monitor);
			tree.clearFilterRestoreState();
		}
	}

	private void selectPathsInThisTask(GTreeState treeState, TaskMonitor monitor,
			boolean disableExpansion) {

		List<TreePath> selectedPaths = treeState.getSelectedPaths();
		if (selectedPaths.isEmpty()) {
			restoreViewToFirstPathIn(treeState.getViewPaths(), monitor);
			return;
		}

		GTreeSelectPathsTask task =
			new GTreeSelectPathsTask(tree, jTree, selectedPaths, EventOrigin.INTERNAL_GENERATED);

		// 
		// The tree will attempt to reconcile *each* path that we are selecting inside of
		// a loop.  For each pass through that loop, the tree will perform logic to make
		// sure that that path is expanded.  In a degenerate case this results in an 
		// n^2 operation.  Further, for each of these operations, the tree will update its
		// height cache, which for some trees means accessing the database.  Imagine a 
		// large tree triggering 4 million database accesses--this locks the UI.
		//
		task.setExpandingDisabled(disableExpansion);
		task.run(monitor);

	}

	private void restoreViewToFirstPathIn(TreePath[] viewPaths, TaskMonitor monitor) {

		for (TreePath path : viewPaths) {
			TreePath currentPath = translatePath(path, monitor);
			if (currentPath != null) {
				Swing.runLater(() -> tree.scrollPathToVisible(currentPath));
				break;
			}
		}

	}

	private void expandPathsInThisTask(GTreeState treeState, TaskMonitor monitor) {
		List<TreePath> expandedPaths = treeState.getExpandedPaths();
		GTreeExpandPathsTask task = new GTreeExpandPathsTask(tree, expandedPaths);
		task.run(monitor);
	}
}
