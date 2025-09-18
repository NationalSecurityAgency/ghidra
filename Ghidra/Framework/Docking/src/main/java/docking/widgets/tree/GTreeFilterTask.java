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
import java.util.Objects;

import javax.swing.tree.TreePath;

import docking.widgets.tree.support.GTreeFilter;
import docking.widgets.tree.tasks.GTreeClearTreeFilterTask;
import docking.widgets.tree.tasks.GTreeExpandAllTask;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GTreeFilterTask extends GTreeTask {

	private final GTreeFilter filter;
	private volatile boolean cancelledProgramatically;

	public GTreeFilterTask(GTree tree, GTreeFilter filter) {
		super(tree);
		this.filter = filter;
		tree.saveFilterRestoreState();
	}

	@Override
	public void run(TaskMonitor monitor) {
		if (filter == null) {
			runOnSwingThread(() -> tree.swingRestoreNonFilteredRootNode());
			restoreInSameTask(monitor);
			return;
		}

		GTreeNode root = tree.getModelRoot();
		try {
			monitor.setMessage("Loading/Organizing Tree ....");

			// disable tree events while loading to prevent unnecessary events from slowing
			// down the operation
			tree.setEventsEnabled(false);
			int nodeCount = root.loadAll(monitor);
			tree.setEventsEnabled(true);
			monitor.setMessage("Filtering...");
			monitor.initialize(nodeCount);
			GTreeNode filtered = root.filter(filter, monitor);
			runOnSwingThread(() -> tree.swingSetFilteredRootNode(filtered));
			if (filter.showFilterMatches()) {
				expandInSameTask(monitor, filtered);
				restoreInSameTask(monitor);
			}
		}
		catch (CloneNotSupportedException e) {
			Msg.error(this, "Got Unexpected CloneNotSupportedException", e);
		}
		catch (CancelledException e) {
			if (!cancelledProgramatically) {
				tree.runTask(new GTreeClearTreeFilterTask(tree));
			}
		}
		finally {
			tree.setEventsEnabled(true);
		}
	}

	private void expandInSameTask(TaskMonitor monitor, GTreeNode filtered) {
		GTreeExpandAllTask expandTask = new GTreeExpandAllTask(tree, filtered);
		expandTask.run(monitor);
	}

	private void restoreInSameTask(TaskMonitor monitor) {

		GTreeState state = tree.getFilterRestoreState();
		if (isOnlyRootSelected(state)) {
			// This is a special case that allows the user to signal to not restore the tree state
			// when the filter is cleared.   The tree will normally restore the state to either 1)
			// the state prior to the filter, or 2) the state the user chose when filtered by 
			// selecting one or more nodes.  If the user selects the root, we will use that as a
			// signal from the user to say they do not want any state to be restored when the filter
			// is cleared.
			return;
		}
		GTreeRestoreTreeStateTask restoreTask = new GTreeRestoreTreeStateTask(tree, state);
		restoreTask.run(monitor);
	}

	private boolean isOnlyRootSelected(GTreeState state) {
		List<TreePath> paths = state.getSelectedPaths();
		if (paths.size() == 1) {
			TreePath path = paths.get(0);
			GTreeNode node = (GTreeNode) path.getLastPathComponent();
			GTreeNode viewRoot = tree.getViewRoot();
			return Objects.equals(node, viewRoot);
		}
		return false;
	}

	@Override
	public void cancel() {
		cancelledProgramatically = true;
		super.cancel();
	}
}
