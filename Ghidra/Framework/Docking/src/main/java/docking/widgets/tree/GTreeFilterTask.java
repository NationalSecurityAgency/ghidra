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

import docking.widgets.tree.support.GTreeFilter;
import docking.widgets.tree.tasks.GTreeClearTreeFilterTask;
import docking.widgets.tree.tasks.GTreeExpandAllTask;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GTreeFilterTask extends GTreeTask {

	private final GTreeFilter filter;
	private boolean cancelledProgramatically;

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
		GTreeRestoreTreeStateTask restoreTask = new GTreeRestoreTreeStateTask(tree, state);
		restoreTask.run(monitor);
	}

	@Override
	public void cancel() {
		cancelledProgramatically = true;
		super.cancel();
	}
}
