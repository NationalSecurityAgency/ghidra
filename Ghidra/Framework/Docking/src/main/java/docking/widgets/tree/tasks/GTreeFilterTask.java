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

import docking.widgets.tree.*;
import docking.widgets.tree.support.GTreeFilter;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GTreeFilterTask extends GTreeTask {

	private final GTreeNode node;
	private final GTreeFilter filter;
	private final GTreeState defaultRestoreState;
	private boolean cancelledProgramatically;

	public GTreeFilterTask(GTree tree, GTreeNode node, GTreeFilter filter) {
		super(tree);
		this.node = node;
		this.filter = filter;

		// save this now, before we modify the tree
		defaultRestoreState = tree.getTreeState();
	}

	@Override
	public void run(TaskMonitor monitor) {
		if (filter == null) {
			node.clearFilter();
			restoreInSameTask(monitor);
			return;
		}

		monitor.setMessage("Filtering...");
		monitor.initialize(1000000000);

		try {
			node.filter(filter, monitor, 0, 1000000000);

			if (filter.showFilterMatches()) {
				expandInSameTask(monitor);
				restoreInSameTask(monitor);
			}
		}
		catch (CancelledException e) {
			if (!cancelledProgramatically) {
				tree.runTask(new GTreeClearTreeFilterTask(tree));
			}
		}
	}

	private void expandInSameTask(TaskMonitor monitor) {
		GTreeExpandAllTask expandTask = new GTreeExpandAllTask(tree, node);
		expandTask.run(monitor);
	}

	private void restoreInSameTask(TaskMonitor monitor) {

		GTreeState existingState = tree.getRestoreTreeState();
		GTreeState state = (existingState == null) ? defaultRestoreState : existingState;
		GTreeRestoreTreeStateTask restoreTask = new GTreeRestoreTreeStateTask(tree, state);
		restoreTask.run(monitor);
	}

	@Override
	public void cancel() {
		cancelledProgramatically = true;
		super.cancel();
	}
}
