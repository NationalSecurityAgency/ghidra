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

import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeTask;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class GTreeBulkTask extends GTreeTask {

	protected GTreeBulkTask(GTree tree) {
		super(tree);
	}

	@Override
	final public void run(TaskMonitor monitor) throws CancelledException {

		boolean filteringEnabled = tree.isFilteringEnabled();

		try {
			if (filteringEnabled) {
				enableFilter(false);
			}

			runBulk(monitor);
		}
		finally {
			if (filteringEnabled) {
				enableFilter(true);
			}
		}
	}

	private void enableFilter(final boolean enable) {
		SystemUtilities.runSwingNow(new Runnable() {
			@Override
			public void run() {
				tree.setFilteringEnabled(enable);
			}
		});
	}

	/**
	 * Perform bulk operations here.
	 *
	 * @param monitor the monitor used to report progress and check for cancelled
	 * @throws CancelledException if the user cancelled and {@link TaskMonitor#checkCanceled()}
	 *         gets called
	 */
	public abstract void runBulk(TaskMonitor monitor) throws CancelledException;
}
