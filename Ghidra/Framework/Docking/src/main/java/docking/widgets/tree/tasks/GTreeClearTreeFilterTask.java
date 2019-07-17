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

import ghidra.util.task.TaskMonitor;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeTask;

public class GTreeClearTreeFilterTask extends GTreeTask {

	public GTreeClearTreeFilterTask(GTree tree) {
		super(tree);
	}

	@Override
	public void run(final TaskMonitor monitor) {
		runOnSwingThread(new Runnable() {
			@Override
			public void run() {
				if (monitor.isCancelled()) {
					return; // we can be cancelled while waiting for Swing to run us
				}

				tree.clearFilter();
			}
		});
	}

}
