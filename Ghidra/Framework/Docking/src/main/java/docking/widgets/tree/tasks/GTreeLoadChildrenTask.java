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
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GTreeLoadChildrenTask extends GTreeTask {

	private final GTreeSlowLoadingNode node;

	public GTreeLoadChildrenTask(GTree tree, GTreeSlowLoadingNode node) {
		super(tree);
		this.node = node;

	}

	@Override
	public void run(TaskMonitor monitor) {
		long progressValue = monitor.getProgress();
		long maxValue = monitor.getMaximum();
		monitor.setMessage("Loading children");
		try {
			node.setChildren(node.generateChildren(monitor));
		}
		catch (CancelledException e) {
			if (!tree.isDisposed()) {
				runOnSwingThread(new Runnable() {
					@Override
					public void run() {
						tree.collapseAll(tree.getViewRoot());
					}
				});
			}
			node.unloadChildren();
		}
		finally {
			monitor.initialize(maxValue);
			monitor.setProgress(progressValue);

		}
	}

}
