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
import docking.widgets.tree.internal.GTreeModel;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SetRootNodeTask extends GTreeTask {

	private final GTreeModel model;
	private final GTreeNode rootNode;

	public SetRootNodeTask(GTree tree, GTreeNode rootNode, GTreeModel model) {
		super(tree);
		this.model = model;
		this.rootNode = rootNode;
	}

	@Override
	public void run(final TaskMonitor monitor) throws CancelledException {
		runOnSwingThread(new Runnable() {
			@Override
			public void run() {
				if (monitor.isCancelled()) {
					return; // cancelled while waiting for the Swing thread 
				}
				model.setRootNode(rootNode);
			}
		});
	}
}
