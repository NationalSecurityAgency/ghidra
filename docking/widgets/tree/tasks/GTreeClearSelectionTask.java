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

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import javax.swing.JTree;

import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeTask;

public class GTreeClearSelectionTask extends GTreeTask {

	private JTree jTree;

	public GTreeClearSelectionTask(GTree tree, JTree jTree) {
		super(tree);
		this.jTree = jTree;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		runOnSwingThread(new Runnable() {
			@Override
			public void run() {
				jTree.clearSelection();
			}
		});
	}

}
