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

import javax.swing.JTree;
import javax.swing.tree.TreePath;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.tree.*;
import docking.widgets.tree.internal.GTreeSelectionModel;
import docking.widgets.tree.support.GTreeSelectionEvent.EventOrigin;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GTreeSelectNodeByNameTask extends GTreeTask {

	private final String[] names;
	private final JTree jTree;
	private EventOrigin origin;

	public GTreeSelectNodeByNameTask(GTree gTree, JTree jTree, String[] names, EventOrigin origin) {
		super(gTree);
		this.jTree = jTree;
		this.names = names;
		this.origin = origin;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Selecting paths");
		GTreeNode node = tree.getViewRoot();

		String rootName = names[0];
		if (!node.getName().equals(rootName)) {
			Msg.debug(this, "When selecting paths by name the first path element must be the " +
				"name of the root node - path: " + StringUtils.join(names, '.'));
			return;
		}

		for (int i = 1; i < names.length; i++) {
			monitor.checkCanceled();
			node = findNodeByName(node, names[i], monitor);
			if (node == null) {
				Msg.debug(this,
					"Could not find node to select - path: " + StringUtils.join(names, '.'));
				return;
			}
		}

		selectPath(node.getTreePath(), monitor);
	}

	private GTreeNode findNodeByName(GTreeNode node, String name, TaskMonitor monitor)
			throws CancelledException {
		for (GTreeNode child : node.getChildren()) {
			monitor.checkCanceled();
			if (child.getName().equals(name)) {
				return child;
			}
		}
		return null;
	}

	private void selectPath(final TreePath treePath, final TaskMonitor monitor) {
		runOnSwingThread(() -> {
			if (monitor.isCancelled()) {
				return; // we can be cancelled while waiting for Swing to run us
			}

			GTreeSelectionModel selectionModel = tree.getGTSelectionModel();
			selectionModel.setSelectionPaths(new TreePath[] { treePath }, origin);
			jTree.scrollPathToVisible(treePath);
		});
	}

}
