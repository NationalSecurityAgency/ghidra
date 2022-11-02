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

import java.util.Objects;

import javax.swing.CellEditor;
import javax.swing.JTree;
import javax.swing.event.CellEditorListener;
import javax.swing.event.ChangeEvent;
import javax.swing.tree.TreePath;

import docking.widgets.tree.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GTreeStartEditingTask extends GTreeTask {

	private final GTreeNode modelParent;
	private final GTreeNode editNode;

	public GTreeStartEditingTask(GTree gTree, JTree jTree, GTreeNode editNode) {
		super(gTree);
		this.modelParent = tree.getModelNode(editNode.getParent());
		this.editNode = editNode;
	}

	@Override
	public void run(final TaskMonitor monitor) throws CancelledException {
		runOnSwingThread(() -> {
			if (monitor.isCancelled()) {
				return; // we can be cancelled while waiting for Swing to run us
			}
			edit();
		});
	}

	@Override
	public long getPriority() {
		return Long.MAX_VALUE;
	}

	private void edit() {
		TreePath path = editNode.getTreePath();
		CellEditor cellEditor = tree.getCellEditor();
		cellEditor.addCellEditorListener(new CellEditorListener() {
			@Override
			public void editingCanceled(ChangeEvent e) {
				cellEditor.removeCellEditorListener(this);
				reselectNode();
			}

			@Override
			public void editingStopped(ChangeEvent e) {
				String newName = Objects.toString(cellEditor.getCellEditorValue());
				cellEditor.removeCellEditorListener(this);

				tree.forceNewNodeIntoView(modelParent, newName, newViewChild -> {
					tree.setSelectedNode(newViewChild);
				});
			}

			private void reselectNode() {
				String name = editNode.getName();
				GTreeNode newModelChild = modelParent.getChild(name);
				tree.setSelectedNode(newModelChild);
			}
		});

		tree.setNodeEditable(editNode);
		jTree.startEditingAtPath(path);

	}

}
