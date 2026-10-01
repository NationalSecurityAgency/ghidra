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
import javax.swing.event.*;
import javax.swing.tree.TreePath;

import docking.widgets.tree.*;
import docking.widgets.tree.internal.GTreeModel;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GTreeStartEditingTask extends GTreeTask {

	private final GTreeNode modelEditNode;

	public GTreeStartEditingTask(GTree gTree, JTree jTree, GTreeNode editNode) {
		super(gTree);
		this.modelEditNode = tree.getModelNode(editNode);
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

		// add a model listener to re-select the newly edited node
		GTreeModel model = tree.getModel();
		SelectNodeListener listener = new SelectNodeListener(model);
		model.addTreeModelListener(listener);

		GTreeNode viewEditNode = tree.getViewNode(modelEditNode);
		TreePath path = viewEditNode.getTreePath();
		CellEditor cellEditor = tree.getCellEditor();
		cellEditor.addCellEditorListener(new CellEditorListener() {
			@Override
			public void editingCanceled(ChangeEvent e) {
				cellEditor.removeCellEditorListener(this);
				tree.setSelectedNode(viewEditNode); // reselect the node on cancel
				listener.dispose();
			}

			@Override
			public void editingStopped(ChangeEvent e) {
				String newName = Objects.toString(cellEditor.getCellEditorValue());
				listener.setNewName(newName);
				cellEditor.removeCellEditorListener(this);
			}
		});

		tree.setNodeEditable(viewEditNode);
		jTree.startEditingAtPath(path);

	}

	private class SelectNodeListener implements TreeModelListener {

		private String newName;
		private GTreeModel model;

		SelectNodeListener(GTreeModel model) {
			this.model = model;
			model.addTreeModelListener(this);
		}

		void setNewName(String newName) {
			this.newName = newName;
		}

		void dispose() {
			// do later to avoid mutating the model during notification					
			Swing.runLater(() -> model.removeTreeModelListener(this));
		}

		@Override
		public void treeNodesInserted(TreeModelEvent e) {
			if (newName == null) {
				return; // editing cancelled
			}

			Object[] children = e.getChildren();
			for (Object object : children) {
				GTreeNode node = (GTreeNode) object;
				String nodeName = node.getName();
				if (nodeName.equals(newName) || nodeName.contains(newName)) {
					tree.setSelectedNode(node);
					dispose();
					break;
				}
			}
		}

		@Override
		public void treeNodesChanged(TreeModelEvent e) {
			// stub
		}

		@Override
		public void treeNodesRemoved(TreeModelEvent e) {
			// stub
		}

		@Override
		public void treeStructureChanged(TreeModelEvent e) {
			// stub
		}
	}
}
