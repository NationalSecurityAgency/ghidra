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

import java.util.*;

import javax.swing.CellEditor;
import javax.swing.JTree;
import javax.swing.event.CellEditorListener;
import javax.swing.event.ChangeEvent;
import javax.swing.tree.TreePath;

import docking.widgets.tree.*;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GTreeStartEditingTask extends GTreeTask {

	private final GTreeNode modelParent;
	private final String childName;
	private GTreeNode editNode;

	public GTreeStartEditingTask(GTree gTree, JTree jTree, GTreeNode parent, String childName) {
		super(gTree);
		this.modelParent = parent;
		this.childName = childName;
	}

	public GTreeStartEditingTask(GTree gTree, JTree jTree, GTreeNode editNode) {
		super(gTree);
		this.modelParent = tree.getModelNodeForPath(editNode.getParent().getTreePath());
		this.childName = editNode.getName();
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
		GTreeNode viewParent = tree.getViewNodeForPath(modelParent.getTreePath());
		if (editNode == null) {
			editNode = viewParent.getChild(childName);
			if (editNode == null) {
				Msg.debug(this, "Can't find node \"" + childName + "\" to edit.");
				return;
			}
		}
		TreePath path = editNode.getTreePath();
		final Set<GTreeNode> childrenBeforeEdit = new HashSet<>(viewParent.getChildren());

		final CellEditor cellEditor = tree.getCellEditor();
		cellEditor.addCellEditorListener(new CellEditorListener() {
			@Override
			public void editingCanceled(ChangeEvent e) {
				cellEditor.removeCellEditorListener(this);
				SystemUtilities.runSwingLater(this::reselectNode);
			}

			@Override
			public void editingStopped(ChangeEvent e) {
				String newName = Objects.toString(cellEditor.getCellEditorValue());
				cellEditor.removeCellEditorListener(this);
				SystemUtilities
						.runSwingLater(() -> reselectNodeHandlingPotentialChildChange(newName));
			}

			/**
			 * Unusual Code Alert!:  This method handles the case where editing of a node triggers
			 *                       a new node to be created.  In this case, reselecting the 
			 *                       node that was edited can leave the tree with a selection that
			 *                       points to a removed node, which has bad consequences to clients.
			 *                       We work around this issue by retrieving the node after the edit
			 *                       has finished and been applied.
			 */
			private void reselectNode() {
				String newName = editNode.getName();
				GTreeNode newModelChild = modelParent.getChild(newName);

				if (newModelChild == null) {
					throw new AssertException("Unable to find new node by name: " + newName);
				}
				tree.setSelectedNode(tree.getViewNodeForPath(newModelChild.getTreePath()));
			}

			/**
			 * Unusual Code Alert!:  This method handles the case where editing of a node triggers
			 *                       a new node to be created.  In this case, reselecting the 
			 *                       node that was edited can leave the tree with a selection that
			 *                       points to a removed node, which has bad consequences to clients.
			 *                       We work around this issue by retrieving the node after the edit
			 *                       has finished and been applied.
			 *                       
			 *                       This method takes into account the fact that we are not given
			 *                       the new name of the node in our editingStopped() callback.
			 *                       As such, we have to deduce the newly added node, based upon
			 *                       the state of the edited node's parent, both before and after
			 *                       the edit.
			 */
			private void reselectNodeHandlingPotentialChildChange(String newName) {
				SystemUtilities
						.runSwingLater(() -> doReselectNodeHandlingPotentialChildChange(newName));
			}

			private void doReselectNodeHandlingPotentialChildChange(String newName) {
				GTreeNode newModelChild = modelParent.getChild(newName);
				List<GTreeNode> children = modelParent.getChildren();
				Msg.debug(this, children.toString());

				if (newModelChild != null) {
					tree.ignoreFilter(newModelChild);

					tree.setSelectedNode(newModelChild);
					Msg.debug(this, "new child not null");
				}
				else {
					Msg.debug(this, "child is null");
				}
			}
		});

		tree.setNodeEditable(editNode);
		jTree.startEditingAtPath(path);

	}

}
