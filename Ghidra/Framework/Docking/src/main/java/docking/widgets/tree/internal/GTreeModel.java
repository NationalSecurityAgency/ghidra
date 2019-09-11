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
package docking.widgets.tree.internal;

import java.util.ArrayList;
import java.util.List;

import javax.swing.event.TreeModelEvent;
import javax.swing.event.TreeModelListener;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;

import docking.widgets.tree.GTreeNode;
import ghidra.util.SystemUtilities;

public class GTreeModel implements TreeModel {

	private GTreeNode root;
	private List<TreeModelListener> listeners = new ArrayList<TreeModelListener>();
	private boolean isFiringNodeStructureChanged;
	private volatile boolean eventsEnabled = true;

	/**
	 * Constructs a GTreeModel with the given root node.
	 * 
	 * @param root The root of the tree.
	 * @param isThreaded True signals to perform all tree tasks in a threaded environment to 
	 *        avoid hanging the swing thread.
	 */
	public GTreeModel(GTreeNode root) {
		this.root = root;
	}

	public void setRootNode(GTreeNode root) {
		this.root = root;
		fireRootChanged();
	}

	@Override
	public Object getRoot() {
		return root;
	}

	public GTreeNode getModelRoot() {
		return root;
	}

	@Override
	public void addTreeModelListener(TreeModelListener l) {
		listeners.add(l);
	}

	@Override
	public void removeTreeModelListener(TreeModelListener l) {
		listeners.remove(l);
	}

	@Override
	public Object getChild(Object parent, int index) {
		GTreeNode gTreeParent = (GTreeNode) parent;
		return gTreeParent.getChild(index);
	}

	@Override
	public int getChildCount(Object parent) {
		GTreeNode gTreeParent = (GTreeNode) parent;
		return gTreeParent.getChildCount();
	}

	@Override
	public int getIndexOfChild(Object parent, Object child) {
		GTreeNode gTreeParent = (GTreeNode) parent;
		return gTreeParent.getIndexOfChild((GTreeNode) child);
	}

	@Override
	public boolean isLeaf(Object node) {
		GTreeNode gTreeNode = (GTreeNode) node;
		return gTreeNode.isLeaf();
	}

	@Override
	public void valueForPathChanged(TreePath path, Object newValue) {
		GTreeNode node = (GTreeNode) path.getLastPathComponent();
		node.valueChanged(newValue);
	}

	public void fireNodeStructureChanged(final GTreeNode changedNode) {
		if (!eventsEnabled || isFiringNodeStructureChanged) {
			return;
		}
		try {
			isFiringNodeStructureChanged = true;
			SystemUtilities.assertThisIsTheSwingThread(
				"GTreeModel.fireNodeStructuredChanged() must be " + "called from the AWT thread");

			TreeModelEvent event = new TreeModelEvent(this, changedNode.getTreePath());
			for (TreeModelListener listener : listeners) {
				listener.treeStructureChanged(event);
			}
		}
		finally {
			isFiringNodeStructureChanged = false;
		}
	}

	public void fireRootChanged() {
		if (!eventsEnabled) {
			return;
		}
		SystemUtilities.runIfSwingOrPostSwingLater(new Runnable() {
			@Override
			public void run() {
				GTreeNode rootNode = root;
				if (rootNode != null) {
					fireNodeStructureChanged(root);
				}
			}
		});
	}

	public void fireNodeDataChanged(final GTreeNode parentNode, final GTreeNode changedNode) {
		if (!eventsEnabled) {
			return;
		}
		SystemUtilities.assertThisIsTheSwingThread(
			"GTreeModel.fireNodeDataChanged() must be " + "called from the AWT thread");

		TreeModelEvent event;
		if (parentNode == null) { // special case when root node changes.
			event = new TreeModelEvent(this, changedNode.getTreePath(), null, null);
		}
		else {
			int indexInParent = changedNode.getIndexInParent();
			if (indexInParent < 0) {
				return; // node is filtered
			}
			event =
				new TreeModelEvent(this, parentNode.getTreePath(), new int[] { indexInParent },
					new Object[] { changedNode });
		}
		for (TreeModelListener listener : listeners) {
			listener.treeNodesChanged(event);
		}
	}

	public void fireNodeAdded(final GTreeNode parentNode, final GTreeNode newNode) {
		if (!eventsEnabled) {
			return;
		}
		SystemUtilities.assertThisIsTheSwingThread(
			"GTreeModel.fireNodeAdded() must be " + "called from the AWT thread");

		int indexInParent = newNode.getIndexInParent();
		if (indexInParent < 0) {
			return;
		}

		TreeModelEvent event =
			new TreeModelEvent(this, parentNode.getTreePath(), new int[] { indexInParent },
				new Object[] { newNode });
		for (TreeModelListener listener : listeners) {
			listener.treeNodesInserted(event);
		}
	}

	public void fireNodeRemoved(final GTreeNode parentNode, final GTreeNode removedNode,
			final int oldIndexInParent) {

		SystemUtilities.assertThisIsTheSwingThread(
			"GTreeModel.fireNodeRemoved() must be " + "called from the AWT thread");

		TreeModelEvent event =
			new TreeModelEvent(this, parentNode.getTreePath(), new int[] { oldIndexInParent },
				new Object[] { removedNode });
		for (TreeModelListener listener : listeners) {
			listener.treeNodesRemoved(event);
		}
	}

	public void dispose() {
		root = null;
	}

	public void setEventsEnabled(boolean b) {
		eventsEnabled = b;
	}
}
