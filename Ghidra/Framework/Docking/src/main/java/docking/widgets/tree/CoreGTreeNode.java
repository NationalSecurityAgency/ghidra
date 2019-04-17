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
package docking.widgets.tree;

import ghidra.util.SystemUtilities;

import java.util.*;

import javax.swing.SwingUtilities;

import docking.widgets.tree.internal.InProgressGTreeNode;

/**
 * This class is not meant to be subclassed directly.  Instead, you should extend 
 * {@link AbstractGTreeNode}.
 * <p>
 * This class is responsible for mutating/managing the children and parent of this node.  These
 * items are sensitive to threading issues, which this class is designed to handle.
 * <p>
 * The pattern used by this class is to create <tt>doXXX</tt> methods for the public mutator 
 * methods of the {@link GTreeNode} interface.
 */
abstract class CoreGTreeNode implements GTreeNode {
	private static InProgressGTreeNode IN_PROGRESS_NODE = new InProgressGTreeNode();
	private static List<GTreeNode> IN_PROGRESS_CHILDREN =
		Collections.unmodifiableList(Arrays.asList(new GTreeNode[] { IN_PROGRESS_NODE }));

	private GTreeNode parent;
	private List<GTreeNode> allChildrenList = null;
	private List<GTreeNode> activeChildrenList = null;

	@Override
	public synchronized GTreeNode getParent() {
		return parent;
	}

	@Override
	public void dispose() {
		parent = null;
		if (allChildrenList == null) {
			return;
		}
		for (GTreeNode node : allChildrenList) {
			node.dispose();
		}
		allChildrenList = null;
		activeChildrenList = null;
	}

	@Override
	public synchronized boolean isInProgress() {
		return activeChildrenList == IN_PROGRESS_CHILDREN;
	}

	protected void setInProgress() {
		doSetActiveChildren(IN_PROGRESS_CHILDREN);
	}

	public synchronized boolean isChildrenLoadedOrInProgress() {
		return activeChildrenList != null;
	}

	protected synchronized boolean isChildrenLoaded() {
		return allChildrenList != null;
	}

	protected synchronized int doGetChildCount() {
		if (activeChildrenList != null) {
			return activeChildrenList.size();
		}
		return 0;
	}

	protected synchronized int doGetAllChildCount() {
		if (allChildrenList != null) {
			return allChildrenList.size();
		}
		return 0;
	}

	protected synchronized List<GTreeNode> doGetAllChildren() {
		if (allChildrenList == null) {
			return Collections.emptyList();
		}
		return new ArrayList<GTreeNode>(allChildrenList);
	}

	protected synchronized List<GTreeNode> doGetActiveChildren() {
		if (activeChildrenList == null) {
			return Collections.emptyList();
		}
		return new ArrayList<GTreeNode>(activeChildrenList);
	}

	protected synchronized GTreeNode doGetChild(int index) {
		if (activeChildrenList == null) {
			return null;
		}
		if (index < 0 || index >= activeChildrenList.size()) {
			return null;
		}
		return activeChildrenList.get(index);
	}

	protected synchronized int doGetIndexOfChild(GTreeNode node) {
		if (activeChildrenList == null) {
			return -1;
		}
		return activeChildrenList.indexOf(node);
	}

	/**
	 * Subclasses can override this method to perform faster lookups of a node; for 
	 * example, if the subclass has a sorted list of children, then a binary search can
	 * be used. 
	 * 
	 * @param node the node whose index we seek
	 * @param children the children who contain the given node (may be null)
	 * @return the index of the given child in the given list
	 */
	protected synchronized int doGetIndexOfChild(GTreeNode node, List<GTreeNode> children) {
		if (children == null) {
			return -1;
		}
		return children.indexOf(node);
	}

//==================================================================================================
// Setter/Mutator Methods
//==================================================================================================	

	protected void doAddNode(final int index, final GTreeNode child) {

		if (SwingUtilities.isEventDispatchThread()) {
			swingAddNode(index, child);
			return;
		}

		SystemUtilities.runSwingNow(new Runnable() {
			@Override
			public void run() {
				swingAddNode(index, child);
			}
		});
	}

	private void swingAddNode(int index, GTreeNode child) {
		//
		// The following code is 'Swing Atomic'--it all (manipulation and notification) happens
		// in the Swing thread together, which synchronizes it with other Swing operations.
		//

		// Synchronized so that the accessor methods do not try to read while we are writing.
		synchronized (this) {
			if (allChildrenList == null) {
				allChildrenList = new ArrayList<GTreeNode>();
				activeChildrenList = allChildrenList;
			}
			if (allChildrenList.contains(child)) {
				return;
			}
			((CoreGTreeNode) child).parent = this;

			if (index < 0 || index >= allChildrenList.size()) {
				index = allChildrenList.size();
			}
			allChildrenList.add(index, child);
		}

		// can't be in synchronized block!
		fireNodeAdded(this, child);
	}

	@Override
	public void removeNode(final GTreeNode node) {

		if (SwingUtilities.isEventDispatchThread()) {
			swingRemoveNode(node);
			return;
		}

		SystemUtilities.runSwingNow(new Runnable() {
			@Override
			public void run() {
				swingRemoveNode(node);
			}
		});
	}

	private void swingRemoveNode(GTreeNode node) {
		int index;
		synchronized (this) {
			((CoreGTreeNode) node).parent = null;
			if (activeChildrenList == null) {
				return;
			}

			index = activeChildrenList.indexOf(node);
			if (index >= 0) {
				activeChildrenList.remove(index);
			}
			if (allChildrenList != activeChildrenList && allChildrenList != null) {
				allChildrenList.remove(node);
			}
		}

		// can't be in synchronized block!
		if (index >= 0) {
			fireNodeRemoved(this, node, index);
		}
	}

	protected void doSetChildren(final List<GTreeNode> childList, final boolean notify) {

		if (SwingUtilities.isEventDispatchThread()) {
			swingSetChildren(childList, notify, false);
			return;
		}

		SystemUtilities.runSwingNow(new Runnable() {
			@Override
			public void run() {
				swingSetChildren(childList, notify, false);
			}
		});
	}

	protected void swingSetChildren(List<GTreeNode> childList, boolean notify,
			boolean onlyIfInProgress) {
		//
		// The following code is 'Swing Atomic'--it all (manipulation and notification) happens
		// in the Swing thread together, which synchronizes it with other Swing operations.
		//

		// Synchronized so that the accessor methods do not try to read while we are writing.
		synchronized (this) {
			if (childList == null) {
				allChildrenList = null;
				activeChildrenList = null;
			}
			else {
				if (onlyIfInProgress && !isInProgress()) {
					return;
				}

				for (GTreeNode child : childList) {
					((CoreGTreeNode) child).parent = this;
				}

				allChildrenList = new ArrayList<GTreeNode>(childList);
				activeChildrenList = allChildrenList;
			}
		}

		// can't be in synchronized block!
		if (notify) {
			notifyNodeStructureChanged(this);
		}
	}

	protected void doSetActiveChildren(final List<GTreeNode> childList) {

		if (SwingUtilities.isEventDispatchThread()) {
			swingSetActiveChilren(childList);
			return;
		}

		SystemUtilities.runSwingNow(new Runnable() {
			@Override
			public void run() {
				swingSetActiveChilren(childList);
			}
		});
	}

	private void swingSetActiveChilren(List<GTreeNode> childList) {
		//
		// The following code is 'Swing Atomic'--it all (manipulation and notification) happens
		// in the Swing thread together, which synchronizes it with other Swing operations.
		//

		// Synchronized so that the accessor methods do not try to read while we are writing.
		synchronized (this) {
			activeChildrenList = childList;
		}

		// can't be in synchronized block!
		notifyNodeStructureChanged(this);
	}

	/**
	 * Convenience method to clear any filtered items by restoring the active children of this
	 * node to be the complete set of children.
	 */
	protected void doResetActiveChildren() {
		doSetActiveChildren(allChildrenList);
	}

//==================================================================================================
// Utility Methods
//==================================================================================================	

	@Override
	public void fireNodeChanged(final GTreeNode parentNode, final GTreeNode node) {

		SystemUtilities.runIfSwingOrPostSwingLater(new Runnable() {
			@Override
			public void run() {
				notifyNodeChanged(parentNode, node);
			}
		});
	}

	private void notifyNodeChanged(GTreeNode parentNode, GTreeNode node) {
		if (isAnyAncestorInProgress()) {
			return;
		}

		GTree tree = getTree();
		if (isInValidTree(tree)) {
			tree.getModel().fireNodeDataChanged(parentNode, node);
		}
	}

	private boolean isInValidTree(GTree tree) {
		return tree != null && !tree.isDisposed();
	}

	@Override
	public void fireNodeStructureChanged(final GTreeNode node) {

		SystemUtilities.runIfSwingOrPostSwingLater(new Runnable() {
			@Override
			public void run() {
				notifyNodeStructureChanged(node);
			}
		});
	}

	private void notifyNodeStructureChanged(GTreeNode node) {
		if (isAnyAncestorInProgress()) {
			return;
		}

		GTree tree = getTree();
		if (isInValidTree(tree)) {
			tree.getModel().fireNodeStructureChanged(node);
		}
	}

	private void fireNodeAdded(GTreeNode parentNode, GTreeNode newNode) {
		// assumption: we are always called in the Swing thread.
		if (!isAnyAncestorInProgress()) {
			GTree tree = getTree();
			if (isInValidTree(tree)) {
				tree.getModel().fireNodeAdded(parentNode, newNode);
			}
		}
	}

	private void fireNodeRemoved(GTreeNode parentNode, GTreeNode removedNode, int deletedChildIndex) {
		// assumption: we are always called in the Swing thread.
		if (!isAnyAncestorInProgress()) {
			GTree tree = getTree();
			if (isInValidTree(tree)) {
				tree.getModel().fireNodeRemoved(parentNode, removedNode, deletedChildIndex);
			}
		}
	}

	private boolean isAnyAncestorInProgress() {
		GTreeNode node = this;
		while (node != null) {
			if (node.isInProgress()) {
				return true;
			}
			node = node.getParent();
		}
		return false;
	}

//==================================================================================================
// End Utility Methods
//==================================================================================================	

}
