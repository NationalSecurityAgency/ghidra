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

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.swing.JTree;

import docking.widgets.tree.internal.InProgressGTreeNode;
import ghidra.util.Swing;
import ghidra.util.SystemUtilities;

/**
 * This class exists to help prevent threading errors in {@link GTreeNode} and subclasses,
 * by privately maintaining synchronous access to the parent and children of a node. 
 * <P>
 * This implementation uses a {@link CopyOnWriteArrayList} to store its children. The theory is
 * that this will allow direct thread-safe access to the children without having to worry about
 * {@link ConcurrentModificationException}s while iterating the children.  Also, the assumption
 * is that accessing the children will occur much more frequently than modifying the children.  
 * This should only be a problem if a direct descendent of GTreeNode creates its children by calling
 * addNode many times. But in that case, the tree should be using Lazy or 
 * SlowLoading nodes which always load into another list first and all the children will be set 
 * on a node in a single operation.
 * <P>
 * Subclasses that need access to the children can call the {@link #children()} method which will
 * ensure that the children are loaded (not null). Since this class uses a
 * {@link CopyOnWriteArrayList}, subclasses that call the {@link #children()} method can safely
 * iterate the list without having to worry about getting a {@link ConcurrentModificationException}.  
 * <P>
 * This class uses synchronization to assure that the parent/children relationship is stable across
 * threads.  To avoid deadlocks, the sychronization strategy is that if you have the lock on
 * a parent node, you can safely acquire the lock on any of its descendants, but never its 
 * ancestors.  To facilitate this strategy, the {@link #getParent()} is not synchronized, but it
 * is made volatile to assure the current value is always used.
 * <P>
 * Except for the {@link #doSetChildren(List)} method, all other calls that mutate the
 * children must be called on the swing thread.  The idea is that bulk operations can work efficiently
 * by avoiding constantly switching to the swing thread to mutate the tree. This works because
 * the bulk setting of the children generates a coarse "node structure changed" event, which causes the
 * underlying {@link JTree} to rebuild its internal cache of the tree.  Individual add/remove operations
 * have to be done very carefully such that the {@link JTree} is always updated on one change before any
 * additional changes are done.  This is why those operations are required to be done on the swing
 * thread, which combined with the fact that all mutate operations are synchronized, keeps the JTree
 * happy.
 * 
 */
abstract class CoreGTreeNode implements Cloneable {
	// the parent is volatile to facilitate the synchronization strategy (see comments above)
	private volatile GTreeNode parent;
	private List<GTreeNode> children;

	/**
	 * Returns the parent of this node.
	 * 
	 * Note: this method is deliberately not synchronized (See comments above)
	 * @return the parent of this node.
	 */
	public final GTreeNode getParent() {
		GTreeNode localParent = parent;

		// Do not return the GTree's fake root node parent.  From the client's perspective,
		// this node does not exist.		
		if (localParent instanceof GTreeRootParentNode) {
			return null;
		}
		return localParent;
	}

	/**
	 * Sets the parent of this node.  This method should only be used by a parent
	 * node when a new child is added to that parent node.
	 * @param parent the node that this node is being added to.
	 */
	synchronized final void setParent(GTreeNode parent) {
		this.parent = parent;
	}

	// provides direct access to the children list 
	protected final List<GTreeNode> children() {
		synchronized (this) {
			if (isLoaded()) {
				return children;
			}
		}

		// The generateChildren must be called outside the synchronized scope because
		// if it is slow it will lock out other threads. Keep in mind that if this is
		// called outside the swing thread then this doesn't return
		// until the work is completed (even for slow loading nodes - they only offload
		// the children loading in another task if called on the swing thread)
		List<GTreeNode> newChildren = generateChildren();

		synchronized (this) {
			// null implies cancelled
			if (newChildren == null) {
				return Collections.emptyList();
			}

			// This can be tricky. If we are in the swing thread and the generate children
			// is deferred to a background thread and we are about to set an in-progress node,
			// then it is possible that the background thread got here first and we are about
			// to overwrite the actual children with an in-progress node. Check for that case.
			if (isInProgress(newChildren) && children != null) {
				return children;
			}

			doSetChildren(newChildren);

			return children;
		}
	}

	/**
	 * Subclasses implement this method to initially load the children.
	 * @return a list of the initial children for this node. 
	 */
	protected abstract List<GTreeNode> generateChildren();

	/**
	 * Sets the children of this node to the given list of child nodes and fires the appropriate
	 * tree event to kick the tree to update the display.  Note: This method must be called
	 * from the swing thread because it will notify the underlying JTree.
	 * @param childList the list of child nodes to assign as children to this node
	 * @see #doSetChildren(List) if calling from a background thread.
	 */
	protected synchronized void doSetChildrenAndFireEvent(List<GTreeNode> childList) {
		doSetChildren(childList);
		doFireNodeStructureChanged();
	}

	/**
	 * Sets the children of this node to the given list of child nodes, but does not notify the
	 * tree. This method does not have to be called from the swing thread.  It is intended to be
	 * used by background threads that want to populate all or part of the tree, but wait until
	 * the bulk operations are completed before notifying the tree.
	 * @param childList the list of child nodes to assign as children to this node
	 */
	protected synchronized void doSetChildren(List<GTreeNode> childList) {
		List<GTreeNode> oldChildren = children;
		children = null;

		if (oldChildren != null) {
			for (GTreeNode node : oldChildren) {
				node.setParent(null);
			}
		}

		if (childList != null) {
			for (GTreeNode node : childList) {
				node.setParent((GTreeNode) this);
			}
			children = new CopyOnWriteArrayList<GTreeNode>(childList);
		}

		if (oldChildren != null) {
			for (GTreeNode node : oldChildren) {
				// only dispose old nodes that aren't included in the new child list - if any
				// old nodes don't have a parent, then they were not include in the new list
				if (node.getParent() == null) {
					node.dispose();
				}
			}
		}
	}

	/**
	 * Adds a node to this node's children. Must be called from the swing thread.
	 * @param node the node to add as a child to this node
	 */
	protected synchronized void doAddNode(GTreeNode node) {
		doAddNode(children().size(), node);
	}

	/**
	 * Adds a node to this node's children at the given index and notifies the tree.
	 * Must be called from the swing thread.
	 * @param index the index at which to add the new node
	 * @param node the node to add as a child to this node
	 */
	protected synchronized void doAddNode(int index, GTreeNode node) {
		List<GTreeNode> kids = children();
		if (kids.contains(node)) {
			return;
		}
		int insertIndex = Math.min(kids.size(), index);
		kids.add(insertIndex, node);
		node.setParent((GTreeNode) this);
		doFireNodeAdded(node);
	}

	/**
	 * Removes the node from this node's children and notifies the tree.  Must be called
	 * from the swing thread.
	 * @param node the node to remove
	 */
	protected synchronized void doRemoveNode(GTreeNode node) {
		List<GTreeNode> kids = children();
		int index = kids.indexOf(node);
		if (index >= 0) {
			kids.remove(index);
			node.setParent(null);
			doFireNodeRemoved(node, index);
		}
	}

	/**
	 * Adds the given nodes to this node's children. Must be called from the swing thread.
	 * @param nodes the nodes to add to the children this node
	 */
	protected synchronized void doAddNodes(List<GTreeNode> nodes) {
		for (GTreeNode node : nodes) {
			node.setParent((GTreeNode) this);
		}
		children().addAll(nodes);
		doFireNodeStructureChanged();
	}

	/**
	 * Creates a clone of this node.  The clone should contain a shallow copy of all the node's
	 * attributes except that the parent and children are null.
	 * @return the clone of this object.
	 * @throws CloneNotSupportedException if some implementation prevents itself from being cloned.
	 */
	@Override
	public GTreeNode clone() throws CloneNotSupportedException {
		CoreGTreeNode clone = (GTreeNode) super.clone();
		clone.parent = null;
		clone.children = null;
		return (GTreeNode) clone;
	}

	public void dispose() {
		List<GTreeNode> oldChildren;
		synchronized (this) {
			oldChildren = children;
			children = null;
			parent = null;
		}

		if (oldChildren != null) {
			for (GTreeNode node : oldChildren) {
				node.dispose();
			}
			oldChildren.clear();
		}
	}

	/**
	 * This is used to dispose filtered "clone" nodes. When a filter is applied to the tree,
	 * the nodes that matched are "shallow" cloned, so when the filter is removed, we don't
	 * want to do a full dispose on the nodes, just clean up the parent-child references.
	 */
	final void disposeClones() {
		List<GTreeNode> oldChildren;
		synchronized (this) {
			oldChildren = children;
			children = null;
			parent = null;
		}

		if (oldChildren != null) {
			for (GTreeNode node : oldChildren) {
				node.disposeClones();
			}
			oldChildren.clear();
		}
	}

	/**
	 * Returns true if the node is in the process of loading its children. 
	 * See {@link GTreeSlowLoadingNode}
	 * @return true if the node is in the process of loading its children.
	 */
	public synchronized final boolean isInProgress() {
		return isInProgress(children);
	}

	/**
	 * True if the children for this node have been loaded yet.  Some GTree nodes are lazy in that they
	 * don't load their children until needed. Nodes that have the IN_PROGRESS node as it child
	 * is considered loaded if in the swing thread, otherwise they are considered not loaded. 
	 * @return true if the children for this node have been loaded.
	 */
	public synchronized boolean isLoaded() {
		if (children == null) {
			return false;
		}
		if (Swing.isSwingThread()) {
			return true;
		}
		return !isInProgress(children);
	}

	/**
	 * Returns the GTree that this node is attached to
	 * @return the GTree that this node is attached to
	 */
	public GTree getTree() {
		// here we want to use the parent variable, not getParent() which
		// filters out GTreeRootParentNodes which is what actually can provide the tree
		if (parent != null) {
			return parent.getTree();
		}
		return null;
	}

	/**
	 * Returns true if the node is in the process of loading its children.  For nodes
	 * that directly extend GTreeNode, this is always false.  See {@link GTreeSlowLoadingNode}
	 * for information on nodes that that can be in the progress of loading.
	 * @param childList the list to test.
	 * @return true if the node is in the progress of loading its children.
	 */
	private boolean isInProgress(List<GTreeNode> childList) {
		if (childList != null && childList.size() == 1 &&
			childList.get(0) instanceof InProgressGTreeNode) {
			return true;
		}
		return false;
	}

	protected void doFireNodeAdded(GTreeNode newNode) {
		assertSwing();
		GTree tree = getTree();
		if (tree != null) {
			tree.getModel().fireNodeAdded((GTreeNode) this, newNode);
			tree.refilterLater(newNode);
		}
	}

	protected void doFireNodeRemoved(GTreeNode removedNode, int index) {
		assertSwing();
		GTree tree = getTree();
		if (tree != null) {
			tree.getModel().fireNodeRemoved((GTreeNode) this, removedNode, index);
		}
	}

	protected void doFireNodeStructureChanged() {
		assertSwing();
		GTree tree = getTree();
		if (tree != null) {
			tree.getModel().fireNodeStructureChanged((GTreeNode) this);
			tree.refilterLater();
		}
	}

	protected void doFireNodeChanged() {
		assertSwing();
		GTree tree = getTree();
		if (tree != null) {
			tree.getModel().fireNodeDataChanged((GTreeNode) this);
			tree.refilterLater();
		}
	}

	private void assertSwing() {
		SystemUtilities
				.assertThisIsTheSwingThread("tree events must be called from the AWT thread");
	}

}
