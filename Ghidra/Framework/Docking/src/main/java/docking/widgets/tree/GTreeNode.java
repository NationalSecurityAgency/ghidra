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
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;

import javax.swing.Icon;
import javax.swing.tree.TreePath;

import docking.widgets.tree.support.*;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import util.CollectionUtils;

/**
 * Base implementation for GTree nodes. Direct subclasses of this class are expected to have
 * all their children in hand when initially constructed (either in their constructor or externally
 * using {@link #addNode(GTreeNode)} or {@link #setChildren(List)}.  For large trees, subclasses
 * should instead extend {@link GTreeLazyNode} or {@link GTreeSlowLoadingNode}
 * <P>
 * All methods in this class that mutate the children node must perform that operation in
 * the swing thread.
 */
public abstract class GTreeNode extends CoreGTreeNode implements Comparable<GTreeNode> {
	private static AtomicLong NEXT_ID = new AtomicLong();

	private final long id;

	protected GTreeNode() {
		id = NEXT_ID.incrementAndGet();
	}

	@Override
	protected List<GTreeNode> generateChildren() {
		return Collections.emptyList();
	}

	/**
	 * Returns the name of the node to be displayed in the tree
	 * @return the name of the node
	 */
	public abstract String getName();

	/**
	 * Returns the Icon to be displayed for this node in the tree
	 * @param expanded true if the node is expanded
	 * @return the icon to be displayed for this node in the tree
	 */
	public abstract Icon getIcon(boolean expanded);

	/**
	 * Returns the string to be displayed as a tooltip when the user 
	 * hovers the mouse on this node in the tree
	 * @return the tooltip to be displayed
	 */
	public abstract String getToolTip();

	/**
	 * Returns true if this node never has children
	 * @return true if this node is a leaf
	 */
	public abstract boolean isLeaf();

	@Override
	public int compareTo(GTreeNode node) {
		return getName().compareToIgnoreCase(node.getName());
	}

	/**
	 * Adds the given node as a child to this node.  Note: this method may be inefficient so if you
	 * have many nodes to add, you should use either {@link #addNodes(List)} or {@link #setChildren(List)}
	 * @param node the node to add as a child
	 */
	public void addNode(GTreeNode node) {
		Swing.runNow(() -> doAddNode(node));
	}

	/**
	 * Adds the given nodes as children to this node
	 * @param nodes the nodes to add
	 */
	public void addNodes(List<GTreeNode> nodes) {
		Swing.runNow(() -> doAddNodes(nodes));
	}

	/**
	 * Adds the given node at the given index as a child to this node
	 * @param index the index to place the node
	 * @param node the node to add as a child of this node
	 */
	public void addNode(int index, GTreeNode node) {
		Swing.runNow(() -> doAddNode(index, node));
	}

	/**
	 * Returns all of the <b>visible</b> children of this node.  If there are filtered nodes, then
	 * they will not be returned.
	 * 
	 * @return all of the <b>visible</b> children of this node.  If there are filtered nodes, then
	 * 		   they will not be returned.
	 */
	public List<GTreeNode> getChildren() {
		return Collections.unmodifiableList(children());
	}

	/**
	 * Returns the number of <b>visible</b> children of this node.  Does not include
	 * nodes that are current filtered out
	 * @return the number of <b>visible</b> children of this node
	 */
	public int getChildCount() {
		return children().size();
	}

	/**
	 * Returns the child node of this node with the given name.
	 * @param name the name of the child to be returned
	 * @return the child with the given name
	 */
	public GTreeNode getChild(String name) {
		for (GTreeNode node : children()) {
			if (name.equals(node.getName())) {
				return node;
			}
		}
		return null;
	}

	/**
	 * Returns the child node at the given index. Returns null if the index is out of
	 * bounds.
	 * @param index the index of the child to be returned
	 * @return the child at the given index
	 */
	public GTreeNode getChild(int index) {
		return children().get(index);
	}

	/**
	 * Returns the total number of nodes in the subtree rooted at this node.  Leaf
	 * nodes return 1.
	 * @return the number of nodes from this node downward
	 */
	public int getNodeCount() {
		int count = 1;
		for (GTreeNode node : children()) {
			count += node.getNodeCount();
		}
		return count;
	}

	/**
	 * Returns the total number of leaf nodes in the subtree from this node
	 * @return the total number of leaf nodes in the subtree from this node
	 */
	public int getLeafCount() {
		int count = 0;
		for (GTreeNode node : children()) {
			count += node.getLeafCount();
		}
		return count == 0 ? 1 : count;		// if my child count == 0, return 1 since I am a leaf
	}

	/**
	 * Returns the index of this node within its parent node
	 * @return the index of this node within its parent node
	 */
	public int getIndexInParent() {
		GTreeNode parent = getParent();
		if (parent == null) {
			return -1;
		}
		return parent.getIndexOfChild(this);
	}

	/**
	 * Returns the index of the given node within this node.  -1 is returned
	 * if the node is not a child of this node.
	 * @param node whose index we want
	 * @return the index of the given node within this node
	 */
	public int getIndexOfChild(GTreeNode node) {
		return children().indexOf(node);
	}

	/**
	 * Returns the TreePath for this node
	 * @return the TreePath for this node
	 */
	public TreePath getTreePath() {
		return new TreePath(getPathToRoot(this, 0));
	}

	/**
	 * Removes all children from this node.  The children nodes will be disposed.
	 */
	public void removeAll() {
		Swing.runNow(() -> doSetChildrenAndFireEvent(null));
	}

	/**
	 * Remove the given node from this node
	 * @param node the to be removed
	 */
	public void removeNode(GTreeNode node) {
		Swing.runNow(() -> doRemoveNode(node));
	}

	/**
	 * Sets the children on this node.  Any existing current children will be dispose.
	 * @param childList this list of nodes to be set as children of this node
	 */
	public void setChildren(List<GTreeNode> childList) {
		Swing.runNow(() -> doSetChildrenAndFireEvent(childList));
	}

	/**
	 * Returns true if the given node is a child of this node or one of its children.
	 * @param node the potential descendant node to check
	 * @return  true if the given node is a child of this node or one of its children
	 */
	public boolean isAncestor(GTreeNode node) {
		GTreeNode nodeParent = node.getParent();
		while (nodeParent != null) {
			if (nodeParent.equals(this)) {
				return true;
			}
			nodeParent = nodeParent.getParent();
		}
		return false;
	}

	/**
	 * Notification method called when a cell editor completes editing to notify this
	 * node that its value has changed.  If you override this method you must also override 
	 * {@link #isEditable()}.
	 * @param newValue the new value provided by the cell editor
	 * @see #isEditable()
	 */
	public void valueChanged(Object newValue) {
		// Overridden in subclasses
	}

	/**
	 * Returns true if this node is allowed to be edited in the tree.  You must override this
	 * method to allow a node to be edited.  You must also override {@link #valueChanged(Object)}
	 * to handle the result of the edit.
	 * @return true if this node is allowed to be edited in the tree
	 * @see #valueChanged(Object)
	 */
	public boolean isEditable() {
		return false;
	}

	/**
	 * Returns the rootNode for this tree or null if there is no parent path to a
	 * GTRootNode
	 * @return the rootNode for this tree
	 */
	public GTreeNode getRoot() {
		GTreeNode myParent = getParent();
		if (myParent == null || myParent instanceof GTreeRootParentNode) {
			return this;
		}
		return myParent.getRoot();
	}

	/**
	 * Returns true if this is a root node
	 * @return  true if this is a root node
	 */
	public boolean isRoot() {
		return getRoot() == this;
	}

	/**
	 * Generates a filtered copy of this node and its children.
	 * <P>
	 * A node will be included if it or any of its descendants are accepted by the filter.
	 * NOTE: the filter will only be applied to a nodes children if they are loaded. So to 
	 * perform a filter on all the nodes in the tree, the {@link #loadAll(TaskMonitor)} should
	 * be called before the filter call. 
	 * @param filter the filter being applied
	 * @param monitor a TaskMonitor for tracking the progress and cancelling
	 * @return A copy of this node and its children that matches the filter or null 
	 * if this node and none of its children match the filter.
	 * @throws CancelledException if the operation is cancelled via the TaskMonitor
	 * @throws CloneNotSupportedException if any nodes in the tree explicitly prevents cloning
	 */

	public GTreeNode filter(GTreeFilter filter, TaskMonitor monitor)
			throws CancelledException, CloneNotSupportedException {
		List<GTreeNode> list = new ArrayList<>();

		if (isLoaded()) {
			for (GTreeNode child : children()) {
				monitor.checkCanceled();
				GTreeNode filtered = child.filter(filter, monitor);
				if (filtered != null) {
					list.add(filtered);
				}
				monitor.incrementProgress(1);
			}
		}

		if (isRoot() || !list.isEmpty() || filter.acceptsNode(this) || getParent() == null) {
			GTreeNode clone = clone();
			clone.doSetChildren(list);
			return clone;
		}
		return null;
	}

	/**
	 * Causes any lazy or slow loading nodes in the tree to load their children so that the tree 
	 * is fully loaded. Nodes that are already loaded (including normal nodes which are always loaded)
	 * do nothing except recursively call {@link #loadAll(TaskMonitor)} on their children.
	 * @param monitor the TaskMonitor to monitor progress and provide cancel checking
	 * @return the total number of nodes in the subtree of this node
	 * @throws CancelledException if the operation is cancelled using the monitor
	 */
	public int loadAll(TaskMonitor monitor) throws CancelledException {
		List<GTreeNode> children = children();
		monitor = new TreeTaskMonitor(monitor, children.size());
		int count = 1;
		for (GTreeNode child : children) {
			monitor.checkCanceled();
			count += child.loadAll(monitor);
			monitor.incrementProgress(1);
		}
		return count;
	}

	@Override
	public int hashCode() {
		return (int) id;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		GTreeNode other = (GTreeNode) obj;
		return id == other.id;
	}

	/**
	 * Returns a stream of the GTree nodes in the subtree of this node
	 * @param depthFirst if true, the nodes will be streamed in depth-first order, otherwise breadth-first order
	 * @return a stream of the GTree nodes in the subtree of this node
	 */
	public Stream<GTreeNode> stream(boolean depthFirst) {
		return CollectionUtils.asStream(iterator(depthFirst));
	}

	/**
	 * Returns an iterator of the GTree nodes in the subtree of this node
	 * @param depthFirst if true, the nodes will be returned in depth-first order, otherwise breadth-first order
	 * @return an iterator of the GTree nodes in the subtree of this node
	 */
	public Iterator<GTreeNode> iterator(boolean depthFirst) {
		if (depthFirst) {
			return new DepthFirstIterator(this);
		}
		return new BreadthFirstIterator(this);
	}

	@Override
	public String toString() {
		return getName();
	}

	/**
	 * Returns an id for this node that is unique among all GTreeNodes in this running JVM.
	 * If this node is cloned, the clone will have the same id.
	 * @return the unique id for this node.
	 */
	public long getId() {
		return id;
	}

	/**
	 * Notifies the tree that the node has different children.  This method 
	 * @param node the node that has changed.
	 */
	public void fireNodeStructureChanged(GTreeNode node) {
		Swing.runNow(() -> doFireNodeStructureChanged());
	}

	/**
	 * Notifies the tree that a node has changed
	 * @param parentNode the node that contains the node that was changed
	 * @param node the that changed
	 */
	public void fireNodeChanged(GTreeNode parentNode, GTreeNode node) {
		Swing.runNow(() -> doFireNodeChanged());
	}

	private GTreeNode[] getPathToRoot(GTreeNode node, int depth) {
		GTreeNode[] returnNodes;

		/* Check for null, in case someone passed in a null node, or
		   they passed in an element that isn't rooted at root. */
		if (node == null || node instanceof GTreeRootParentNode) {
			if (depth == 0) {
				return null;
			}
			returnNodes = new GTreeNode[depth];
		}
		else {
			depth++;
			returnNodes = getPathToRoot(node.getParent(), depth);
			returnNodes[returnNodes.length - depth] = node;
		}
		return returnNodes;
	}

}
