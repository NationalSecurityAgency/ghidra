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

import java.util.List;

import javax.swing.Icon;
import javax.swing.tree.TreePath;

import docking.widgets.tree.support.GTreeFilter;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public interface GTreeNode extends Comparable<GTreeNode>, Iterable<GTreeNode> {

	/**
	 * Returns the name of the node to be displayed in the tree
	 * @return the name of the node.
	 */
	public String getName();

	/**
	 * Returns the Icon to be displayed for this node in the tree.
	 * @param expanded true if the node is expanded.
	 * @return the icon to be displayed for this node in the tree.
	 */
	public Icon getIcon(boolean expanded);

	/**
	 * Returns the string to be displayed as a tooltip when the user 
	 * hovers the mouse on this node in the tree.
	 * @return the tooltip to be displayed.
	 */
	public String getToolTip();

	/**
	 * Returns true if this node never has children.
	 * @return true if this node is a leaf.
	 */
	public boolean isLeaf();

	/**
	 * Adds the given node as a child to this node.
	 * @param node the node to add as a child.
	 */
	public void addNode(GTreeNode node);

	/**
	 * Adds the given node at the given index as a child to this node.
	 * @param index the index to place the node.
	 * @param node the node to add as a child of this node.
	 */
	public void addNode(int index, GTreeNode node);

	/**
	 * Returns the list of children including those that have been filtered out.
	 * @return the list of all children of this node including those that are filtered out.
	 */
	public List<GTreeNode> getAllChildren();

	/**
	 * Returns all of the <b>visible</b> children of this node.  If there are filtered nodes, then
	 * they will not be returned.
	 * 
	 * @return all of the <b>visible</b> children of this node.  If there are filtered nodes, then
	 * 		   they will not be returned.
	 */
	public List<GTreeNode> getChildren();

	/**
	 * Returns the number of <b>visible</b> children of this node.  Does not include
	 * nodes that are current filtered out.
	 * @return the number of <b>visible</b> children of this node.
	 */
	public int getChildCount();

	/**
	 * Returns the number of <b>all</b> children of this node.  Includes nodes that
	 * are currently filtered out.
	 * @return the number of <b>all</b? children of this node.
	 */
	public int getAllChildCount();

	/**
	 * Returns the child node of this node with the given name.
	 * @param name the name of the child to be returned.
	 * @return the child with the given name.
	 */
	public GTreeNode getChild(String name);

	/**
	 * Returns the child node at the given index. Returns null if the index is out of
	 * bounds.
	 * @param index the index of the child to be returned.
	 * @return the child at the given index.
	 */
	public GTreeNode getChild(int index);

	/**
	 * Returns the total number of nodes in the subtree rooted at this node.  Leaf
	 * nodes return 1.
	 * @return the number of nodes from this node downward.
	 */
	public int getNodeCount();

	/**
	 * Returns the total number of leaf nodes in the subtree from this node.
	 * @return the total number of leaf nodes in the subtree from this node.
	 */
	public int getLeafCount();

	/**
	 * Returns the index of this node within its parent node.
	 * @return the index of this node within its parent node.
	 */
	public int getIndexInParent();

	/**
	 * Returns the index of the given node within this node.  -1 is returned
	 * if the node is not a child of this node.
	 * @param node whose index we want.
	 * @return the index of the given node within this node.
	 */
	public int getIndexOfChild(GTreeNode node);

	/**
	 * Returns the TreePath for this node.
	 * @return the TreePath for this node.
	 */
	public TreePath getTreePath();

	/**
	 * Removes all children from this node.  The children nodes will be disposed.
	 */
	public void removeAll();

	/**
	 * Remove the given node from this node.
	 * @param node the to be removed.
	 */
	public void removeNode(GTreeNode node);

	/**
	 * Sets the children on this node.  Any existing current children will be dispose.
	 * @param childList this list of nodes to be set as children of this node.
	 */
	public void setChildren(List<GTreeNode> childList);

	/**
	 * Returns true if the given node is a child of this node or one of its children.
	 * @param node the potential descendant node to check
	 */
	public boolean isAncestor(GTreeNode node);

	/**
	 * Applies the the given filter to the subtree of this node.  Nodes will be
	 * filtered out if the node and all of its descendants are not accepted by the filter. In 
	 * other words, a node will remain if it or any of its descendants are accepted by the filter.
	 * @param filter the filter being applied.
	 * @param monitor a TaskMonitor for tracking the progress and cancelling.
	 * @param min the min value to use for the progress bar for this subtree.
	 * @param max the max value to use for the progress bar for this subtree.
	 * @throws CancelledException if the operation is cancelled via the TaskMonitor.
	 */
	public void filter(GTreeFilter filter, TaskMonitor monitor, int min, int max)
			throws CancelledException;

	/**
	 * Removes any filtering on this subtree.
	 */
	public void clearFilter();

	/**
	 * Returns true if this node is filtered and not in the current view 
	 */
	public boolean isFilteredOut();

	/**
	 * Notification method called when a cell editor completes editing to notify this
	 * node that its value has changed.  If you override this method you must also override 
	 * {@link #isEditable()}.
	 * @param newValue the new value provided by the cell editor.
	 * @see #isEditable()
	 */
	public void valueChanged(Object newValue);

	/**
	 * Returns true if this node is allowed to be edited in the tree.  You must override this
	 * method to allow a node to be edited.  You must also override {@link #valueChanged(Object)}
	 * to handle the result of the edit.
	 * @return true if this node is allowed to be edited in the tree.
	 * @see #valueChanged(Object)
	 */
	public boolean isEditable();

	/**
	 * Returns the rootNode for this tree or null if there is no parent path to a
	 * GTRootNode.
	 * @return the rootNode for this tree. 
	 */
	public GTreeRootNode getRoot();

	/**
	 * Returns the GTTree that contains this node. 
	 * @return the GTTree that contains this node.
	 */
	public GTree getTree();

	/**
	 * Disposes this node and all of its descendants.
	 */
	public void dispose();

	/**
	 * Returns true if this node is currently being modified.
	 * @return true if this node is currently being modified.
	 */
	public boolean isInProgress();

	/**
	 * Notifies the tree that the node has different children.  This method 
	 * @param node the node that has changed.
	 */
	public void fireNodeStructureChanged(GTreeNode node);

	/**
	 * Notifies the tree that a node has changed.
	 * @param parentNode the node that contains the node that was changed.
	 * @param node the that changed.
	 */
	public void fireNodeChanged(GTreeNode parentNode, GTreeNode node);

	/**
	 * Returns the parent of this node.
	 * @return the parent of this node.
	 */
	public GTreeNode getParent();

}
