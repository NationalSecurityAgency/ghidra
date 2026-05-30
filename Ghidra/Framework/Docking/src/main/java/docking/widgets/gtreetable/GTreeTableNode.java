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
package docking.widgets.gtreetable;

import java.io.Serializable;
import java.util.*;
import java.util.function.Consumer;
import java.util.function.Predicate;

import javax.swing.Icon;

public class GTreeTableNode implements Serializable {
	private class EachAncestorIterator implements Iterator<GTreeTableNode> {
		GTreeTableNode curNode = getParent();

		@Override
		public boolean hasNext() {
			return curNode != null;
		}

		@Override
		public GTreeTableNode next() {
			final GTreeTableNode ret = curNode;
			curNode = curNode.getParent();
			return ret;
		}
	}

	private class EachDecendantIterator implements Iterator<GTreeTableNode> {
		final List<GTreeTableNode> nodes = new ArrayList<>(children);

		@Override
		public boolean hasNext() {
			return !nodes.isEmpty();
		}

		@Override
		public GTreeTableNode next() {
			final GTreeTableNode curNode = nodes.removeFirst();
			nodes.addAll(curNode.getChildren());
			return curNode;
		}

	}

	private class EachExpandedIterator implements Iterator<GTreeTableNode> {
		final List<GTreeTableNode> nodes = new ArrayList<>(children);

		@Override
		public boolean hasNext() {
			return !nodes.isEmpty();
		}

		@Override
		public GTreeTableNode next() {
			final GTreeTableNode curNode = nodes.removeFirst();
			if (curNode.isExpanded()) {
				nodes.addAll((curNode.getChildren()));
			}
			return curNode;
		}

	}

	protected final String name;
	protected Icon icon;
	protected boolean expanded;

	protected GTreeTableNode parent;

	protected List<GTreeTableNode> children;

	protected boolean visible;

	public GTreeTableNode(final String name) {
		this.name = name;
		expanded = false;
		children = Collections.synchronizedList(new ArrayList<>());
		visible = true;
	}

	/**
	 * Add new child to this node's children
	 *
	 * @param newChild
	 * 		New child to add
	 */
	public void add(GTreeTableNode newChild) {
		if ((newChild != null) && (newChild.getParent() == this)) {
			insert(newChild, getChildCount() - 1);
		}
		else {
			insert(newChild, getChildCount());
		}
	}

	/**
	 * Get an iterable of all the ancestors of this node
	 *
	 * @return An iterable of ancestors
	 */
	public Iterable<GTreeTableNode> ancestors() {
		return EachAncestorIterator::new;
	}

	/**
	 * Get a list of all descendants of this node in depth first search order
	 *
	 * @return List of descendants in DFS order
	 */
	public List<GTreeTableNode> depthFirstSearchList() {
		final List<GTreeTableNode> nodes = new LinkedList<>();
		final List<GTreeTableNode> result = new LinkedList<>();

		result.add(this);
		nodes.addAll(0, getChildren());

		while (!nodes.isEmpty()) {
			final GTreeTableNode curNode = nodes.removeFirst();
			result.add(curNode);
			nodes.addAll(0, curNode.getChildren());
		}

		return result;
	}

	/**
	 * Get an iterable of all the descendants of this node
	 *
	 * @return An iterable of descendants
	 */
	public Iterable<GTreeTableNode> descendants() {
		return EachDecendantIterator::new;
	}

	/**
	 * Get an iterable of all the expanded descendants of this node
	 *
	 * @return An iterable of expanded descendants
	 */
	public Iterable<GTreeTableNode> expandedDescendants() {
		return EachExpandedIterator::new;
	}

	/**
	 * Find nodes in descendants that match a certain condition
	 *
	 * @param condition
	 * 		Predicate to match nodes on
	 * @return List of nodes matching the condition
	 */
	public List<GTreeTableNode> find(Predicate<GTreeTableNode> condition) {
		final List<GTreeTableNode> nodes = new LinkedList<>();
		final List<GTreeTableNode> result = new LinkedList<>();

		result.add(this);
		nodes.addAll(0, getChildren());

		while (!nodes.isEmpty()) {
			final GTreeTableNode curNode = nodes.removeFirst();
			if (condition.test(curNode)) {
				result.add(curNode);
			}
			nodes.addAll(0, curNode.getChildren());
		}
		return result;
	}

	/**
	 * Perform an action on each ancestor of this node
	 *
	 * @param action
	 * 		To perform on each ancestor
	 */
	public void forEachAncestor(final Consumer<GTreeTableNode> action) {
		GTreeTableNode curNode = getParent();
		while (curNode != null) {
			action.accept(curNode);
			curNode = curNode.getParent();
		}
	}

	/**
	 * Perform an action on each descendant of this node
	 *
	 * @param action
	 * 		To perform on each descendant
	 */
	public void forEachDescendant(final Consumer<GTreeTableNode> action) {
		final List<GTreeTableNode> nodes = new ArrayList<>(children);

		while (!nodes.isEmpty()) {
			final GTreeTableNode curNode = nodes.removeFirst();
			action.accept(curNode);
			nodes.addAll(curNode.getChildren());
		}
	}

	/**
	 * Perform an action on each expanded descendant of this node
	 *
	 * @param action
	 * 		To perform on each expanded descendant
	 */
	public void forEachExpanded(final Consumer<GTreeTableNode> action) {
		final List<GTreeTableNode> nodes = new ArrayList<>(children);

		while (!nodes.isEmpty()) {
			final GTreeTableNode curNode = nodes.removeFirst();
			action.accept(curNode);

			if (curNode.isExpanded()) {
				nodes.addAll((curNode.getChildren()));
			}
		}
	}

	/**
	 * Get number of children
	 *
	 * @return Number of children
	 */
	public int getChildCount() {
		return children.size();
	}

	/**
	 * Get list of children
	 *
	 * @return List of children
	 */
	public List<GTreeTableNode> getChildren() {
		return children;
	}

	/**
	 * Get list of descendants who are expanded
	 *
	 * @return List of expanded descendants
	 */
	public List<GTreeTableNode> getExpanded() {
		final List<GTreeTableNode> nodes = new ArrayList<>();
		forEachExpanded(nodes::add);
		return nodes;
	}

	/**
	 * Get icon
	 *
	 * @return icon
	 */
	public Icon getIcon() {
		return icon;
	}

	/**
	 * Get tree depth from the root node
	 *
	 * @return Level from root node
	 */
	public int getLevel() {
		int levels = 0;
		GTreeTableNode ancestor = this;
		while ((ancestor = ancestor.getParent()) != null) {
			++levels;
		}

		return levels;
	}

	/**
	 * Get name of node
	 *
	 * @return name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Get parent of node
	 *
	 * @return parent
	 */
	public GTreeTableNode getParent() {
		return parent;
	}

	/**
	 * Get list of ancestors in order leading to this node
	 *
	 * @return List of nodes leading to this one
	 */
	public List<GTreeTableNode> getPath() {
		final List<GTreeTableNode> path = new ArrayList<>();
		forEachAncestor(path::add);
		return path;
	}

	/**
	 * Get root node
	 *
	 * @return root node
	 */
	public GTreeTableNode getRoot() {
		for (GTreeTableNode cur = this;; cur = cur.getParent()) {
			if (cur.getParent() == null) {
				return cur;
			}
		}
	}

	/**
	 * Get data associated with this node
	 *
	 * @return data
	 */
	public String getTreeData() {
		return name;
	}

	/**
	 * Check if node has children
	 *
	 * @return true/false if node has children
	 */
	public boolean hasChildren() {
		return (children != null) && !children.isEmpty();
	}

	/**
	 * Check if another node is in this node's ancestry, the current node will return true as
	 * being in its own ancestry
	 *
	 * @param anotherNode
	 * 		Node to check for in the current nodes ancestry
	 * @return true/false if other node is in the ancestry
	 */
	public boolean hasNodeInItsAncestry(GTreeTableNode anotherNode) {
		if (anotherNode == null) {
			return false;
		}

		for (GTreeTableNode cur = this; cur != null; cur = cur.getParent()) {
			if (anotherNode == cur) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Check if this node has any visible children
	 *
	 * @return true/false if any children are visible
	 */
	public boolean hasVisibleChildren() {
		return (children != null) && children.stream().anyMatch(c -> c.visible);
	}

	/**
	 * Insert a new node into the children of this node
	 *
	 * @param newChild
	 * 		New child to insert
	 * @param childIndex
	 * 		Index to insert child at
	 */
	public void insert(GTreeTableNode newChild, int childIndex) {
		if (hasNodeInItsAncestry(Objects.requireNonNull(newChild))) {
			throw new IllegalArgumentException(
				"New child is already an ancestor, and cycles are not permitted");
		}
		final GTreeTableNode oldParent = newChild.getParent();
		if (oldParent != null) {
			oldParent.remove(newChild);
		}

		newChild.setParent(this);
		if (children == null) {
			children = Collections.synchronizedList(new ArrayList<>());
		}

		children.add(childIndex, newChild);
	}

	/**
	 * Check if node is expanded
	 *
	 * @return true/false if expanded
	 */
	public boolean isExpanded() {
		return expanded;
	}

	/**
	 * Check if node is leaf node
	 *
	 * @return true/false if leaf
	 */
	public boolean isLeaf() {
		return children.isEmpty();
	}

	/**
	 * Check if node is root node (i.e. it has no parent)
	 *
	 * @return true/false if root
	 */
	public boolean isRoot() {
		return getParent() == null;
	}

	/**
	 * @return
	 */
	public boolean isVisible() {
		return visible;
	}

	/**
	 * Remove child from list of children
	 *
	 * @param aChild
	 * 		Child to remove
	 */
	public void remove(GTreeTableNode aChild) {
		children.remove(aChild);
		aChild.setParent(null);
	}

	/**
	 * Remove child from list of children
	 *
	 * @param childIndex
	 * 		Index of child to remove
	 */
	public void remove(int childIndex) {
		final GTreeTableNode child = children.get(childIndex);
		children.remove(childIndex);
		child.setParent(null);
	}

	/**
	 * Change node expanded state
	 *
	 * @param expanded
	 * 		Expanded state
	 */
	public void setExpanded(boolean expanded) {
		this.expanded = expanded;
	}

	/**
	 * Set parent of node
	 *
	 * @param newParent
	 * 		Parent to set
	 */
	public void setParent(GTreeTableNode newParent) {
		parent = newParent;
	}

	/**
	 * Change node visibility state
	 *
	 * @param visible
	 * 		Node visibility
	 */
	public void setVisible(boolean visible) {
		this.visible = visible;
	}

	@Override
	public String toString() {
		return name == null ? "" : name;
	}
}
