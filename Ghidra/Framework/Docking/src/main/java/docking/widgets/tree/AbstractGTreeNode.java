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
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.tree.TreePath;

import docking.widgets.tree.support.GTreeFilter;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Base class for GTNodes.  To create a simple GTNode where nodes will be added immediately
 * using the addNode() methods, simply extend this class and implement the following methods:

 * <ul>
 * 		<li>getName()</li>
 * 		<li>getToolTip()</li>
 * 		<li>isLeaf()</li>
 * 		<li>getIcon()</li>
 * </ul>
 *
 * <a name="usage"></a>Usage Notes:
 * <ul>
 * 	<li>The <b><tt>equals()</tt></b> method:  The <tt>GTree</tt> has the ability to remember expanded and
 *      selected states.  This will only work if the nodes in the saved state can be matched
 *      with the nodes in the <tt>GTree</tt>.  Java will do this by using the <tt>equals()</tt> method.
 *      There is a potential problem with this usage.  If nodes within the <tt>GTree</tt> get rebuilt (
 *      i.e., new nodes are created), then, by default, the expanded and selected state
 *      feature will be unable to find the correct nodes, since the default <tt>equals()</tt>
 *      method on <tt>GTreeNode</tt> performs a comparison based upon instances.  To fix this problem you
 *      must override the <tt>equals()</tt> method that can find the same logical nodes when
 *      the instances in memory have changed; typically this is done by overriding <tt>equals()</tt>
 *       to compare by node name.
 *      <p><br>
 *      <p>
 *      The <tt>GTreeNode</tt> has already overridden {@link #hashCode()} so that the node name is
 *       used to generate the correct value.  If you override the {@link #equals(Object)} method,
 *      <b>and you do not compare only by {@link #getName()}, then you must also override the
 *      {@link #hashCode()} method to generate a value based upon the same algorithm used by the
 *       new <tt>equals()</tt> method.</b>
 *      <p><br>
 *      <p>
 *      As a rule of thumb, unless you want to allow multiple nodes under one parent with the
 *      same name, then it is a swell idea to override the <tt>equals()</tt> method to compare on
 *      {@link #getName()}, as outlined above.
 *   </li>
 * </ul>
 */
public abstract class AbstractGTreeNode extends CoreGTreeNode {

	private AtomicBoolean isFiltering = new AtomicBoolean();

	/**
	 * This will be called when it is time to load children.  Some subclasses may not use this
	 * method, but may instead have children externally added.
	 */
	protected void loadChildren() {
		// I don't use this...subclasses might
	}

	@Override
	public void addNode(GTreeNode node) {
		addNode(-1, node);
	}

	@Override
	public void addNode(int index, GTreeNode node) {
		doAddNode(index, node);
		GTreeFilter filter = getFilter();
		if (filter != null) {
			GTree tree = getTree();
			tree.scheduleFilterTask(this);
		}

	}

	@Override
	public int compareTo(GTreeNode node) {
		return getName().compareToIgnoreCase(node.getName());
	}

	@Override
	public List<GTreeNode> getAllChildren() {
//		TODO this seemed like an unnecessary and inconsistent optimization, as
//		     the loadChildren() call will not perform excess work when called repeatedly, even
//		     if the children are empty (i.e., isLeaf()); remove after a bit
//		if (isLeaf()) {
//			return Collections.emptyList();
//		}
		loadChildren();
		return doGetAllChildren();
	}

	@Override
	public List<GTreeNode> getChildren() {
//		TODO this seemed like an unnecessary and inconsistent optimization, as
//	     	 the loadChildren() call will not perform excess work when called repeatedly, even
//	     	 if the children are empty (i.e., isLeaf()); remove after a bit
//		if (isLeaf()) {
//			return Collections.emptyList();
//		}
		loadChildren();
		return doGetActiveChildren();
	}

	@Override
	public int getChildCount() {
		loadChildren();
		return doGetChildCount();
	}

	@Override
	public int getAllChildCount() {
		loadChildren();
		return doGetAllChildCount();
	}

	@Override
	public GTreeNode getChild(String name) {
		List<GTreeNode> children = getChildren();
		for (GTreeNode child : children) {
			if (child.getName().equals(name)) {
				return child;
			}
		}
		return null;
	}

	@Override
	public GTreeNode getChild(int index) {
		loadChildren();
		return doGetChild(index);
	}

	@Override
	public int getNodeCount() {
		List<GTreeNode> children = getChildren();
		int count = 1;
		for (GTreeNode child : children) {
			count += child.getNodeCount();
		}
		return count;
	}

	@Override
	public int getLeafCount() {
		if (isLeaf()) {
			return 1;
		}

		if (!isChildrenLoadedOrInProgress()) {
			return 0;
		}

		List<GTreeNode> children = getChildren();
		int count = 0;
		for (GTreeNode child : children) {
			count += child.getLeafCount();
		}
		return count;
	}

	@Override
	public int getIndexInParent() {
		GTreeNode myParent = getParent();
		if (myParent != null) {
			return myParent.getIndexOfChild(this);
		}
		return -1;
	}

	@Override
	public int getIndexOfChild(GTreeNode node) {
		loadChildren();
		return doGetIndexOfChild(node);
	}

	@Override
	public TreePath getTreePath() {
		return new TreePath(getPathToRoot(this, 0));
	}

	@Override
	public void removeAll() {
		if (!isChildrenLoadedOrInProgress()) {
			return;
		}
		List<GTreeNode> allChildren = getAllChildren();

		doSetChildren(null, true);
		for (GTreeNode gTreeNode : allChildren) {
			gTreeNode.dispose();
		}
	}

	@Override
	public void setChildren(List<GTreeNode> childList) {
		doSetChildren(childList, true);
		if (isFiltering.get()) {
			return;
		}
		GTreeFilter filter = getFilter();
		if (filter != null) {
			GTree tree = getTree();
			tree.scheduleFilterTask(this);
		}
	}

	@Override
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

	public static class AllPathsIterator implements Iterator<TreePath> {
		private TreePath ancestry;
		private TreePath nextPath;
		private Iterator<GTreeNode> childIt = null;
		private Iterator<TreePath> childPathIt = null;

		public AllPathsIterator(TreePath path) {
			ancestry = path;
			nextPath = path;
		}

		@Override
		public boolean hasNext() {
			return nextPath != null;
		}

		@Override
		public TreePath next() {
			TreePath n = nextPath;
			loadNext();
			return n;
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		protected void loadNext() {
			if (childIt == null) {
				Object obj = ancestry.getLastPathComponent();
				assert obj instanceof GTreeNode;
				childIt = ((GTreeNode) obj).iterator();
			}
			if (childPathIt == null || !childPathIt.hasNext()) {
				if (childIt.hasNext()) {
					childPathIt = new AllPathsIterator(ancestry.pathByAddingChild(childIt.next()));
				}
				else {
					childPathIt = null;
				}
			}
			if (childPathIt != null && childPathIt.hasNext()) {
				nextPath = childPathIt.next();
			}
			else {
				nextPath = null;
			}
		}
	}

	public Iterable<TreePath> allPaths() {
		return new AllPathsIterable(new TreePath(this));
	}

	@Override
	public Iterator<GTreeNode> iterator() {
		return getChildren().iterator();
	}

	@Override
	public void filter(GTreeFilter filter, TaskMonitor monitor, int min, int max)
			throws CancelledException {

		if (isFiltering.get()) {
			stopCurrentFilterAndRestart();
			return;
		}

		isFiltering.set(true);
		try {
			doFilter(filter, monitor, min, max);
		}
		finally {
			isFiltering.set(false);
		}
	}

	private void stopCurrentFilterAndRestart() {
		GTree tree = getTree();
		if (tree != null) {
			// assume that filtering will be done later when we are made be part of a tree
			tree.refilter();
		}
	}

	private void doFilter(GTreeFilter filter, TaskMonitor monitor, int min, int max)
			throws CancelledException {

		if (isLeaf()) {
			return;
		}

		List<GTreeNode> allChildren = getAllChildren();
		if (allChildren.size() == 0) {
			return;
		}

		List<GTreeNode> newChildren = allChildren;
		try {
			setInProgress();
			List<GTreeNode> filteredChildren = new ArrayList<GTreeNode>();
			monitor.setProgress(min);
			int progressChunkSize = (max - min) / (allChildren.size());
			int childMin = min;
			for (GTreeNode child : allChildren) {
				monitor.checkCanceled();
				child.filter(filter, monitor, childMin, childMin + progressChunkSize);
				if (filter.acceptsNode(child) || child.getChildCount() > 0) {
					filteredChildren.add(child);
				}
				childMin += progressChunkSize;
			}

			newChildren = filteredChildren;
		}
		finally {
			// if an exception occurs, then the default children will be restored
			doSetActiveChildren(newChildren);
		}
		monitor.setProgress(max);
	}

	@Override
	public void clearFilter() {
		if (isLeaf()) {
			return;
		}

		if (!isChildrenLoaded()) {
			return;
		}

		List<GTreeNode> allChildren = getAllChildren();
		if (allChildren.size() == 0) {
			return;
		}
		setInProgress();
		for (GTreeNode child : allChildren) {
			child.clearFilter();
		}
		doResetActiveChildren();
	}

	@Override
	public boolean isFilteredOut() {
		if (getParent() == null) {
			return false;
		}
		return getIndexInParent() < 0;
	}

	@Override
	public void valueChanged(Object newValue) {
		// Overridden in subclasses
	}

	@Override
	public boolean isEditable() {
		return false;
	}

	@Override
	/**
	 * The hashCode() method has been overridden so that it will work in the hashtables inside of JTree.
	 * This assumes that if the .equals method is overridden, then the names will match which will
	 * make this hashCode implementation valid.  If for some reason .equals is overriden such that
	 * two node may be equal even if their names don't match, then the hashCode method must also be
	 * overridden.
	 *
	 * @see <a href="#usage">GTreeNode Usage</a>
	 */
	public int hashCode() {
		return getName().hashCode();
	}

	@Override
	public GTreeRootNode getRoot() {
		GTreeNode myParent = getParent();
		if (myParent == null) {
			if (this instanceof GTreeRootNode) {
				return (GTreeRootNode) this;
			}
			throw new AssertException(
				"Found a root node that is not an instance of GTreeRootNode--stop it!");
		}
		return myParent.getRoot();
	}

	@Override
	public String toString() {
		return getName();
	}

	@Override
	public GTree getTree() {
		GTreeNode myParent = getParent();
		if (myParent != null) {
			return myParent.getTree();
		}
		if (this instanceof GTreeRootNode) {
			return ((GTreeRootNode) this).getGTree();
		}
		return null;
	}

	private GTreeNode[] getPathToRoot(GTreeNode node, int depth) {
		GTreeNode[] returnNodes;

		/* Check for null, in case someone passed in a null node, or
		   they passed in an element that isn't rooted at root. */
		if (node == null) {
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

	protected GTreeFilter getFilter() {
		GTree tree = getTree();
		if (tree != null) {
			return tree.getFilter();
		}
		return null;
	}

	private static class AllPathsIterable implements Iterable<TreePath> {
		private TreePath path;

		public AllPathsIterable(TreePath path) {
			this.path = path;
		}

		@Override
		public Iterator<TreePath> iterator() {
			return new AllPathsIterator(path);
		}
	}

}
