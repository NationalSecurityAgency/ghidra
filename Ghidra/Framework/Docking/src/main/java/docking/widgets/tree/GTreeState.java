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

import java.awt.Rectangle;
import java.util.*;

import javax.swing.JTree;
import javax.swing.tree.TreePath;

import util.CollectionUtils;

/**
 * A class to remember the current state of the tree, for things like expanded paths, 
 * selected paths and the view location.
 * 
 * <p>This class is used to restore state for uses so that updates to the tree do not cause the
 * user to lose their spot.   
 * 
 * <p>Issues:
 * <ul>
 * 	<li>If the number of expanded items is too large, then the tree will spend a large 
 *      amount of time restoring, thus we limit the size of the expanded paths</li>
 *  <li>If we have to trim the number of items we remember, we need to do so intelligently so
 *      that the user experience seems natural (for example, when trimming what to keep, 
 *      be sure to first keep what is visible to the user, versus expanded/selected items 
 *      that are scrolled off the top of the view.</li>
 * </ul>
 */
public class GTreeState {

	/**
	 * A super arbitrary number to limit how many expanded paths and selected paths we try 
	 * to restore.   We reason that some number of items is not worth restoring--would the user
	 * be able to make use of 1,000,000 items selected.    
	 */
	private static final int MAX_ITEM_COUNT = 50; // 50 seems more than sufficient for now

	private List<TreePath> expandedPaths;
	private List<TreePath> selectionPaths;
	private LinkedHashSet<TreePath> viewPaths;

	private GTree tree;

	public GTreeState(GTree tree) {
		this(tree, tree.getViewRoot());
	}

	public GTreeState(GTree tree, GTreeNode node) {
		this.tree = tree;
		expandedPaths = tree.getExpandedPaths(node);
		selectionPaths = getSelectionPaths(node);
		viewPaths = getSomeViewPaths();

		adjustPathsForSizeConstraint();
	}

	private void adjustPathsForSizeConstraint() {

		doAdjustPathsForSizeConstraint();
	}

	private void doAdjustPathsForSizeConstraint() {

		int maxSize = getMaxItemCount();
		int combinedSize = selectionPaths.size() + expandedPaths.size();
		if (combinedSize < maxSize) {
			return; // nothing to do
		}

		//
		// Once we have too many items to deal with, what should be done?  We could:
		// 1) trim the items to the max size, preferring those that are in the view, grabbing
		//    surrounding paths as will fit		
		// 2) keep just the items in the view, limited to the max size
		// 3) pick a single item to select that is in the view
		//
		// The benefit of the last approach is that it will be easier to see that not all
		// of your state was restored.  The benefit of the other approaches is that items the 
		// user was viewing will probably be restored, since we are going to restore more 
		// items than will fit in the view.  So, do we err on the side of showing the user that
		// there were to many items, at the expense of jarring their view when the tree is 
		// updated? Or, do we somewhat hide from the user the fact that we could not restore
		// all of their view? 
		//
		// We've decided for now that the max limit is probably only exceeded in one of a few
		// cases, such as:
		// -the user has performed a s 'select all' on the tree nodes
		// -the user has expanded the entire tree
		//
		// In these cases, the user most likely cannot make use of the entire tree and will those
		// probably not miss any functionality if we do not restore all selected and expanded 
		// items.
		// 

		LinkedHashSet<TreePath> limitedViewPaths = getViewPaths(maxSize);

		expandedPaths = new ArrayList<>(limitedViewPaths);

		if (selectionPaths.size() > maxSize) {
			// too many; restrict to the view
			selectionPaths.retainAll(limitedViewPaths);
			return;
		}

		// 
		// Special case: the user has selected one or a few items--we should keep those, 
		// regardless of whether they are in the view.  Just add these to the list of expanded
		// paths so they get expanded.
		// 
		expandedPaths.addAll(selectionPaths);
	}

	/*testing*/ int getMaxItemCount() {
		return MAX_ITEM_COUNT;
	}

	public List<TreePath> getExpandedPaths() {
		return Collections.unmodifiableList(expandedPaths);
	}

	public List<TreePath> getSelectedPaths() {
		return Collections.unmodifiableList(selectionPaths);
	}

	/**
	 * Returns the top few paths that are visible in the view.
	 * @return the top few paths that are visible in the view.
	 */
	public TreePath[] getViewPaths() {
		TreePath[] arrrr = viewPaths.toArray(new TreePath[viewPaths.size()]);
		return arrrr;
	}

	public void updateStateForMovedNodes() {
		for (int i = 0; i < expandedPaths.size(); i++) {
			expandedPaths.set(i, updatePathForMovedNode(expandedPaths.get(i)));
		}
		for (int i = 0; i < selectionPaths.size(); i++) {
			selectionPaths.set(i, updatePathForMovedNode(selectionPaths.get(i)));
		}
	}

	public boolean isEmpty() {
		return selectionPaths.isEmpty() && expandedPaths.isEmpty();
	}

	private TreePath updatePathForMovedNode(TreePath path) {
		GTreeNode node = (GTreeNode) path.getLastPathComponent();
		return node.getTreePath();
	}

	private List<TreePath> getSelectionPaths(GTreeNode node) {
		TreePath[] allSelectionPaths = tree.getSelectionPaths();
		if (node == tree.getViewRoot()) {
			return CollectionUtils.asList(allSelectionPaths);
		}
		if (allSelectionPaths == null) {
			return Collections.emptyList();
		}
		TreePath nodeTreePath = node.getTreePath();
		List<TreePath> pathList = new ArrayList<>();
		for (TreePath path : allSelectionPaths) {
			if (nodeTreePath.isDescendant(path)) {
				pathList.add(nodeTreePath);
			}
		}
		return pathList;
	}

	private LinkedHashSet<TreePath> getSomeViewPaths() {

		int arbitrarySize = 5; // grab a few paths in case some are removed
		return getViewPaths(arbitrarySize);
	}

	private LinkedHashSet<TreePath> getViewPaths(int limit) {

		Rectangle r = tree.getViewRect();
		JTree jTree = tree.getJTree();
		int top = jTree.getClosestRowForLocation(r.x, r.y);
		int bottom = jTree.getClosestRowForLocation(r.x, r.y + r.height);

		// JTree Note: the getClosestRowForLocation() call will return the row that is 
		//             closest to the point *and* that is not clipped.   So, when we get the 
		//             top and bottom values, the user can see more items at the edges past the
		//             top and bottom.   Lets compensate by adding 1 to both values so that the
		//             rows in the view contains all that the user can see.
		top -= 1;
		bottom += 1;

		//
		// 				Unusual Code Alert!
		//
		// Due to how the JTree scrolls, the best path to save is the bottom-most path.  When
		// you ask the tree to scroll to a path, it will only scroll until that path is just
		// in the view, which is at the bottom.  By saving the bottom-most, even if we don't 
		// save all of the view paths, the view will often appear unchanged, since by putting
		// the bottom path in the view, those paths above it may still be visible.
		//
		int end = bottom - limit;
		end = Math.max(end, top); // constrain 'end' when the limit is larger than the view size

		LinkedHashSet<TreePath> result = new LinkedHashSet<>();
		for (int i = bottom; i > end; i--) {
			TreePath path = jTree.getPathForRow(i);
			if (path == null) {
				// the top or bottom is out-of-range (can happen due to how we fudged the
				// 'top' and 'bottom' above)
				continue;
			}

			result.add(path);
		}
		return result;
	}

	@Override
	public String toString() {
		return "GTreeState[Selection: " + getPaths(selectionPaths) + ", Expansion: " +
			getPaths(expandedPaths) + "]";
	}

	private String getPaths(List<TreePath> paths) {
		StringBuffer buffer = new StringBuffer();
		for (TreePath treePath : paths) {
			buffer.append(treePath);
		}
		return buffer.toString();
	}
}
