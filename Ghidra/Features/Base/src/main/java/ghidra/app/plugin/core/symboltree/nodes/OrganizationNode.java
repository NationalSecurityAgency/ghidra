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
package ghidra.app.plugin.core.symboltree.nodes;

import java.awt.datatransfer.DataFlavor;
import java.util.*;

import javax.swing.Icon;

import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.tasks.GTreeCollapseAllTask;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

/**
 * These nodes are used to organize large lists of nodes into a hierachical structure based on 
 * the node names. See {@link #organize(List, int, TaskMonitor)} for details on 
 * how this class works.
 */
public class OrganizationNode extends SymbolTreeNode {
	public static final int MAX_SAME_NAME = 10;

	static final Comparator<GTreeNode> COMPARATOR = new OrganizationNodeComparator();

	private static Icon OPEN_FOLDER_GROUP_ICON =
		ResourceManager.loadImage("images/openFolderGroup.png");
	private static Icon CLOSED_FOLDER_GROUP_ICON =
		ResourceManager.loadImage("images/closedFolderGroup.png");

	private String baseName;
	private int totalCount;

	private MoreNode moreNode;

	private OrganizationNode(List<GTreeNode> list, int maxGroupSize, TaskMonitor monitor)
			throws CancelledException {
		totalCount = list.size();
		// organize children further if the list is too big
		List<GTreeNode> children = organize(list, maxGroupSize, monitor);

		// if all the entries have the same name and we have more than a handful, show only
		// a few and add a special "More" node
		if (children.size() > MAX_SAME_NAME && hasSameName(children)) {
			// they all have the same name, so just use that as this nodes name
			baseName = children.get(0).getName();

			children = new ArrayList<>(children.subList(0, MAX_SAME_NAME));
			moreNode = new MoreNode(baseName, totalCount - MAX_SAME_NAME);
			children.add(moreNode);
		}
		else {
			// name this node the prefix that all children nodes have in common
			baseName = getCommonPrefix(children);
		}
		doSetChildren(children);
	}

	/**
	 * Subdivide the given list of nodes recursively such that there are generally not more
	 * than maxGroupSize number of nodes at any level. Also, if there are ever many
	 * nodes of the same name, a group for them will be created and only a few will be shown with
	 * an "xx more..." node to indicate there are additional nodes that are not shown.
	 * <p>
	 * This algorithm uses the node names to group nodes based upon common prefixes.  For example,
	 * if a parent node contained more than <tt>maxNodes</tt> children then a possible grouping
	 * would be:
	 * <pre>
	 *  -abc...
	 *  --abca
	 *  --abcb
	 *  --abcc
	 *  -g
	 * </pre>
	 * where the nodes given contained:
	 * <pre>
	 *  abca
	 *  abcb
	 *  abcc
	 *  g
	 * </pre>
	 * <p>
	 * @param list list of child nodes of to breakup into smaller groups
	 * @param maxGroupSize the max number of nodes to allow before trying to organize into
	 * smaller groups
	 * @param monitor the TaskMonitor to be checked for canceling this operation
	 * @return the given <tt>list</tt> sub-grouped as outlined above
	 * @throws CancelledException if the operation is cancelled
	 */
	public static List<GTreeNode> organize(List<GTreeNode> list, int maxGroupSize,
			TaskMonitor monitor) throws CancelledException {

		Map<String, List<GTreeNode>> prefixMap = partition(list, maxGroupSize, monitor);

		// if they didn't partition, just add all given nodes as children
		if (prefixMap == null) {
			return new ArrayList<>(list);
		}

		// otherwise, the nodes have been partitioned into groups with a common prefix
		// loop through and create organization nodes for groups larger than one element
		List<GTreeNode> children = new ArrayList<>();
		for (String prefix : prefixMap.keySet()) {
			monitor.checkCanceled();

			List<GTreeNode> nodesSamePrefix = prefixMap.get(prefix);

			// all the nodes that don't have a common prefix get added directly
			if (prefix.isEmpty()) {
				children.addAll(nodesSamePrefix);
			}
			// groups with one entry, just add in the element directly
			else if (nodesSamePrefix.size() == 1) {
				children.addAll(nodesSamePrefix);
			}
			else {
				// add an organization node for each unique prefix
				children.add(new OrganizationNode(nodesSamePrefix, maxGroupSize, monitor));
			}
		}
		return children;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (getClass() != o.getClass()) {
			return false;
		}
		OrganizationNode node = (OrganizationNode) o;
		return baseName.equals(node.baseName);
	}

//==================================================================================================
// Interface Methods
//==================================================================================================

	@Override
	public boolean canCut() {
		return false;
	}

	@Override
	public boolean canPaste(List<GTreeNode> pastedNodes) {
		return false;
	}

	@Override
	public boolean isCut() {
		return false;
	}

	@Override
	public void setNodeCut(boolean isCut) {
		throw new UnsupportedOperationException("Cannot cut an organization node");
	}

	@Override
	public Icon getIcon(boolean expanded) {
		if (expanded) {
			return OPEN_FOLDER_GROUP_ICON;
		}
		return CLOSED_FOLDER_GROUP_ICON;
	}

	@Override
	public String getName() {
		return baseName;
	}

	@Override
	public String getToolTip() {
		return "Contains labels that start with \"" + getName() + "\" (" + totalCount + ")";
	}

	@Override
	public boolean isLeaf() {
		return false;
	}

	@Override
	public DataFlavor getNodeDataFlavor() {
		return null;
	}

	@Override
	public boolean supportsDataFlavors(DataFlavor[] dataFlavors) {
		return false;
	}

	@Override
	public Namespace getNamespace() {
		return null;
	}

	/**
	 * Inserts the given node into this organization node which is different than calling the
	 * {@link #addNode(GTreeNode)} method, which is used during construction.  This method knows
	 * how to recursively find the correct {@link OrganizationNode} node into which the given
	 * node should be inserted.
	 *
	 * @param newNode the node to insert.
	 */
	public void insertNode(GTreeNode newNode) {
		if (moreNode != null) {
			moreNode.incrementCount();
			return;
		}

		int index = Collections.binarySearch(getChildren(), newNode, getChildrenComparator());
		if (index >= 0) {
			// found a match
			GTreeNode matchingNode = getChild(index);
			if (matchingNode instanceof OrganizationNode) {
				OrganizationNode orgNode = (OrganizationNode) matchingNode;
				orgNode.insertNode(newNode);
				return;
			}
		}
		else {
			index = -index - 1;
		}

		addNode(index, newNode);
		checkForTooManyNodes();
	}

	private void checkForTooManyNodes() {
		if (getChildCount() > SymbolCategoryNode.MAX_NODES_BEFORE_CLOSING) {
			// If we have too many nodes, find the root category node and close it
			GTreeNode parent = getParent();
			while (parent != null) {
				if (parent instanceof SymbolCategoryNode) {
					GTree tree = getTree();
					// also clear the selection so that it doesn't reopen the category needlessly
					tree.clearSelectionPaths();
					tree.runTask(new GTreeCollapseAllTask(tree, parent));
					return;
				}
				parent = parent.getParent();
			}
		}
	}

	@Override
	public GTreeNode findSymbolTreeNode(SymbolNode key, boolean loadChildren,
			TaskMonitor taskMonitor) {

		String symbolName = key.getName();
		if (!symbolName.startsWith(baseName)) {
			// the given name does not start with the base name; it cannot be in this node
			return null;
		}

		// special case: all symbols in this group have the same name.
		if (moreNode != null) {
			if (!symbolName.equals(baseName)) {
				return null;
			}
			// The node either belongs to this node's children or it is represented by the
			// 'more' node
			for (GTreeNode child : children()) {
				SymbolTreeNode symbolTreeNode = (SymbolTreeNode) child;
				if (symbolTreeNode.getSymbol() == key.getSymbol()) {
					return child;
				}
			}

			return moreNode;
		}

		//
		// Note: The 'key' node used for searching will find us the parent node of the symbol
		//       that has changed if it is an org node (this is because the org node searches
		//       using the old name).  So, org nodes are different than normal nodes in that
		//       the old name will find the right parent, but not the actual current node, as
		//       it has a new name.  
		//
		return super.findSymbolTreeNode(key, loadChildren, taskMonitor);
	}

	@Override
	public int compareTo(GTreeNode node) {
		if (!(node instanceof OrganizationNode)) {
			String nodeName = node.getName();
			if (nodeName.regionMatches(true, 0, baseName, 0, baseName.length())) {
				// Consider this node equal to the org node, as the symbol node will be a child
				// of this org node.  This allows us to quickly search for the parent of any
				// given symbol node.
				return 0;
			}
		}

		return super.compareTo(node);
	}

	@Override
	public Comparator<GTreeNode> getChildrenComparator() {
		return COMPARATOR;
	}

	// We are being tricky here. The findSymbolTreeNode above returns the 'more' node
	// if the searched node is one of the nodes not being shown, so then the removeNode gets
	// called with the 'more' node, which just means to decrement the count.
	@Override
	public void removeNode(GTreeNode node) {
		if (node == moreNode) {
			moreNode.decrementCount();
			if (!moreNode.isEmpty()) {
				return;
			}
			// The 'more' node is empty, just let it be removed
			moreNode = null;
		}
		super.removeNode(node);
		// if this org node is empty, just remove it
		if (getChildCount() == 0) {
			getParent().removeNode(this);
		}
	}

	@Override
	public List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException {
		// not used, children generated in constructor
		return null;
	}

	private String getCommonPrefix(List<GTreeNode> children) {
		int commonPrefixSize = getCommonPrefixSize(children);
		return children.get(0).getName().substring(0, commonPrefixSize);
	}

	/**
	 * This is the algorithm for partitioning a list of nodes into a hierarchical structure based
	 * on common prefixes 
	 * @param nodeList the list of nodes to be partitioned
	 * @param maxGroupSize the maximum number of nodes in a group before an organization is attempted
	 * @param monitor {@link TaskMonitor} so the operation can be cancelled
	 * @return a map of common prefixes to lists of nodes that have that common prefix. Returns null
	 * if the size is less than maxGroupSize or the partition didn't reduce the number of nodes
	 * @throws CancelledException if the operation was cancelled
	 */
	private static Map<String, List<GTreeNode>> partition(List<GTreeNode> nodeList,
			int maxGroupSize, TaskMonitor monitor) throws CancelledException {

		// no need to partition of the number of nodes is small enough
		if (nodeList.size() <= maxGroupSize) {
			return null;
		}
		int commonPrefixSize = getCommonPrefixSize(nodeList);
		int uniquePrefixSize = commonPrefixSize + 1;
		Map<String, List<GTreeNode>> map = new LinkedHashMap<>();
		for (GTreeNode node : nodeList) {
			monitor.checkCanceled();
			String prefix = getPrefix(node, uniquePrefixSize);
			List<GTreeNode> list = map.computeIfAbsent(prefix, k -> new ArrayList<GTreeNode>());
			list.add(node);
		}
		if (map.size() == 1) {
			return null;
		}
		if (map.size() >= nodeList.size()) {
			return null;	// no reduction
		}

		return map;
	}

	private static String getPrefix(GTreeNode gTreeNode, int uniquePrefixSize) {
		String name = gTreeNode.getName();
		if (name.length() <= uniquePrefixSize) {
			return name;
		}
		return name.substring(0, uniquePrefixSize);
	}

	private static int getCommonPrefixSize(List<GTreeNode> list) {
		GTreeNode node = list.get(0);
		String first = node.getName();
		int inCommonSize = first.length();
		for (int i = 1; i < list.size(); i++) {
			String next = list.get(i).getName();
			inCommonSize = Math.min(inCommonSize, getCommonPrefixSize(first, next, inCommonSize));
		}
		return inCommonSize;
	}

	private static int getCommonPrefixSize(String base, String candidate, int max) {
		int maxCompareLength = Math.min(max, candidate.length());
		for (int i = 0; i < maxCompareLength; i++) {
			if (base.charAt(i) != candidate.charAt(i)) {
				return i;
			}
		}
		return maxCompareLength; // one string is a subset of the other (or the same)
	}

	private static boolean hasSameName(List<GTreeNode> list) {
		if (list.size() < 2) {
			return false;
		}
		String name = list.get(0).getName();
		for (GTreeNode node : list) {
			if (!name.equals(node.getName())) {
				return false;
			}
		}
		return true;

	}

	static class OrganizationNodeComparator implements Comparator<GTreeNode> {
		@Override
		public int compare(GTreeNode g1, GTreeNode g2) {
			if (!(g1 instanceof OrganizationNode) && g2 instanceof OrganizationNode) {
				// we want to use this org node's compareTo() method, so, flip the comparison 
				// and then negate the result so that the sorting is the same as if we had
				// not flipped the comparison.
				int result = -g2.compareTo(g1);
				return result;
			}

			int result = g1.compareTo(g2);
			return result;
		}
	}

}
