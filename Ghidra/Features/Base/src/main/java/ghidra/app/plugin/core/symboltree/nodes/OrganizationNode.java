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

import docking.widgets.tree.GTreeNode;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.datastruct.IntArray;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

/**
 * See {@link #computeChildren(List, int, GTreeNode, int, TaskMonitor)} for details on 
 * how this class works.
 */
public class OrganizationNode extends SymbolTreeNode {
	static final Comparator<GTreeNode> COMPARATOR = new OrganizationNodeComparator();

	private static Icon OPEN_FOLDER_GROUP_ICON =
		ResourceManager.loadImage("images/openFolderGroup.png");
	private static Icon CLOSED_FOLDER_GROUP_ICON =
		ResourceManager.loadImage("images/closedFolderGroup.png");

	private String baseName;

	/**
	 * You cannot instantiate this class directly, instead use the factory method below
	 * {@link #organize(List, int, TaskMonitor)}
	 * @throws CancelledException if the operation is cancelled
	 */
	private OrganizationNode(List<GTreeNode> list, int max, int parentLevel, TaskMonitor monitor)
			throws CancelledException {

		doSetChildren(computeChildren(list, max, this, parentLevel, monitor));

		GTreeNode child = getChild(0);
		baseName = child.getName().substring(0, getPrefixSizeForGrouping(getChildren(), 1) + 1);
	}

	/**
	 * A factory method for creating OrganizationNode objects. 
	 * See {@link #computeChildren(List, int, GTreeNode, int, TaskMonitor)}
	 *
	 * @param nodes the original list of child nodes to be subdivided.
	 * @param max The max number of child nodes per parent node at any node level.
	 * @param monitor the task monitor used to cancel this operation
	 * @return A list of nodes that is based upon the given list, but subdivided as needed.
	 * @throws CancelledException if the operation is cancelled
	 * @see #computeChildren(List, int, GTreeNode, int, TaskMonitor)
	 */
	public static List<GTreeNode> organize(List<GTreeNode> nodes, int max, TaskMonitor monitor)
			throws CancelledException {
		return organize(nodes, null, max, monitor);
	}

	private static List<GTreeNode> organize(List<GTreeNode> nodes, GTreeNode parent, int max,
			TaskMonitor monitor) throws CancelledException {
		return computeChildren(nodes, max, parent, 0, monitor);
	}

	/**
	 * Subdivide the given list of nodes such that the list or no new parent created will have
	 * more than <tt>maxNodes</tt> children.
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
	 * The algorithm prefers to group nodes that have the longest common prefixes.
	 * <p>
	 * <b>Note: the given data must be sorted for this method to work properly.</b>
	 *
	 * @param list list of child nodes of <tt>parent</tt> to breakup into smaller groups.
	 * @param maxNodes The max number of child nodes per parent node at any node level.
	 * @param parent The parent of the given <tt>children</tt>
	 * @param parentLevel node depth in the tree of <b>Organization</b> nodes.
	 * @return the given <tt>list</tt> sub-grouped as outlined above.
	 * @throws CancelledException if the operation is cancelled
	 */
	private static List<GTreeNode> computeChildren(List<GTreeNode> list, int maxNodes,
			GTreeNode parent, int parentLevel, TaskMonitor monitor) throws CancelledException {
		List<GTreeNode> children;
		if (list.size() <= maxNodes) {
			children = new ArrayList<>(list);
		}
		else {
			int characterOffset = getPrefixSizeForGrouping(list, maxNodes);

			characterOffset = Math.max(characterOffset, parentLevel + 1);

			children = new ArrayList<>();
			String prevStr = list.get(0).getName();
			int start = 0;
			int end = list.size();
			for (int i = 1; i < end; i++) {
				monitor.checkCanceled();
				String str = list.get(i).getName();
				if (stringsDiffer(prevStr, str, characterOffset)) {
					addNode(children, list, start, i - 1, maxNodes, characterOffset, monitor);
					start = i;
				}
				prevStr = str;
			}
			addNode(children, list, start, end - 1, maxNodes, characterOffset, monitor);
		}
		return children;
	}

	private static boolean stringsDiffer(String s1, String s2, int diffLevel) {
		if (s1.length() <= diffLevel || s2.length() <= diffLevel) {
			return true;
		}
		return s1.substring(0, diffLevel + 1)
				.compareToIgnoreCase(s2.substring(0, diffLevel + 1)) != 0;
	}

	private static void addNode(List<GTreeNode> children, List<GTreeNode> list, int start, int end,
			int max, int diffLevel, TaskMonitor monitor) throws CancelledException {
		if (end - start > 0) {
			children.add(
				new OrganizationNode(list.subList(start, end + 1), max, diffLevel, monitor));
		}
		else {
			GTreeNode node = list.get(start);
			children.add(node);
		}
	}

	/**
	 * Returns the longest prefix size such that the list of nodes can be grouped by
	 * those prefixes while not exceeding <tt>maxNodes</tt> number of children.
	 */
	private static int getPrefixSizeForGrouping(List<GTreeNode> list, int maxNodes) {
		IntArray prefixSizeCountBins = new IntArray();
		Iterator<GTreeNode> it = list.iterator();
		String previousNodeName = it.next().getName();
		prefixSizeCountBins.put(0, 1);
		while (it.hasNext()) {
			String currentNodeName = it.next().getName();
			int prefixSize = getCommonPrefixSize(previousNodeName, currentNodeName);
			prefixSizeCountBins.put(prefixSize, prefixSizeCountBins.get(prefixSize) + 1);
			previousNodeName = currentNodeName;
		}

		int binContentsTotal = 0;
		for (int i = 0; i <= prefixSizeCountBins.getLastNonEmptyIndex(); i++) {
			binContentsTotal += prefixSizeCountBins.get(i);
			if (binContentsTotal > maxNodes) {
				return Math.max(0, i - 1);  // we've crossed the max; take a step back
			}
		}

		return prefixSizeCountBins.getLastNonEmptyIndex(); // all are allowed; use max prefix size
	}

	private static int getCommonPrefixSize(String s1, String s2) {
		int maxCompareLength = Math.min(s1.length(), s2.length());
		for (int i = 0; i < maxCompareLength; i++) {
			if (Character.toUpperCase(s1.charAt(i)) != Character.toUpperCase(s2.charAt(i))) {
				return i;
			}
		}
		return maxCompareLength; // one string is a subset of the other (or the same)
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

	public boolean isModifiable() {
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
		return baseName + "...";
	}

	@Override
	public String getToolTip() {
		return getName();
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
	}

	@Override
	public GTreeNode findSymbolTreeNode(SymbolNode key, boolean loadChildren,
			TaskMonitor taskMonitor) {

		String symbolName = key.getName();
		if (!symbolName.startsWith(baseName)) {
			// the given name does not start with the base name; it cannot be in this node
			return null;
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

	@Override
	public List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException {
		// not used, children generated in constructor
		return null;
	}
}
