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
package ghidra.framework.main.datatree;

import java.util.*;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.GTreeSlowLoadingNode;
import docking.widgets.tree.internal.InProgressGTreeNode;
import ghidra.framework.data.LinkHandler;
import ghidra.framework.data.LinkHandler.LinkStatus;
import ghidra.framework.model.*;
import ghidra.util.datastruct.AlphaNumericComparator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * {@link DataTreeNode} provides the base implementation for all node types contained within
 * a {@link DataTree}.
 */
public abstract class DataTreeNode extends GTreeSlowLoadingNode implements Cuttable {

	/**
	 * {@link NodeType} is used to aid the sorting/comparison of data tree node.  The
	 * sort order is based upon the following comparisons in order of significance:
	 * <ol>
	 * <li>Node type weighting.  Folder and Folder-Links have equal weighting.</li>
	 * <li>Node comparison by name.</li>
	 * <li>Node type ordinal (e.g., ensures that a Folder-Link with the same name as a Folder 
	 * will be placed after the Folder.</li>
	 * </ol>
	 */
	enum NodeType {

		FOLDER(1),
		FOLDER_LINK(1),
		FILE(2);

		private int weight;

		NodeType(int weight) {
			this.weight = weight;
		}
	}

	static final Comparator<GTreeNode> DATA_NODE_COMPARATOR = new DataNodeSortComparator();

	private static boolean useNaturalSort = true;

	private volatile boolean isCut; // true if this node is marked as cut

	public static void setUseNaturalSort(boolean b) {
		useNaturalSort = b;
	}

	@Override
	public final void setIsCut(boolean isCut) {
		if (isCut != this.isCut) {
			this.isCut = isCut;
			fireNodeChanged();
		}
	}

	@Override
	public final boolean isCut() {
		return isCut;
	}

	protected abstract NodeType getNodeType();

	/**
	 * Get the project data instance to which this file or folder belongs.
	 * @return project data instance
	 */
	public abstract ProjectData getProjectData();

	/**
	 * {@return domain folder/file pathname within project}
	 */
	public abstract String getPathname();

	@Override
	public abstract int compareTo(GTreeNode node);

	@Override
	public abstract boolean equals(Object obj);

	@Override
	public abstract int hashCode();

	@Override
	public void addNode(GTreeNode newNode) {
		if (!isLoaded()) {
			return;
		}

		List<GTreeNode> allChildren = getChildren();
		int index = Collections.binarySearch(allChildren, newNode, DATA_NODE_COMPARATOR);
		if (index < 0) {
			index = -index - 1;
		}
		addNode(index, newNode);

		if (newNode instanceof DomainFolderNode) {
			// Refresh possible conflicting folder-link
			DomainFileNode folderLink =
				(DomainFileNode) getChild(newNode.getName(), NodeType.FOLDER_LINK);
			if (folderLink != null) {
				folderLink.refresh();
			}
		}
	}

	@Override
	public void removeNode(GTreeNode node) {
		if (!isLoaded()) {
			return;
		}
		// NOTE: Remove node is not implemented in a manner where we can remove by index
		// using a binary search.
		super.removeNode(node);

		if (node instanceof DomainFolderNode) {
			// Refresh possible conflicting folder-link resolved
			DomainFileNode folderLink =
				(DomainFileNode) getChild(node.getName(), NodeType.FOLDER_LINK);
			if (folderLink != null) {
				folderLink.refresh();
			}
		}
	}

// NOTE: The use of this method should be blocked since it does not properly handle duplicate child
// names within the same folder.
//	/**
//	 * Domain folders and files may have the same name within a parent.  This method should 
//	 * not be used.
//	 */
//	@Override
//	public final GTreeNode getChild(String name) {
//		throw new UnsupportedOperationException("DataTree node names may not be unique");
//	}

	/**
	 * Find a child using a binary-search approach.
	 * 
	 * @param name name of child to find
	 * @param type node type
	 * @return matching tree node or null if not found
	 */
	public abstract GTreeNode getChild(String name, NodeType type);

	/**
	 * Find a child using a binary-search approach vs. the default brute-force search.
	 * Note that two supported node types may have the same name, one being a {@link DomainFolderNode} 
	 * and the other being a {@link DomainFileNode}.  Folders are always placed before Files, 
	 * although such different node types with the same name are not adjacent.  For this reason
	 * a binary search cannot be used with a arbitrary predicate.
	 * 
	 * @param children children to be searched
	 * @param name name of child to find
	 * @param type node type
	 * @return matching tree node or null if not found
	 */
	static GTreeNode getChild(List<GTreeNode> children, String name, NodeType type) {

		SearchNode key = new SearchNode(name, type);
		int index = Collections.binarySearch(children, key, DATA_NODE_COMPARATOR);
		return index >= 0 ? children.get(index) : null;
	}

	/**
	 * Generate filtered child nodes for a DomainFolder
	 * @param domainFolder folder
	 * @param filter filter
	 * @param monitor load task monitor
	 * @return list of filtered children
	 * @throws CancelledException if load task is cancelled
	 */
	static List<GTreeNode> generateChildren(DomainFolder domainFolder, DomainFileFilter filter,
			TaskMonitor monitor) throws CancelledException {

		List<GTreeNode> children = new ArrayList<>();
		if (domainFolder == null) {
			return children;
		}

		DomainFolder[] folders = domainFolder.getFolders();
		for (DomainFolder folder : folders) {
			monitor.checkCancelled();
			children.add(new DomainFolderNode(folder, filter));
		}

		DomainFile[] files = domainFolder.getFiles();
		for (DomainFile df : files) {
			monitor.checkCancelled();
			if (skip(df, filter)) {
				continue;
			}
			children.add(new DomainFileNode(df, filter));
		}

		Collections.sort(children, DATA_NODE_COMPARATOR);
		return children;
	}

	private static boolean skip(DomainFile df, DomainFileFilter filter) {

		if (filter == null) {
			return false;
		}

		boolean hideFolderLinks = filter.ignoreFolderLinks();
		boolean hideBroken = filter.ignoreBrokenLinks();
		boolean hideExternal = filter.ignoreExternalLinks();

		boolean isFolderLink = df.isLink() && df.getLinkInfo().isFolderLink();
		if (hideFolderLinks && isFolderLink) {
			return true;
		}

		if ((hideBroken || hideExternal) && df.isLink()) {
			LinkStatus linkStatus = LinkHandler.getLinkFileStatus(df, null);
			if (hideBroken && linkStatus == LinkStatus.BROKEN) {
				return true;
			}
			if (hideExternal && linkStatus == LinkStatus.EXTERNAL) {
				return true;
			}
		}

		if (!isFolderLink && !filter.accept(df)) {
			return true;
		}

		return false;
	}

//=================================================================================================
// Inner Classes
//=================================================================================================	

	private static class DataNodeSortComparator implements Comparator<GTreeNode> {

		private static AlphaNumericComparator alphaNumericComparator =
			new AlphaNumericComparator(false);

		@Override
		public int compare(GTreeNode o1, GTreeNode o2) {

			if (o1 instanceof InProgressGTreeNode) {
				return -1; // loading
			}

			// We want folders appear before files except for folder-links which should be grouped 
			// with folders but come after a folder with the same name
			DataTreeNode dtn1 = (DataTreeNode) o1;
			DataTreeNode dtn2 = (DataTreeNode) o2;
			NodeType type1 = dtn1.getNodeType();
			NodeType type2 = dtn2.getNodeType();

			int result = type1.weight - type2.weight;
			if (result != 0) {
				return result;
			}

			String n1 = o1.getName();
			String n2 = o2.getName();
			result = compareNames(n1, n2);
			if (result == 0) {
				return type1.ordinal() - type2.ordinal();
			}
			return result;
		}

		private int compareNames(String n1, String n2) {
			if (useNaturalSort) {
				return alphaNumericComparator.compare(n1, n2);
			}

			int result = n1.compareToIgnoreCase(n2);
			if (result != 0) {
				return result;
			}
			return n1.compareTo(n2);
		}
	}

	/**
	 * A dummy search node used to find a child node by the given name and type.
	 */
	private static class SearchNode extends DataTreeNode {

		private String name;
		private NodeType nodeType;

		SearchNode(String name, NodeType nodeType) {
			this.name = name;
			this.nodeType = nodeType;
		}

		@Override
		public String getName() {
			return name;
		}

		@Override
		protected NodeType getNodeType() {
			return nodeType;
		}

		@Override
		public ProjectData getProjectData() {
			throw new UnsupportedOperationException();
		}

		@Override
		public String getPathname() {
			throw new UnsupportedOperationException();
		}

		@Override
		public int compareTo(GTreeNode node) {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean equals(Object obj) {
			throw new UnsupportedOperationException();
		}

		@Override
		public int hashCode() {
			throw new UnsupportedOperationException();
		}

		@Override
		public GTreeNode getChild(String childName, NodeType type) {
			throw new UnsupportedOperationException();
		}

		@Override
		public List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException {
			throw new UnsupportedOperationException();
		}

		@Override
		public Icon getIcon(boolean expanded) {
			throw new UnsupportedOperationException();
		}

		@Override
		public String getToolTip() {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean isLeaf() {
			throw new UnsupportedOperationException();
		}
	}

}
