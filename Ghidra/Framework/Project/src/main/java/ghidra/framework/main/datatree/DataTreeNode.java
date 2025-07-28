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

import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.GTreeSlowLoadingNode;
import ghidra.framework.data.LinkHandler;
import ghidra.framework.data.LinkHandler.LinkStatus;
import ghidra.framework.model.*;
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
	 * <li>Node comparison by name (see {@link DataTreeNode#compareNodeNames(String, String)}).</li>
	 * <li>Node type ordinal (e.g., ensures that a Folder-Link with the same name as a Folder 
	 * will be placed after the Folder.</li>
	 * </ol>
	 */
	enum NodeType {

		FOLDER(1), FOLDER_LINK(1), FILE(2), OTHER(3);

		int weight;

		NodeType(int weight) {
			this.weight = weight;
		}

		static NodeType getNodeType(GTreeNode node) {
			if (node instanceof DomainFolderNode) {
				return FOLDER;
			}
			if (node instanceof DomainFileNode fileNode) {
				return fileNode.isFolderLink() ? FOLDER_LINK : FILE;
			}
			return OTHER;
		}
	}

	/**
	 * Sort {@link Comparator} for use with sorting children and node comparison
	 */
	static final Comparator<GTreeNode> DATA_NODE_SORT_COMPARATOR = new DataNodeSortComparator();

	/**
	 *  Search {@link Comparator} for use by {@link #getChild(String, NodeType)} only
	 */
	private static final DataNodeSearchComparator DATA_NODE_SEARCH_COMPARATOR =
		new DataNodeSearchComparator();

	private volatile boolean isCut; // true if this node is marked as cut

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

	/**
	 * Get the project data instance to which this file or folder belongs.
	 * @return project data instance
	 */
	public abstract ProjectData getProjectData();

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
		int index = Collections.binarySearch(allChildren, newNode, DATA_NODE_SORT_COMPARATOR);
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
	@SuppressWarnings("unchecked")
	static GTreeNode getChild(List<GTreeNode> children, String name, NodeType type) {
		ChildSearchRecord childSearchRecord = new ChildSearchRecord(name, type);
		int index =
			Collections.binarySearch(children, childSearchRecord, DATA_NODE_SEARCH_COMPARATOR);
		return index >= 0 ? children.get(index) : null;
	}

	private record ChildSearchRecord(String name, NodeType type) {
	}

	@SuppressWarnings("rawtypes")
	private static class DataNodeSearchComparator implements Comparator {
		@Override
		public int compare(Object o1, Object o2) {

			GTreeNode node = (GTreeNode) o1;
			ChildSearchRecord childSearchRecord = (ChildSearchRecord) o2;

			NodeType type1 = NodeType.getNodeType(node);
			NodeType type2 = childSearchRecord.type;

			int comp = type1.weight - type2.weight;
			if (comp != 0) {
				return comp;
			}

			// NOTE: This name comparison is consistent with the sort order and
			// will provide a case-senstive name-match
			comp = compareNodeNames(node.getName(), childSearchRecord.name);
			if (comp == 0) {
				return type1.ordinal() - type2.ordinal();
			}
			return comp;
		}
	}

	private static class DataNodeSortComparator implements Comparator<GTreeNode> {
		@Override
		public int compare(GTreeNode o1, GTreeNode o2) {

			//
			// Goal is to have folders appear before files except for folder-links
			// which should be grouped with folders but come after a folder with 
			// the same name

			NodeType type1 = NodeType.getNodeType(o1);
			NodeType type2 = NodeType.getNodeType(o2);

			int comp = type1.weight - type2.weight;
			if (comp != 0) {
				return comp;
			}

			// NOTE: This name comparison is consistent with compareTo implementaions
			comp = compareNodeNames(o1.getName(), o2.getName());
			if (comp == 0) {
				return type1.ordinal() - type2.ordinal();
			}
			return comp;
		}
	}

	/**
	 * Name comparison to be used for DataTreeNode comparators and node comparison.
	 * @param n1 first name
	 * @param n2 second name
	 * @return comparison result consistent with {@link String#compareTo(String) n1.compareTo(n2)}
	 */
	static int compareNodeNames(String n1, String n2) {
		int c = n1.compareToIgnoreCase(n2);
		if (c == 0) {
			// disambiguate for deterministic sort
			c = n1.compareTo(n2);
		}
		return c;
	}

	/**
	 * Generate filtered child nodes for a DomainFolder
	 * @param domainFolder folder
	 * @param filter filter
	 * @param monitor load task monitor
	 * @return list of filtered chidren
	 * @throws CancelledException if load task is cancelled
	 */
	static List<GTreeNode> generateChildren(DomainFolder domainFolder, DomainFileFilter filter,
			TaskMonitor monitor) throws CancelledException {

		boolean hideFolderLinks = false;
		boolean hideBroken = false;
		boolean hideExternal = false;
		if (filter != null) {
			hideFolderLinks = filter.ignoreFolderLinks();
			hideBroken = filter.ignoreBrokenLinks();
			hideExternal = filter.ignoreExternalLinks();
		}

		List<GTreeNode> children = new ArrayList<>();
		if (domainFolder != null) {

			DomainFolder[] folders = domainFolder.getFolders();
			for (DomainFolder folder : folders) {
				monitor.checkCancelled();
				children.add(new DomainFolderNode(folder, filter));
			}

			DomainFile[] files = domainFolder.getFiles();
			for (DomainFile df : files) {
				monitor.checkCancelled();
				if (filter != null) {
					boolean isFolderLink = df.isLink() && df.getLinkInfo().isFolderLink();
					if (hideFolderLinks && isFolderLink) {
						continue;
					}
					if ((hideBroken || hideExternal) && df.isLink()) {
						LinkStatus linkStatus = LinkHandler.getLinkFileStatus(df, null);
						if (hideBroken && linkStatus == LinkStatus.BROKEN) {
							continue;
						}
						if (hideExternal && linkStatus == LinkStatus.EXTERNAL) {
							continue;
						}
					}
					if (!isFolderLink && !filter.accept(df)) {
						continue;
					}
				}
				children.add(new DomainFileNode(df, filter));
			}
		}
		Collections.sort(children, DATA_NODE_SORT_COMPARATOR);
		return children;
	}
}
