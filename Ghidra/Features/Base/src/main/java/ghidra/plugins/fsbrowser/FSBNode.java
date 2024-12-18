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
package ghidra.plugins.fsbrowser;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import javax.swing.Icon;
import javax.swing.tree.TreePath;

import org.apache.commons.io.FilenameUtils;

import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.GTreeSlowLoadingNode;
import ghidra.formats.gfilesystem.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Base class for all filesystem browser gtree nodes.
 */
public abstract class FSBNode extends GTreeSlowLoadingNode {

	/**
	 * Returns the {@link FSRL} of the filesystem object that this node represents.
	 * <p>
	 * The root of filesystems will return a {@link FSRLRoot}.
	 *
	 * @return {@link FSRL} of the filesystem object.
	 */
	public abstract FSRL getFSRL();

	public void init(TaskMonitor monitor) throws CancelledException {
		// nothing
	}

	public GFile getGFile() {
		return null;
	}

	@Override
	public String getToolTip() {
		return getName();
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return null;
	}

	@Override
	public String getName() {
		return getFSRL().getName();
	}

	/**
	 * Returns the extension of this node's name, or "" if none
	 * 
	 * @return extension of this node's name, or "" if none
	 */
	public String getFileExtension() {
		return FilenameUtils.getExtension(getName());
	}

	public FSBRootNode getFSBRootNode() {
		GTreeNode node = getParent();
		while (node != null) {
			if (node instanceof FSBRootNode rootNode) {
				return rootNode;
			}
			node = node.getParent();
		}
		return null;
	}

	public abstract void refreshNode(TaskMonitor monitor) throws CancelledException;

	protected void loadChildrenIfNeeded(TaskMonitor monitor) throws CancelledException {
		if (!isLeaf() && !isLoaded()) {
			doSetChildren(generateChildren(monitor));
		}
	}

	private static Map<FSRL, GFile> getListing(GFile f) {
		try {
			List<GFile> listing = f.getListing();
			return listing.stream().collect(Collectors.toMap(f1 -> f1.getFSRL(), f1 -> f1));
		}
		catch (IOException e) {
			return Map.of();
		}
	}

	protected void refreshChildren(TaskMonitor monitor)
			throws CancelledException {
		GFile f = getGFile();
		if (f == null || !isLoaded() || isLeaf()) {
			return;
		}
		Map<FSRL, GFile> currentFiles = getListing(f);

		int changeCount = 0;
		boolean cryptoCausesFullRefresh = true;
		boolean flagFSBRootNodeWithCryptoUpdate = false;

		List<GTreeNode> newNodes = new ArrayList<>();
		List<GTreeNode> currentChildren = new ArrayList<>(children());
		for (GTreeNode oldNode : currentChildren) {
			monitor.increment();
			if (oldNode instanceof FSBNode fsbNode) {
				GFile currentFile = currentFiles.get(fsbNode.getFSRL());
				if (fileMatchesNode(currentFile, fsbNode)) {
					boolean checkPwUpdate = cryptoCausesFullRefresh &&
						fsbNode instanceof FSBFileNode fileNode && fileNode.hasMissingPassword();

					fsbNode.refreshNode(monitor);

					flagFSBRootNodeWithCryptoUpdate |= checkPwUpdate &&
						fsbNode instanceof FSBFileNode fileNode && !fileNode.hasMissingPassword();

					newNodes.add(fsbNode); // port old node over to new list
					currentFiles.remove(fsbNode.getFSRL());
				}
				else {
					// by not adding to newNodes, the old node will disappear
					changeCount++;
				}
			}
		}

		// add any remaining GFiles as new nodes
		changeCount += currentFiles.size();
		currentFiles.values()
				.stream()
				.map(f1 -> createNodeFromFile(f1, monitor))
				.forEach(newNodes::add);

		Collections.sort(newNodes, FSBNODE_NAME_TYPE_COMPARATOR);

		FSBRootNode fsbRootNode;
		if (flagFSBRootNodeWithCryptoUpdate && (fsbRootNode = getFSBRootNode()) != null) {
			fsbRootNode.setCryptoStatusUpdated(true);
		}

		if (changeCount > 0) {
			setChildren(newNodes);
		}
	}

	private boolean fileMatchesNode(GFile f, FSBNode node) {
		if (f == null) {
			return false;
		}
		if (node instanceof FSBFileNode fileNode &&
			f.isDirectory() != (fileNode instanceof FSBDirNode)) {
			return false;
		}
		return true;

	}

	protected FSBFileNode findMatchingNode(GFile f, TaskMonitor monitor) throws CancelledException {
		loadChildrenIfNeeded(monitor);
		for (GTreeNode treeNode : children()) {
			if (treeNode instanceof FSBFileNode fileNode) {
				if (fileNode.file.equals(f)) {
					return fileNode;
				}
			}
		}
		return null;
	}

	public String getFormattedTreePath() {
		TreePath treePath = getTreePath();
		StringBuilder path = new StringBuilder();
		for (Object pathElement : treePath.getPath()) {
			if (pathElement instanceof FSBNode node) {
				if (!path.isEmpty()) {
					path.append("/");
				}
				if (node instanceof FSBRootNode rootNode) {
					FSRL fsContainer = rootNode.getContainer();
					if (fsContainer != null) {
						path.append(fsContainer.getName());
					}
				}
				else {
					path.append(node.getFSRL().getName());
				}
			}
		}
		return path.toString();
	}

	abstract public FSRL getLoadableFSRL();

	/**
	 * Returns the {@link FSBRootNode} that represents the root of the file system that
	 * contains the specified file node.
	 * 
	 * @param node GTree node that represents a file.
	 * @return FSBRootNode that represents the file system holding the file.
	 */
	public static FSBRootNode findContainingFileSystemFSBRootNode(FSBNode node) {
		GTreeNode parent = node.getParent();
		while (parent != null && !(parent instanceof FSBRootNode)) {
			parent = parent.getParent();
		}
		return (parent instanceof FSBRootNode) ? (FSBRootNode) parent : null;
	}

	/**
	 * Helper method to convert {@link GFile} objects to FSBNode objects.
	 *
	 * @param files {@link List} of {@link GFile} objects to convert
	 * @param monitor {@link TaskMonitor}
	 * @return {@link List} of {@link FSBNode} instances (return typed as a GTreeNode list),
	 * specific to each GFile instance's type.
	 */
	public static List<GTreeNode> createNodesFromFileList(List<GFile> files, TaskMonitor monitor) {
		files = new ArrayList<>(files);
		Collections.sort(files, FSUtilities.GFILE_NAME_TYPE_COMPARATOR);

		List<GTreeNode> nodes = new ArrayList<>(files.size());
		for (GFile child : files) {
			FSBFileNode node = createNodeFromFile(child, monitor);
			nodes.add(node);
		}
		return nodes;
	}

	/**
	 * Helper method to convert a single {@link GFile} object into a FSBNode object.
	 *
	 * @param file {@link GFile} to convert
	 * @return a new {@link FSBFileNode} with type specific to the GFile's type.
	 */
	public static FSBFileNode createNodeFromFile(GFile file, TaskMonitor monitor) {
		FSBFileNode result = file.isDirectory() ? new FSBDirNode(file) : new FSBFileNode(file);
		result.init(monitor);
		return result;
	}

	public static final Comparator<GTreeNode> FSBNODE_NAME_TYPE_COMPARATOR = (o1, o2) -> {
		if (!(o1 instanceof FSBNode node1) || !(o2 instanceof FSBNode node2)) {
			return 0;
		}
		GFile f1 = node1.getGFile();
		GFile f2 = node2.getGFile();
		int result = Boolean.compare(!f1.isDirectory(), !f2.isDirectory());
		if (result == 0) {
			String n1 = Objects.requireNonNullElse(f1.getName(), "");
			String n2 = Objects.requireNonNullElse(f2.getName(), "");
			result = n1.compareToIgnoreCase(n2);
		}
		return result;
	};

}
