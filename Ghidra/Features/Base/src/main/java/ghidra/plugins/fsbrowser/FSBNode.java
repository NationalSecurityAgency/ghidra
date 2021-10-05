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

import java.util.*;

import javax.swing.Icon;

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

	public FSBRootNode getFSBRootNode() {
		GTreeNode node = getParent();
		while (node != null && !(node instanceof FSBRootNode)) {
			node = node.getParent();
		}
		return (node instanceof FSBRootNode) ? (FSBRootNode) node : null;
	}

	protected abstract void updateFileAttributes(TaskMonitor monitor) throws CancelledException;

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
			FSBFileNode node = createNodeFromFile(child);
			if (node.isLeaf()) {
				node.updateFileAttributes(monitor);
			}
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
	public static FSBFileNode createNodeFromFile(GFile file) {
		return file.isDirectory() ? new FSBDirNode(file) : new FSBFileNode(file);
	}

}
