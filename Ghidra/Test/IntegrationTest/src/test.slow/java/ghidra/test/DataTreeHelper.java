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
package ghidra.test;

import java.util.ArrayList;
import java.util.List;

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.test.AbstractDockingTest;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import generic.test.AbstractGTest;
import generic.test.AbstractGuiTest;
import ghidra.framework.main.datatable.ProjectDataContext;
import ghidra.framework.main.datatree.*;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.store.FileSystem;

/**
 * This class provides some convenience methods for interacting with a {@link DataTree}.
 */
public class DataTreeHelper {

	private boolean isFrontEndTree;
	private DataTree tree;
	private DomainFolderRootNode rootNode;

	public DataTreeHelper(DataTree tree, boolean isFrontEndTree) {
		this.tree = tree;
		this.isFrontEndTree = isFrontEndTree;
		rootNode = (DomainFolderRootNode) tree.getViewRoot();
	}

	public void waitForTree() {
		AbstractDockingTest.waitForTree(tree);
	}

	public DomainFolder getRootFolder() {
		return rootNode.getDomainFolder();
	}

	public GTree getTree() {
		return tree;
	}

	public GTreeNode getRootNode() {
		return tree.getModelRoot();
	}

	private GTreeNode getDataTreeNodeByPath(String path) {
		int len = path.length();
		if (len == 0 || path.charAt(0) != FileSystem.SEPARATOR_CHAR) {
			throw new IllegalArgumentException(
				"Absolute path must begin with '" + FileSystem.SEPARATOR_CHAR + "'");
		}

		GTreeNode node = rootNode;
		String[] split = path.split(FileSystem.SEPARATOR);
		if (split.length == 0) {
			return node;
		}

		for (int i = 1; i < split.length; i++) {
			GTreeNode child = getChild(node, split[i]);
			if (child == null) {
				return null;
			}
			node = child;
		}
		return node;
	}

	private GTreeNode getChild(GTreeNode parent, String name) {
		return AbstractGTest.waitForValue(() -> parent.getChild(name));
	}

	public GTreeNode waitForTreeNode(String name) {
		return name.startsWith(FileSystem.SEPARATOR) ? getDataTreeNodeByPath(name)
				: getChild(rootNode, name);
	}

	public DomainFileNode waitForFileNode(String name) {
		return (DomainFileNode) waitForTreeNode(name);
	}

	public DomainFolderNode waitForFolderNode(String name) {
		return (DomainFolderNode) waitForTreeNode(name);
	}

	public void clearTreeSelection() {
		AbstractGuiTest.runSwing(() -> tree.clearSelection());
	}

	public void setTreeSelection(final TreePath[] paths) throws Exception {
		tree.setSelectionPaths(paths);
		waitForTree();
	}

	public void selectNodes(GTreeNode... nodes) {
		tree.setSelectedNodes(nodes);
		waitForTree();
	}

	public void expandNode(GTreeNode node) {
		tree.expandPath(node);
		waitForTree();
	}

	public ActionContext getDomainFileActionContext(GTreeNode... nodes) {

		List<DomainFile> fileList = new ArrayList<>();
		List<DomainFolder> folderList = new ArrayList<>();
		TreePath[] treePaths = new TreePath[nodes.length];
		for (int i = 0; i < nodes.length; i++) {
			GTreeNode node = nodes[i];
			treePaths[i] = node.getTreePath();
			if (node instanceof DomainFileNode) {
				fileList.add(((DomainFileNode) node).getDomainFile());
			}
			else if (node instanceof DomainFolderNode) {
				folderList.add(((DomainFolderNode) node).getDomainFolder());
			}
		}

		if (isFrontEndTree) {
			boolean isActiveProject = tree.getName().equals("Data Tree");
			return new FrontEndProjectTreeContext(null, rootNode.getDomainFolder().getProjectData(),
				treePaths, folderList, fileList, tree, isActiveProject);
		}

		return new ProjectDataContext(null, rootNode.getDomainFolder().getProjectData(), nodes[0],
			folderList, fileList, tree, true);

	}

}
