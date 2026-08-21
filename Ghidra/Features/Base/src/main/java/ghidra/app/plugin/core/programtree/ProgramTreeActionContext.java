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
package ghidra.app.plugin.core.programtree;

import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;

import ghidra.app.context.ProgramActionContext;
import ghidra.program.model.listing.Program;

/**
 * A context object for the {@link ProgramTreePlugin}.
 */
public class ProgramTreeActionContext extends ProgramActionContext {

	private ViewManagerComponentProvider provider;

	public ProgramTreeActionContext(ViewManagerComponentProvider provider, Program program,
			ViewPanel viewPanel, Object contextObject) {
		super(provider, program, viewPanel, contextObject);
		this.provider = provider;
	}

	public ProgramDnDTree getTree() {
		ViewProviderService viewProvider = provider.getCurrentViewProvider();
		if (!(viewProvider instanceof TreeViewProvider treeProvider)) {
			return null;
		}

		ProgramTreePanel treePanel = treeProvider.getViewComponent();
		return treePanel.getDnDTree();
	}

	public TreePath[] getSelectionPaths() {
		ProgramDnDTree tree = getTree();
		if (tree == null) {
			return null;
		}
		return tree.getSelectionPaths();
	}

	public ProgramNode getLeadSelectedNode() {
		ProgramNode node = getSingleSelectedNode();
		if (node != null) {
			return node; // only one node selected 
		}

		ProgramDnDTree tree = getTree();
		if (tree == null) {
			return null;
		}

		int n = tree.getSelectionCount();
		if (n == 0) {
			return null;
		}

		TreePath path = tree.getSelectionPath();
		if (n > 1) {
			path = tree.getLeadSelectionPath();
		}
		return (ProgramNode) path.getLastPathComponent();
	}

	public ProgramNode getSingleSelectedNode() {
		TreePath[] paths = getSelectionPaths();
		if (paths == null || paths.length != 1) {
			return null;
		}
		return (ProgramNode) paths[0].getLastPathComponent();
	}

	public boolean hasSingleNodeSelection() {
		ProgramDnDTree tree = getTree();
		if (tree == null) {
			return false;
		}
		return tree.getSelectionCount() == 1;
	}

	public boolean isOnlyRootNodeSelected() {
		ProgramDnDTree tree = getTree();
		if (tree == null) {
			return false;
		}
		TreePath[] paths = tree.getSelectionPaths();
		if (paths == null || paths.length != 1) {
			return false;
		}

		ProgramNode node = (ProgramNode) paths[0].getLastPathComponent();
		DefaultTreeModel treeModel = (DefaultTreeModel) tree.getModel();
		ProgramNode root = (ProgramNode) treeModel.getRoot();
		return node == root;
	}

	/**
	 * Returns true if the selected paths: 1) do not contain the root node and 2) for each folder,
	 * either all children are selected or no children are selected.
	 * 
	 * @return true if the criteria above are met
	 */
	public boolean hasFullNodeMultiSelection() {

		ProgramDnDTree tree = getTree();
		if (tree == null) {
			return false;
		}
		TreePath[] paths = tree.getSelectionPaths();
		if (paths == null) {
			return false;
		}

		DefaultTreeModel treeModel = (DefaultTreeModel) tree.getModel();
		ProgramNode root = (ProgramNode) treeModel.getRoot();
		for (TreePath path : paths) {
			ProgramNode node = (ProgramNode) path.getLastPathComponent();

			if (node == root) {
				return false;
			}

			if (hasMixedChildSelection(node, paths)) {
				return false;
			}
		}

		return true;
	}

	private boolean hasMixedChildSelection(ProgramNode node, TreePath[] selectedPaths) {

		if (!node.getAllowsChildren()) {
			return false;
		}

		int nchild = node.getChildCount();
		int numberSelected = 0;

		for (int i = 0; i < nchild; i++) {
			ProgramNode child = (ProgramNode) node.getChildAt(i);
			TreePath childPath = child.getTreePath();

			// see if childPath is in selected list
			for (TreePath element : selectedPaths) {
				if (childPath.equals(element)) {
					++numberSelected;
					break;
				}
			}
		}
		if (numberSelected == 0 || numberSelected == nchild) {
			return false;
		}
		return true;
	}
}
