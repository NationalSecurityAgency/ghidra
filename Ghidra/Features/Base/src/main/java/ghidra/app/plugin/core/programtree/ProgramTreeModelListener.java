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

import javax.swing.event.TreeModelEvent;
import javax.swing.event.TreeModelListener;
import javax.swing.tree.TreePath;

import ghidra.app.cmd.module.RenameCmd;
import ghidra.program.model.listing.Group;
import ghidra.program.model.listing.ProgramModule;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.StringKeyIndexer;

/**
 * Class that is a listener on the TreeModel.
 */
class ProgramTreeModelListener implements TreeModelListener {

	private ProgramDnDTree tree;

	ProgramTreeModelListener(ProgramDnDTree tree) {
		this.tree = tree;
	}

	/**
	 * Called when a node changes; update the Group name for the node being changed.
	 */
	@Override
	public void treeNodesChanged(TreeModelEvent e) {
		ProgramNode node = (ProgramNode) e.getTreePath().getLastPathComponent();

		int[] indices = e.getChildIndices();
		if (indices != null) {
			node = (ProgramNode) node.getChildAt(indices[0]);
		}

		String newName = node.getUserObject().toString().trim();
		if (newName.isEmpty()) {

			node.setUserObject(node.getName());
			Msg.showError(this, null, "Rename Failed", "Please enter a name.");

			// maintain the editing state
			SystemUtilities.runSwingLater(() -> tree.rename());
			return;
		}

		Group group = node.getGroup();
		String oldName = group.getName();
		if (newName.equals(oldName)) {
			return;    // name hasn't changed
		}

		RenameCmd cmd =
			new RenameCmd(tree.getTreeName(), (group instanceof ProgramModule), oldName, newName);
		if (tree.getTool().execute(cmd, tree.getProgram())) {

			StringKeyIndexer nameIndexer = tree.getNameIndexer();
			nameIndexer.remove(oldName);
			nameIndexer.put(newName);
		}
		else {
			node.setUserObject(node.getName());
			Msg.showError(this, tree, "Rename Failed", cmd.getStatusMsg());

			// maintain the editing state
			SystemUtilities.runSwingLater(() -> tree.rename());
		}
		tree.setEditable(false);
	}

	/**
	 * Method called when nodes are being inserted into the tree; update the treePath and the 
	 * group path fields in the ProgramNode object.
	 */
	@Override
	public void treeNodesInserted(TreeModelEvent e) {

		Object[] path = e.getPath();
		Object[] me = e.getChildren();

		// build the tree path for the node being inserted
		Object[] childPath = new Object[path.length + 1];
		System.arraycopy(path, 0, childPath, 0, path.length);
		childPath[childPath.length - 1] = me[0];

		ProgramNode node = (ProgramNode) me[0];

		node.setTreePath(new TreePath(childPath));

		// set up GroupPath
		tree.setGroupPath(node);
	}

	@Override
	public void treeNodesRemoved(TreeModelEvent e) {
		// don't care
	}

	@Override
	public void treeStructureChanged(TreeModelEvent e) {
		// don't care
	}
}
