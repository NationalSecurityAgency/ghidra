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
package ghidra.app.plugin.core.datamgr.actions;

import javax.swing.SwingUtilities;
import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree;
import ghidra.util.exception.CancelledException;

public class CreateProjectArchiveAction extends DockingAction {
	private final DataTypeManagerPlugin plugin;

	public CreateProjectArchiveAction(DataTypeManagerPlugin plugin) {
		super("New Project Data Type Archive", plugin.getName());
		this.plugin = plugin;

		setMenuBarData(new MenuData(new String[] { "New Project Archive..." }, null, "Archive"));
		setDescription("Creates a new project data type archive in this data type manager.");
		setEnabled(true);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		try {
			Archive newArchive = plugin.getDataTypeManagerHandler().createProjectArchive();
			DataTypeArchiveGTree gTree = plugin.getProvider().getGTree();
			selectNewArchive(newArchive, gTree);
		}
		catch (CancelledException ce) {
			plugin.getTool().setStatusInfo("Create project archive was cancelled.");
		}
	}

	private void selectNewArchive(final Archive archive, final DataTypeArchiveGTree gTree) {
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				// start an edit on the new temporary node name
				GTreeNode node = gTree.getViewRoot();
				final GTreeNode child = node.getChild(archive.getName());
				if (child != null) {
					gTree.expandPath(node);
					TreePath path = child.getTreePath();
					gTree.scrollPathToVisible(path);
					gTree.setSelectedNode(child);
				}
			}
		});
	}
}
