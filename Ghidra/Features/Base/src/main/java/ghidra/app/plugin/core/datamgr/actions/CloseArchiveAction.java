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

import java.util.ArrayList;
import java.util.List;

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.plugin.core.datamgr.archive.ArchiveUtils;
import ghidra.app.plugin.core.datamgr.editor.DataTypeEditorManager;
import ghidra.app.plugin.core.datamgr.tree.*;

public class CloseArchiveAction extends DockingAction {

	private final DataTypeManagerPlugin plugin;

	public CloseArchiveAction(DataTypeManagerPlugin plugin) {
		super("Close Archive", plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(new MenuData(new String[] { "Close Archive" }, null, "File"));

		setDescription("Closes a data type archive and removes it from the tool "
			+ "(does not affect program file associations).");
		setEnabled(true);

	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		Object contextObject = context.getContextObject();
		GTree gtree = (GTree) contextObject;
		TreePath[] selectionPaths = gtree.getSelectionPaths();

		if (selectionPaths.length == 0) {
			return false;
		}

		for (TreePath path : selectionPaths) {
			GTreeNode node = (GTreeNode) path.getLastPathComponent();
			if (!(node instanceof FileArchiveNode) && !(node instanceof InvalidArchiveNode) &&
				!(node instanceof ProjectArchiveNode)) {
				return false;
			}
		}
		return true;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		GTree gtree = (GTree) context.getContextObject();
		TreePath[] selectionPaths = gtree.getSelectionPaths();
		DataTypeEditorManager editorManager = plugin.getEditorManager();
		List<Archive> archives = new ArrayList<Archive>();
		for (TreePath path : selectionPaths) {
			Object pathComponent = path.getLastPathComponent();
			if (pathComponent instanceof InvalidArchiveNode) {
				InvalidArchiveNode invalidArchiveNode = (InvalidArchiveNode) pathComponent;
				Archive archive = invalidArchiveNode.getArchive();
				archive.close();
				continue;
			}

			Archive archive = null;
			Object node = path.getLastPathComponent();
			if (node instanceof ArchiveNode) {
				ArchiveNode archiveNode = (ArchiveNode) node;
				archive = archiveNode.getArchive();
			}
			if (archive != null) {
				archives.add(archive);
				if (!editorManager.checkEditors(archive.getDataTypeManager(), true)) {
					return;
				}
			}
		}
		if (ArchiveUtils.canClose(archives, gtree)) {
			for (Archive archive : archives) {
				editorManager.dismissEditors(archive.getDataTypeManager());
				archive.close();
			}
		}
	}

}
