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

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.*;
import ghidra.app.plugin.core.datamgr.tree.ArchiveNode;
import ghidra.program.model.dtarchive.*;

/**
 * Action for saving a ProjectDataTypeArchive or a FileDataTypeArchive to a new storage location.
 */
public class SaveArchiveAsAction extends DockingAction {
	private DataTypeManagerPlugin plugin;

	public SaveArchiveAsAction(DataTypeManagerPlugin plugin) {
		super("Save As", plugin.getName());

		this.plugin = plugin;
		setPopupMenuData(new MenuData(new String[] { "Save Archive As..." }, "File"));
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
		if (selectionPaths == null || selectionPaths.length != 1) {
			return false;
		}

		GTreeNode node = (GTreeNode) selectionPaths[0].getLastPathComponent();
		if (node instanceof ArchiveNode) {
			return true;
		}

		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		GTree gtree = (GTree) context.getContextObject();
		ArchiveManager archiveManager = plugin.getArchiveManager();
		TreePath[] selectionPaths = gtree.getSelectionPaths();
		ArchiveNode node = (ArchiveNode) selectionPaths[0].getLastPathComponent();
		PersistentDataTypeArchive archive = node.getArchive();

		archiveManager.saveAs(archive);
		if (archive instanceof FileDataTypeArchive fa) {
			plugin.addRecentlyOpenedArchiveFile(fa.getFile());
		}
		else if (archive instanceof ProjectDataTypeArchive pa) {
			plugin.addRecentlyOpenedProjectArchive(pa);
		}
	}
}
