/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.archive.*;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateFileException;

import java.io.IOException;

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;

public class SaveAsAction extends DockingAction {
	private DataTypeManagerPlugin plugin;

	public SaveAsAction(DataTypeManagerPlugin plugin) {
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
		if ((node instanceof FileArchiveNode) || (node instanceof ProjectArchiveNode)) {
			return true;
		}

		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		GTree gtree = (GTree) context.getContextObject();

		TreePath[] selectionPaths = gtree.getSelectionPaths();
		ArchiveNode node = (ArchiveNode) selectionPaths[0].getLastPathComponent();
		Archive archive = node.getArchive();

		try {
			if (node instanceof FileArchiveNode) {
				FileArchive fa = (FileArchive) archive;
				ArchiveUtils.saveAs(gtree, fa);
				plugin.addRecentlyOpenedArchiveFile(fa.getFile());
			}
			else if (node instanceof ProjectArchiveNode) {
				ProjectArchive pa = (ProjectArchive) archive;
				pa.saveAs(gtree);
				plugin.addRecentlyOpenedProjectArchive(pa);
			}
		}
		catch (DuplicateFileException de) {
			Msg.showError(this, gtree, "Unable to Save File", "Archive already exists: " + archive);
		}
		catch (IOException ioe) {
			Msg.showError(this, gtree, "Unable to Save File",
				"Unexpected exception attempting to save archive: " + archive, ioe);
		}
	}
}
