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

import java.io.File;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.plugin.core.datamgr.archive.ArchiveFileChooser;
import ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree;
import ghidra.util.Msg;

public class CreateArchiveAction extends DockingAction {
	private final DataTypeManagerPlugin plugin;

	public CreateArchiveAction(DataTypeManagerPlugin plugin) {
		super("New File Data Type Archive", plugin.getName());
		this.plugin = plugin;

		setMenuBarData(new MenuData(new String[] { "New File Archive..." }, null, "Archive"));

		setDescription("Creates a new data type archive in this data type manager.");
		setEnabled(true);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		DataTypeArchiveGTree gTree = plugin.getProvider().getGTree();
		ArchiveFileChooser fileChooser = new ArchiveFileChooser(gTree);
		fileChooser.setApproveButtonText("Create Archive");
		fileChooser.setApproveButtonToolTipText("Create Archive");
		fileChooser.setTitle("Create Archive");

		Msg.trace(this, "Showing filechooser to get new archive name...");
		File file = fileChooser.promptUserForFile("New_Archive");
		if (file == null) {
			Msg.trace(this, "No new archive filename chosen by user - not performing action");
			return;
		}

		Msg.trace(this, "User picked file: " + file.getAbsolutePath());

		if (file.exists()) {
			Msg.trace(this, "Need to overwrite--showing dialog");
			if (OptionDialog.showYesNoDialogWithNoAsDefaultButton(gTree,
				"Overwrite Existing File?",
				"Do you want to overwrite existing file\n" +
					file.getAbsolutePath()) != OptionDialog.OPTION_ONE) {
				Msg.trace(this, "\tdo not overwrite was chosen");
				return;
			}
			Msg.trace(this, "\toverwriting file!");
			file.delete();
		}
		Archive newArchive = plugin.getDataTypeManagerHandler().createArchive(file);
		if (newArchive != null) {
			Msg.trace(this, "Created new archive: " + newArchive.getName());
			selectNewArchive(newArchive, gTree);
		}
	}

	private void selectNewArchive(final Archive archive, final DataTypeArchiveGTree gTree) {
		GTreeNode rootNode = gTree.getModelRoot();
		gTree.setSelectedNodeByNamePath(new String[] { rootNode.getName(), archive.getName() });
	}
}
