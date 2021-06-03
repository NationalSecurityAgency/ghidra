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
import java.io.IOException;
import java.util.List;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import generic.jar.ResourceFile;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesProvider;
import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler;
import ghidra.app.plugin.core.datamgr.tree.ArchiveNode;
import ghidra.framework.Application;
import ghidra.framework.GenericRunInfo;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.util.Msg;
import ghidra.util.filechooser.ExtensionFileFilter;

public class OpenArchiveAction extends DockingAction {

	private final DataTypeManagerPlugin plugin;

	public OpenArchiveAction(DataTypeManagerPlugin plugin) {
		super("Open File Data Type Archive", plugin.getName());
		this.plugin = plugin;

		setMenuBarData(new MenuData(new String[] { "Open File Archive..." }, "Archive"));

		setDescription("Opens a data type archive in this data type manager.");
		setEnabled(true);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		DataTypesProvider provider = plugin.getProvider();
		GTree tree = provider.getGTree();
		GhidraFileChooser fileChooser = new GhidraFileChooser(tree);

		File archiveDirectory = getArchiveDirectory();
		fileChooser.setFileFilter(new ExtensionFileFilter(
			new String[] { FileDataTypeManager.EXTENSION }, "Ghidra Data Type Files"));
		fileChooser.setCurrentDirectory(archiveDirectory);
		fileChooser.setApproveButtonText("Open DataType Archive File");
		fileChooser.setApproveButtonToolTipText("Open DataType Archive File");

		DataTypeManagerHandler manager = plugin.getDataTypeManagerHandler();
		File file = fileChooser.getSelectedFile();
		if (file == null) {
			return;
		}
		if (!file.getName().endsWith(FileDataTypeManager.EXTENSION)) {
			file = new File(file.getParent(), file.getName() + "." + FileDataTypeManager.EXTENSION);
		}

		File lastOpenedDir = file.getParentFile();
		Preferences.setProperty(Preferences.LAST_OPENED_ARCHIVE_DIRECTORY,
			lastOpenedDir.getAbsolutePath());

		try {
			Archive archive = manager.openArchive(file, false, true);
			GTreeNode node = getNodeForArchive(tree, archive);
			if (node != null) {
				tree.setSelectedNode(node);
			}
		}
		catch (Throwable t) {
			DataTypeManagerHandler.handleArchiveFileException(plugin, new ResourceFile(file), t);
		}
	}

	private GTreeNode getNodeForArchive(GTree tree, Archive archive) {
		GTreeNode rootNode = tree.getModelRoot();
		List<GTreeNode> allChildren = rootNode.getChildren();
		for (GTreeNode node : allChildren) {
			ArchiveNode archiveNode = (ArchiveNode) node;
			if (archiveNode.getArchive() == archive) {
				return archiveNode;
			}
		}

		return null;
	}

	private File getArchiveDirectory() {
		String lastOpenedDirPath =
			Preferences.getProperty(Preferences.LAST_OPENED_ARCHIVE_DIRECTORY, null, true);
		if (lastOpenedDirPath != null) {
			return new File(lastOpenedDirPath);
		}

		// Start browsing in the installed type info directory if the user hasn't ever
		// specified an archive directory.
		String archiveDirPath = getTypeInfoDirPath();
		if (archiveDirPath == null) {
			// start the browsing in the user's preferred project directory if they have not opened
			// any other archives yet and we can't find the typeinfo directory.
			archiveDirPath = GenericRunInfo.getProjectsDirPath();
		}
		return new File(archiveDirPath);
	}

	private String getTypeInfoDirPath() {
		try {
			File dir = Application.getModuleDataSubDirectory("Base", "typeinfo").getFile(false);
			if (dir == null) {
				return null;
			}
			return dir.getAbsolutePath();
		}
		catch (IOException e) {
			Msg.debug(null, "typeinfo directory not found");
			return null;
		}
	}
}
