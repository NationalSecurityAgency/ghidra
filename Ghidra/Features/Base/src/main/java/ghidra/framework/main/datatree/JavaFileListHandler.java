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
/**
 *
 */
package ghidra.framework.main.datatree;

import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.DropTargetDropEvent;
import java.io.File;
import java.util.List;

import docking.widgets.tree.GTreeNode;
import ghidra.app.services.FileImporterService;
import ghidra.app.util.FileOpenDataFlavorHandler;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.Swing;
import util.CollectionUtils;

/**
 * {@literal A drag-and-drop handler for trees that is specific to List<File>.} (see
 * {@link DataFlavor#javaFileListFlavor}).
 */
public final class JavaFileListHandler implements DataTreeFlavorHandler, FileOpenDataFlavorHandler {

	@Override
	public void handle(PluginTool tool, Object transferData, DropTargetDropEvent e, DataFlavor f) {

		FileImporterService importer = tool.getService(FileImporterService.class);
		if (importer == null) {
			Msg.showError(this, null, "Could Not Import", "Could not find Importer Service");
			return;
		}

		DomainFolder folder = tool.getProject().getProjectData().getRootFolder();
		doImport(importer, folder, transferData);
	}

	@Override
	public void handle(PluginTool tool, DataTree dataTree, GTreeNode destinationNode,
			Object transferData, int dropAction) {

		FileImporterService importer = tool.getService(FileImporterService.class);
		if (importer == null) {
			Msg.showError(this, dataTree, "Could Not Import", "Could not find Importer Service");
			return;
		}

		DomainFolder folder = getDomainFolder(destinationNode);
		doImport(importer, folder, transferData);
	}

	private void doImport(FileImporterService importer, DomainFolder folder, Object files) {

		List<File> fileList = CollectionUtils.asList((List<?>) files, File.class);
		Swing.runLater(() -> {
			if (fileList.size() == 1 && fileList.get(0).isFile()) {
				importer.importFile(folder, fileList.get(0));
			}
			else {
				importer.importFiles(folder, fileList);
			}
		});
	}

	private DomainFolder getDomainFolder(GTreeNode destinationNode) {
		if (destinationNode instanceof DomainFolderNode) {
			return ((DomainFolderNode) destinationNode).getDomainFolder();
		}
		else if (destinationNode instanceof DomainFileNode) {
			DomainFolderNode parent = (DomainFolderNode) destinationNode.getParent();
			return parent.getDomainFolder();
		}
		return null;
	}
}
