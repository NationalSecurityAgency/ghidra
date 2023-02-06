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
package ghidra.framework.main.datatree;

import java.awt.Component;
import java.io.File;
import java.util.List;

import docking.widgets.tree.GTreeNode;
import ghidra.app.services.FileImporterService;
import ghidra.app.util.FileOpenDataFlavorHandler;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.Swing;

/**
 * An abstract handler to facilitate drag-n-drop for a list of Java {@link File} objects which is 
 * dropped onto the Project data tree (see {@link DataTreeFlavorHandler}) or a running Ghidra Tool
 * (see {@link FileOpenDataFlavorHandler}).
 */
abstract class AbstractFileListFlavorHandler
		implements DataTreeFlavorHandler, FileOpenDataFlavorHandler {

	/**
	 * Do import when destination folder has been specified (e.g., data tree folder node).
	 * @param folder destination folder (if null root folder will be assumed)
	 * @param files files to be imported
	 * @param tool target tool (active/current project assumed)
	 * @param component parent component for popup messages
	 */
	protected void doImport(DomainFolder folder, List<File> files, PluginTool tool,
			Component component) {

		Swing.runLater(() -> {
			FileImporterService im = tool.getService(FileImporterService.class);
			if (im == null) {
				Msg.showError(AbstractFileListFlavorHandler.class, component, "Could Not Import",
					"Could not find importer service.");
				return;
			}

			if (files.size() == 1 && files.get(0).isFile()) {
				im.importFile(folder, files.get(0));
			}
			else {
				im.importFiles(folder, files);
			}
		});
	}

	protected DomainFolder getDomainFolder(GTreeNode destinationNode) {
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
